"""
Author: Ugur Ates
Analysis Manager - Background task management for web API.

SQLite-backed analysis job queue with asyncio support.
"""

import asyncio
import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

_DEFAULT_DB = Path.home() / '.blue-team-assistant' / 'cache' / 'analysis_jobs.db'

VERDICT_GROUPS = {
    "malicious": ("MALICIOUS", "PHISHING"),
    "suspicious": ("SUSPICIOUS", "SPAM"),
    "clean": ("CLEAN",),
}

_HISTORY_GROUPS = (
    "malicious", "suspicious", "clean", "unknown", "failed", "in_progress",
)
_HISTORY_SORTS = {
    "date": "created_at",
    "score": "(score IS NULL) ASC, score",
    "type": "analysis_type",
    "status": "status",
    "verdict": (
        "CASE verdict_group "
        "WHEN 'malicious' THEN 0 "
        "WHEN 'suspicious' THEN 1 "
        "WHEN 'clean' THEN 2 "
        "WHEN 'unknown' THEN 3 "
        "WHEN 'failed' THEN 4 "
        "WHEN 'in_progress' THEN 5 "
        "ELSE 6 END"
    ),
}


def _verdict_group_sql() -> tuple[str, list[str]]:
    parts = [
        "CASE",
        "WHEN status = 'failed' THEN 'failed'",
        "WHEN status IN ('queued', 'running') THEN 'in_progress'",
    ]
    values = []
    for group_name, verdicts in VERDICT_GROUPS.items():
        placeholders = ", ".join("?" for _ in verdicts)
        parts.append(
            f"WHEN status = 'completed' AND verdict IN ({placeholders}) "
            f"THEN '{group_name}'"
        )
        values.extend(verdicts)
    parts.append("ELSE 'unknown' END")
    return " ".join(parts), values


def _history_target_sql() -> str:
    return (
        "CASE WHEN json_valid(params) THEN "
        "COALESCE(json_extract(params, '$.value'), "
        "json_extract(params, '$.filename'), id) "
        "ELSE id END"
    )


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class AnalysisManager:
    """Manage background analysis tasks.

    Usage::

        mgr = AnalysisManager()
        job_id = mgr.create_job('ioc', {'value': '8.8.8.8', 'ioc_type': 'ip'})
        mgr.update_progress(job_id, 50, 'Querying VirusTotal...')
        mgr.complete_job(job_id, result_dict)
    """

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._lock = threading.Lock()
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}
        self._event_loop: Optional[asyncio.AbstractEventLoop] = None
        self._init_db()

    # ------------------------------------------------------------------ #
    # Job CRUD
    # ------------------------------------------------------------------ #

    def create_job(
        self,
        analysis_type: str,
        params: Dict[str, Any],
        user_id: Optional[int] = None,
    ) -> str:
        """Create a new analysis job. Returns job ID."""
        job_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        params_json = json.dumps(params, default=str)

        with self._lock:
            conn = self._connect()
            conn.execute(
                """INSERT INTO analysis_jobs
                   (id, analysis_type, params, status, progress, created_at, user_id)
                   VALUES (?, ?, ?, 'queued', 0, ?, ?)""",
                (job_id, analysis_type, params_json, now, user_id),
            )
            conn.commit()
            conn.close()

        logger.info(f"[JOB] Created {analysis_type} job: {job_id}")
        return job_id

    def get_job(
        self,
        job_id: str,
        user_id: Optional[int] = None,
    ) -> Optional[Dict]:
        """Get job details."""
        conn = self._connect()
        if user_id is None:
            cur = conn.execute(
                "SELECT * FROM analysis_jobs WHERE id = ?",
                (job_id,),
            )
        else:
            cur = conn.execute(
                "SELECT * FROM analysis_jobs WHERE id = ? AND user_id = ?",
                (job_id, user_id),
            )
        row = cur.fetchone()
        conn.close()
        if row is None:
            return None
        return self._row_to_dict(cur.description, row)

    def update_detection_rule(
        self,
        analysis_id: str,
        rule_type: str,
        content: str,
        editor_user_id: Optional[int] = None,
    ) -> bool:
        """Persist one detection-rule edit without replacing other result data.

        The read-modify-write cycle uses the same self._lock as complete_job(),
        and commits the complete JSON result plus optional ownership metadata
        in one transaction.
        """
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "SELECT result FROM analysis_jobs WHERE id = ?",
                    (analysis_id,),
                )
                row = cur.fetchone()
                if row is None or not row[0]:
                    conn.rollback()
                    return False

                try:
                    result = json.loads(row[0])
                except (TypeError, json.JSONDecodeError):
                    conn.rollback()
                    return False

                if not isinstance(result, dict):
                    conn.rollback()
                    return False
                rules = result.get('detection_rules')
                if not isinstance(rules, dict) or rule_type not in rules:
                    conn.rollback()
                    return False

                result['detection_rules'][rule_type] = content
                conn.execute(
                    "UPDATE analysis_jobs SET result = ? WHERE id = ?",
                    (json.dumps(result, default=str), analysis_id),
                )
                if editor_user_id is not None:
                    conn.execute(
                        """
                        INSERT INTO detection_rule_ownership (
                            analysis_id, rule_type, last_edited_by, last_edited_at
                        ) VALUES (?, ?, ?, ?)
                        ON CONFLICT(analysis_id, rule_type) DO UPDATE SET
                            last_edited_by = excluded.last_edited_by,
                            last_edited_at = excluded.last_edited_at
                        """,
                        (
                            analysis_id,
                            rule_type,
                            int(editor_user_id),
                            datetime.now(timezone.utc).isoformat(),
                        ),
                    )
                conn.commit()
                return True
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def get_detection_rule_owner(
        self,
        analysis_id: str,
        rule_type: str,
    ) -> Optional[Dict[str, Any]]:
        """Return the latest editor metadata for one rule, if it exists."""
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT analysis_id, rule_type, last_edited_by, last_edited_at
                FROM detection_rule_ownership
                WHERE analysis_id = ? AND rule_type = ?
                """,
                (analysis_id, rule_type),
            ).fetchone()
            if row is None:
                return None
            return {
                "analysis_id": row[0],
                "rule_type": row[1],
                "last_edited_by": row[2],
                "last_edited_at": row[3],
            }
        finally:
            conn.close()

    def list_jobs(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        user_id: Optional[int] = None,
        user_ids: Optional[Sequence[int]] = None,
    ) -> List[Dict]:
        """List analysis jobs with optional filtering."""
        conn = self._connect()
        clauses = []
        params = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if user_ids is not None:
            if not user_ids:
                return []
            placeholders = ", ".join("?" for _ in user_ids)
            clauses.append(f"user_id IN ({placeholders})")
            params.extend(user_ids)

        query = "SELECT * FROM analysis_jobs"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cur = conn.execute(query, params)
        rows = cur.fetchall()
        conn.close()
        return [self._row_to_dict(cur.description, r) for r in rows]

    def _history_query_parts(
        self,
        *,
        status: Optional[str] = None,
        user_id: Optional[int] = None,
        user_ids: Optional[Sequence[int]] = None,
        group: Optional[str] = None,
        analysis_type: Optional[str] = None,
        q: Optional[str] = None,
        range_name: str = "all",
        sort: str = "date",
        order: str = "desc",
    ) -> tuple[str, str, list[Any], str]:
        """Build the shared history query and its bound parameters."""
        if group is not None and group not in _HISTORY_GROUPS:
            raise ValueError("invalid history group")
        if analysis_type is not None and analysis_type not in {"ioc", "file", "email"}:
            raise ValueError("invalid analysis type")
        if range_name not in {"all", "24h", "7d"}:
            raise ValueError("invalid history range")
        if sort not in _HISTORY_SORTS:
            raise ValueError("invalid history sort")
        if order not in {"asc", "desc"}:
            raise ValueError("invalid history order")

        group_sql, group_params = _verdict_group_sql()
        base_sql = (
            "WITH history AS ("
            "SELECT analysis_jobs.*, "
            f"{_history_target_sql()} AS history_target, "
            f"{group_sql} AS verdict_group "
            "FROM analysis_jobs)"
        )
        clauses = []
        params = list(group_params)

        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if user_ids is not None:
            if not user_ids:
                clauses.append("1 = 0")
            else:
                placeholders = ", ".join("?" for _ in user_ids)
                clauses.append(f"user_id IN ({placeholders})")
                params.extend(user_ids)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if group:
            clauses.append("verdict_group = ?")
            params.append(group)
        if analysis_type:
            clauses.append("analysis_type = ?")
            params.append(analysis_type)
        if range_name != "all":
            hours = 24 if range_name == "24h" else 24 * 7
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            clauses.append("created_at >= ?")
            params.append(cutoff.isoformat())
        if q:
            pattern = f"%{_escape_like(q)}%"
            clauses.append(
                "(id LIKE ? ESCAPE '\\' "
                "OR analysis_type LIKE ? ESCAPE '\\' "
                "OR history_target LIKE ? ESCAPE '\\')"
            )
            params.extend([pattern, pattern, pattern])

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        direction = "ASC" if order == "asc" else "DESC"
        order_sql = f"{_HISTORY_SORTS[sort]} {direction}, id {direction}"
        return base_sql, where, params, order_sql

    def list_history_page(
        self,
        limit: int = 25,
        offset: int = 0,
        status: Optional[str] = None,
        user_id: Optional[int] = None,
        user_ids: Optional[Sequence[int]] = None,
        group: Optional[str] = None,
        analysis_type: Optional[str] = None,
        q: Optional[str] = None,
        range_name: str = "all",
        sort: str = "date",
        order: str = "desc",
    ) -> Dict:
        """Return one filtered, sorted, role-scoped history page and its total."""
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if offset < 0:
            raise ValueError("offset must be non-negative")
        base_sql, where, params, order_sql = self._history_query_parts(
            status=status,
            user_id=user_id,
            user_ids=user_ids,
            group=group,
            analysis_type=analysis_type,
            q=q,
            range_name=range_name,
            sort=sort,
            order=order,
        )
        conn = self._connect()
        try:
            total = conn.execute(
                f"{base_sql} SELECT COUNT(*) FROM history{where}",
                params,
            ).fetchone()[0]

            rows_sql = (
                f"{base_sql} SELECT * FROM history{where} "
                f"ORDER BY {order_sql} "
                "LIMIT ? OFFSET ?"
            )
            cur = conn.execute(rows_sql, [*params, limit, offset])
            rows = cur.fetchall()
            description = cur.description
            items = []
            for row in rows:
                item = self._row_to_dict(description, row)
                item.pop("history_target", None)
                items.append(item)
            return {"items": items, "total": total}
        finally:
            conn.close()

    def export_history_rows(
        self,
        *,
        cap: int,
        status: Optional[str] = None,
        user_id: Optional[int] = None,
        user_ids: Optional[Sequence[int]] = None,
        group: Optional[str] = None,
        analysis_type: Optional[str] = None,
        q: Optional[str] = None,
        range_name: str = "all",
        sort: str = "date",
        order: str = "desc",
    ) -> List[Dict]:
        """Return up to cap+1 rows from one consistently filtered history query."""
        if cap < 1:
            raise ValueError("history export cap must be positive")

        base_sql, where, params, order_sql = self._history_query_parts(
            status=status,
            user_id=user_id,
            user_ids=user_ids,
            group=group,
            analysis_type=analysis_type,
            q=q,
            range_name=range_name,
            sort=sort,
            order=order,
        )
        conn = self._connect()
        try:
            cur = conn.execute(
                f"{base_sql} SELECT * FROM history{where} "
                f"ORDER BY {order_sql} LIMIT ?",
                [*params, cap + 1],
            )
            description = cur.description
            return [
                self._row_to_dict(description, row)
                for row in cur.fetchall()
            ]
        finally:
            conn.close()

    def get_history_summary(
        self,
        user_id: Optional[int] = None,
        user_ids: Optional[Sequence[int]] = None,
    ) -> Dict:
        """Return role-scoped, mutually exclusive history summary counts."""
        conn = self._connect()
        clauses = []
        scope_params = []
        if user_id is not None:
            clauses.append("user_id = ?")
            scope_params.append(user_id)
        if user_ids is not None:
            if not user_ids:
                clauses.append("1 = 0")
            else:
                placeholders = ", ".join("?" for _ in user_ids)
                clauses.append(f"user_id IN ({placeholders})")
                scope_params.extend(user_ids)

        group_sql, group_params = _verdict_group_sql()
        group_names = (*VERDICT_GROUPS.keys(), "unknown", "failed", "in_progress")
        select_parts = ["COUNT(*) AS total"]
        query_params = [*group_params]
        for group_name in group_names:
            select_parts.append(
                "SUM(CASE WHEN verdict_group = ? THEN 1 ELSE 0 END) "
                f"AS {group_name}"
            )
            query_params.append(group_name)

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        row = conn.execute(
            f"WITH history AS ("
            f"SELECT *, {group_sql} AS verdict_group FROM analysis_jobs) "
            f"SELECT {', '.join(select_parts)} FROM history{where}",
            [*query_params, *scope_params],
        ).fetchone()
        conn.close()

        summary = {
            "total": row[0] or 0,
            "malicious": row[1] or 0,
            "suspicious": row[2] or 0,
            "clean": row[3] or 0,
            "unknown": row[4] or 0,
            "failed": row[5] or 0,
            "in_progress": row[6] or 0,
        }
        if sum(summary[key] for key in summary if key != "total") != summary["total"]:
            raise RuntimeError("Analysis history summary counts are inconsistent")
        return summary

    def update_progress(
        self,
        job_id: str,
        progress: int,
        current_step: str = '',
        tool_name: str = '',
        tool_source: str = '',
    ) -> None:
        """Update job progress (0-100) and current step."""
        with self._lock:
            conn = self._connect()
            conn.execute(
                """UPDATE analysis_jobs
                   SET status = 'running', progress = ?, current_step = ?
                   WHERE id = ?""",
                (min(progress, 100), current_step, job_id),
            )
            conn.commit()
            conn.close()

        # Notify WebSocket subscribers
        msg = {
            'type': 'progress',
            'progress': progress,
            'step': current_step,
        }
        if tool_name:
            msg['tool_name'] = tool_name
        if tool_source:
            msg['tool_source'] = tool_source
        self._notify(job_id, msg)

    def update_steps(
        self,
        job_id: str,
        steps: List[Dict[str, Any]],
        progress: int,
        current_step: str = '',
    ) -> None:
        """Persist analyzer step states in the existing job params JSON."""
        safe_steps = [
            {
                'key': str(step.get('key', '')),
                'label': str(step.get('label', '')),
                'state': str(step.get('state', 'pending')),
            }
            for step in steps
            if isinstance(step, dict)
        ]
        with self._lock:
            conn = self._connect()
            row = conn.execute(
                "SELECT params FROM analysis_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            params = {}
            if row and row[0]:
                try:
                    params = json.loads(row[0])
                except (TypeError, json.JSONDecodeError):
                    params = {}
            if not isinstance(params, dict):
                params = {}
            params['_analysis_steps'] = safe_steps
            conn.execute(
                """UPDATE analysis_jobs
                   SET params = ?, status = 'running', progress = ?, current_step = ?
                   WHERE id = ?""",
                (json.dumps(params, default=str), min(progress, 100), current_step, job_id),
            )
            conn.commit()
            conn.close()

        steps_done = sum(
            step['state'] in {'completed', 'skipped'} for step in safe_steps
        )
        self._notify(job_id, {
            'type': 'progress',
            'progress': min(progress, 100),
            'step': current_step,
            'steps': safe_steps,
            'steps_total': len(safe_steps),
            'steps_done': steps_done,
        })

    def complete_job(
        self,
        job_id: str,
        result: Dict[str, Any],
        verdict: str = 'UNKNOWN',
        score: int = 0,
    ) -> None:
        """Mark job as completed with result."""
        now = datetime.now(timezone.utc).isoformat()
        result_json = json.dumps(result, default=str)

        with self._lock:
            conn = self._connect()
            conn.execute(
                """UPDATE analysis_jobs
                   SET status = 'completed', progress = 100,
                       result = ?, verdict = ?, score = ?,
                       completed_at = ?
                   WHERE id = ?""",
                (result_json, verdict, score, now, job_id),
            )
            conn.commit()
            conn.close()

        self._notify(job_id, {
            'type': 'completed',
            'verdict': verdict,
            'score': score,
        })
        logger.info(f"[JOB] Completed {job_id}: {verdict} ({score})")

    def fail_job(self, job_id: str, error: str) -> None:
        """Mark job as failed."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                """UPDATE analysis_jobs
                   SET status = 'failed', current_step = ?, completed_at = ?
                   WHERE id = ?""",
                (error, now, job_id),
            )
            conn.commit()
            conn.close()

        self._notify(job_id, {'type': 'failed', 'error': error})

    # ------------------------------------------------------------------ #
    # Statistics
    # ------------------------------------------------------------------ #

    def get_stats(self) -> Dict:
        """Return analysis statistics."""
        conn = self._connect()
        cur = conn.execute(
            """SELECT
                 COUNT(*) as total,
                 SUM(CASE WHEN verdict='MALICIOUS' THEN 1 ELSE 0 END) as malicious,
                 SUM(CASE WHEN verdict='SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious,
                 SUM(CASE WHEN verdict='CLEAN' THEN 1 ELSE 0 END) as clean,
                 AVG(CASE WHEN score IS NOT NULL THEN score END) as avg_score,
                 SUM(CASE WHEN date(created_at) = date('now') THEN 1 ELSE 0 END) as today
               FROM analysis_jobs WHERE status = 'completed'"""
        )
        row = cur.fetchone()
        conn.close()

        if row is None:
            return {}
        return {
            'total_analyses': row[0] or 0,
            'malicious_count': row[1] or 0,
            'suspicious_count': row[2] or 0,
            'clean_count': row[3] or 0,
            'average_score': round(row[4] or 0, 1),
            'analyses_today': row[5] or 0,
        }

    # ------------------------------------------------------------------ #
    # WebSocket pub/sub
    # ------------------------------------------------------------------ #

    def subscribe(self, job_id: str) -> asyncio.Queue:
        """Subscribe to real-time updates for a job."""
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(job_id, []).append(q)
        # Capture the event loop that owns this queue so _notify can
        # push messages safely from background threads.
        try:
            self._event_loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        return q

    def unsubscribe(self, job_id: str, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(job_id, [])
        if queue in subs:
            subs.remove(queue)

    def _notify(self, job_id: str, message: Dict) -> None:
        """Push message to WebSocket subscribers (thread-safe)."""
        subs = self._subscribers.get(job_id, [])
        if not subs:
            return

        def _put_all():
            for q in subs:
                try:
                    q.put_nowait(message)
                except asyncio.QueueFull:
                    pass

        loop = getattr(self, '_event_loop', None)
        if loop is not None and loop.is_running():
            try:
                loop.call_soon_threadsafe(_put_all)
                return
            except RuntimeError:
                pass
        _put_all()

    # ------------------------------------------------------------------ #
    # DB helpers
    # ------------------------------------------------------------------ #

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analysis_jobs (
                id           TEXT PRIMARY KEY,
                analysis_type TEXT NOT NULL,
                params       TEXT NOT NULL DEFAULT '{}',
                status       TEXT NOT NULL DEFAULT 'queued',
                progress     INTEGER NOT NULL DEFAULT 0,
                current_step TEXT DEFAULT '',
                verdict      TEXT,
                score        INTEGER,
                result       TEXT,
                created_at   TEXT NOT NULL,
                completed_at TEXT,
                user_id      INTEGER
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_jobs_status ON analysis_jobs(status)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_jobs_created ON analysis_jobs(created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_jobs_user_id "
            "ON analysis_jobs(user_id)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS detection_rule_ownership (
                analysis_id TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                last_edited_by INTEGER NOT NULL,
                last_edited_at TEXT NOT NULL,
                PRIMARY KEY (analysis_id, rule_type),
                FOREIGN KEY (analysis_id) REFERENCES analysis_jobs(id)
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_detection_rule_ownership_editor
            ON detection_rule_ownership(last_edited_by)
            """
        )
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), timeout=5)

    @staticmethod
    def _row_to_dict(description, row) -> Dict:
        cols = [d[0] for d in description]
        d = dict(zip(cols, row))
        # Parse JSON fields
        for key in ('params', 'result'):
            if d.get(key) and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except json.JSONDecodeError:
                    pass
        return d
