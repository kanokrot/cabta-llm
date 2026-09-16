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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

_DEFAULT_DB = Path.home() / '.blue-team-assistant' / 'cache' / 'analysis_jobs.db'


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
    ) -> bool:
        """Persist one detection-rule edit without replacing other result data.

        The read-modify-write cycle uses the same self._lock as complete_job(),
        and commits the complete JSON result after changing one rule key.
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
                conn.commit()
                return True
            except Exception:
                conn.rollback()
                raise
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
