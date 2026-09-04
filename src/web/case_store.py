"""
Author: Ugur Ates
Case Management Store - SQLite-backed case tracking.

Tables:
- cases: id, title, description, severity, status, created_at, updated_at
- case_analyses: case_id, analysis_id, linked_at
- case_notes: id, case_id, content, author, created_at
"""

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB = Path.home() / '.blue-team-assistant' / 'cache' / 'cases.db'

_INCIDENT_REPORT_FIELDS = (
    'threat_type',
    'threat_description',
    'attacker_ip',
    'target_ip',
    'affected_username',
    'attack_outcome',
    'occurrence_note',
    'detected_at',
    'detection_device',
    'severity_4tier',
    'findings',
    'analysis',
    'impact',
    'remediation',
    'reference',
)
_INCIDENT_REPORT_JSON_FIELDS = {
    'findings', 'analysis', 'impact', 'remediation', 'reference'
}


def _severity_to_4tier(case_severity: str) -> str:
    """Map a case severity value to its four-tier report label."""
    return {
        'low': 'Low',
        'medium': 'Medium',
        'high': 'High',
        'critical': 'Critical',
    }.get(case_severity.lower(), '') if case_severity else ''


class CaseStore:
    """SQLite-backed case management."""

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._lock = threading.Lock()
        self._init_db()

    # ------------------------------------------------------------------ #
    # Cases
    # ------------------------------------------------------------------ #

    def create_case(
        self,
        title: str,
        description: str = '',
        severity: str = 'medium',
    ) -> str:
        case_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                """INSERT INTO cases (id, title, description, severity, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 'Open', ?, ?)""",
                (case_id, title, description, severity, now, now),
            )
            conn.commit()
            conn.close()
        logger.info(f"[CASE] Created case {case_id}: {title}")
        return case_id

    def get_case(self, case_id: str) -> Optional[Dict]:
        conn = self._connect()
        cur = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
        row = cur.fetchone()
        if row is None:
            conn.close()
            return None
        case = self._row_to_dict(cur.description, row)

        # Attach analyses
        cur2 = conn.execute(
            "SELECT analysis_id, linked_at FROM case_analyses WHERE case_id = ?",
            (case_id,),
        )
        case['analyses'] = [
            {'analysis_id': r[0], 'linked_at': r[1]} for r in cur2.fetchall()
        ]

        # Attach notes
        cur3 = conn.execute(
            "SELECT id, content, author, created_at FROM case_notes WHERE case_id = ? ORDER BY created_at",
            (case_id,),
        )
        case['notes'] = [
            {'id': r[0], 'content': r[1], 'author': r[2], 'created_at': r[3]}
            for r in cur3.fetchall()
        ]
        conn.close()
        return case

    def list_cases(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> List[Dict]:
        conn = self._connect()
        if status:
            cur = conn.execute(
                """SELECT c.*,
                          (SELECT COUNT(*) FROM case_analyses WHERE case_id=c.id) as analysis_count,
                          (SELECT COUNT(*) FROM case_notes WHERE case_id=c.id) as note_count
                   FROM cases c WHERE c.status = ?
                   ORDER BY c.updated_at DESC LIMIT ? OFFSET ?""",
                (status, limit, offset),
            )
        else:
            cur = conn.execute(
                """SELECT c.*,
                          (SELECT COUNT(*) FROM case_analyses WHERE case_id=c.id) as analysis_count,
                          (SELECT COUNT(*) FROM case_notes WHERE case_id=c.id) as note_count
                   FROM cases c
                   ORDER BY c.updated_at DESC LIMIT ? OFFSET ?""",
                (limit, offset),
            )
        rows = cur.fetchall()
        conn.close()
        return [self._row_to_dict(cur.description, r) for r in rows]

    def update_case_status(self, case_id: str, status: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                "UPDATE cases SET status = ?, updated_at = ? WHERE id = ?",
                (status, now, case_id),
            )
            conn.commit()
            updated = cur.rowcount > 0
            conn.close()
        return updated

    # ------------------------------------------------------------------ #
    # Incident reports
    # ------------------------------------------------------------------ #

    def create_incident_report(self, case_id: str, **fields) -> Dict:
        unknown = set(fields) - set(_INCIDENT_REPORT_FIELDS)
        if unknown:
            raise ValueError(f"Unknown incident report fields: {sorted(unknown)}")

        now = datetime.now(timezone.utc).isoformat()
        values = {
            key: json.dumps(value) if key in _INCIDENT_REPORT_JSON_FIELDS else value
            for key, value in fields.items()
        }
        columns = ['case_id', *values.keys(), 'created_at', 'updated_at']
        parameters = [case_id, *values.values(), now, now]
        placeholders = ', '.join('?' for _ in columns)

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    f"INSERT INTO case_incident_reports ({', '.join(columns)}) "
                    f"VALUES ({placeholders})",
                    parameters,
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
        return self.get_incident_report(case_id)

    def get_incident_report(self, case_id: str) -> Optional[Dict]:
        conn = self._connect()
        cur = conn.execute(
            "SELECT * FROM case_incident_reports WHERE case_id = ?", (case_id,)
        )
        row = cur.fetchone()
        if row is None:
            conn.close()
            return None
        report = self._row_to_dict(cur.description, row)
        conn.close()
        for field in _INCIDENT_REPORT_JSON_FIELDS:
            report[field] = json.loads(report[field])
        return report

    def update_incident_report(self, case_id: str, **fields) -> bool:
        unknown = set(fields) - set(_INCIDENT_REPORT_FIELDS)
        if unknown:
            raise ValueError(f"Unknown incident report fields: {sorted(unknown)}")

        values = {
            key: json.dumps(value) if key in _INCIDENT_REPORT_JSON_FIELDS else value
            for key, value in fields.items()
        }
        values['updated_at'] = datetime.now(timezone.utc).isoformat()
        assignments = ', '.join(f"{key} = ?" for key in values)

        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                f"UPDATE case_incident_reports SET {assignments} WHERE case_id = ?",
                (*values.values(), case_id),
            )
            conn.commit()
            updated = cur.rowcount > 0
            conn.close()
        return updated

    # ------------------------------------------------------------------ #
    # Case-Analysis linking
    # ------------------------------------------------------------------ #

    def link_analysis(self, case_id: str, analysis_id: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            try:
                conn = self._connect()
                conn.execute(
                    "INSERT OR IGNORE INTO case_analyses (case_id, analysis_id, linked_at) VALUES (?, ?, ?)",
                    (case_id, analysis_id, now),
                )
                conn.commit()
                conn.close()
                return True
            except Exception:
                return False

    # ------------------------------------------------------------------ #
    # Notes
    # ------------------------------------------------------------------ #

    def add_note(self, case_id: str, content: str, author: str = 'analyst') -> str:
        note_id = uuid.uuid4().hex[:10]
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT INTO case_notes (id, case_id, content, author, created_at) VALUES (?, ?, ?, ?, ?)",
                (note_id, case_id, content, author, now),
            )
            # Touch updated_at on parent case
            conn.execute(
                "UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id)
            )
            conn.commit()
            conn.close()
        return note_id

    # ------------------------------------------------------------------ #
    # DB setup
    # ------------------------------------------------------------------ #

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id          TEXT PRIMARY KEY,
                title       TEXT NOT NULL,
                description TEXT DEFAULT '',
                severity    TEXT DEFAULT 'medium',
                status      TEXT DEFAULT 'Open',
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS case_analyses (
                case_id     TEXT NOT NULL,
                analysis_id TEXT NOT NULL,
                linked_at   TEXT NOT NULL,
                PRIMARY KEY (case_id, analysis_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS case_notes (
                id         TEXT PRIMARY KEY,
                case_id    TEXT NOT NULL,
                content    TEXT NOT NULL,
                author     TEXT DEFAULT 'analyst',
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS case_incident_reports (
                case_id             TEXT PRIMARY KEY,
                threat_type         TEXT DEFAULT '',
                threat_description  TEXT DEFAULT '',
                attacker_ip         TEXT DEFAULT '',
                target_ip           TEXT DEFAULT '',
                affected_username   TEXT DEFAULT '',
                attack_outcome      TEXT DEFAULT '',
                occurrence_note     TEXT DEFAULT '',
                detected_at         TEXT DEFAULT '',
                detection_device    TEXT DEFAULT '',
                severity_4tier      TEXT DEFAULT '',
                findings            TEXT DEFAULT '[]',
                analysis            TEXT DEFAULT '[]',
                impact              TEXT DEFAULT '[]',
                remediation         TEXT DEFAULT '[]',
                reference           TEXT DEFAULT '[]',
                created_at          TEXT NOT NULL,
                updated_at          TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            )
        """)
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), timeout=5)

    @staticmethod
    def _row_to_dict(description, row) -> Dict:
        return dict(zip([d[0] for d in description], row))
