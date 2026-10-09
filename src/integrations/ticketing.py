
import sqlite3
import uuid
import json
from datetime import datetime
import logging
from collections.abc import Mapping

import os

logger = logging.getLogger(__name__)


def _nonempty_text(value):
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _ticket_identifier(job_result):
    """Choose an identifier available in an IOC, file, or email result."""
    identifier = _nonempty_text(job_result.get('ioc'))
    if identifier:
        return identifier

    hashes = job_result.get('hashes')
    if isinstance(hashes, Mapping):
        identifier = _nonempty_text(hashes.get('sha256'))
        if identifier:
            return identifier
    identifier = _nonempty_text(job_result.get('sha256'))
    if identifier:
        return identifier

    file_info = job_result.get('file_info')
    if isinstance(file_info, Mapping):
        for field in ('filename', 'name'):
            identifier = _nonempty_text(file_info.get(field))
            if identifier:
                return identifier
    identifier = _nonempty_text(job_result.get('filename'))
    if identifier:
        return identifier

    email_data = job_result.get('email_data')
    if isinstance(email_data, Mapping):
        for field in ('subject', 'from', 'sender'):
            identifier = _nonempty_text(email_data.get(field))
            if identifier:
                return identifier
    for field in ('subject', 'sender', 'from'):
        identifier = _nonempty_text(job_result.get(field))
        if identifier:
            return identifier
    return None


def _summary_score(job_result):
    for field in ('threat_score', 'composite_score'):
        score = job_result.get(field)
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            return score
    return None


def _summary_coverage(job_result):
    coverage = job_result.get('coverage')
    if not isinstance(coverage, Mapping):
        return None
    ok = coverage.get('sources_ok')
    applicable = coverage.get('sources_applicable')
    if ok is None:
        flagged = coverage.get('sources_flagged')
        clean = coverage.get('sources_clean')
        if flagged is not None and clean is not None:
            ok = flagged + clean
    if applicable is None:
        applicable = coverage.get('total_sources_attempted')
    if ok is None or applicable is None:
        return None
    return f'{ok}/{applicable}'


def _build_fallback_summary(job_result, identifier):
    verdict = _nonempty_text(job_result.get('verdict')) or 'UNKNOWN'
    parts = []
    score = _summary_score(job_result)
    if score is not None:
        parts.append(f'score {score:g}/100')
    coverage = _summary_coverage(job_result)
    if coverage is not None:
        parts.append(f'coverage {coverage}')
    detail = f" ({', '.join(parts)})" if parts else ''
    return f'{identifier} classified as {verdict}{detail}'

def _get_db_path():
    return os.environ.get('TICKETING_DB_PATH', 'data/tickets/tickets.db')


def ensure_owner_schema(connection):
    """Add the nullable owner column and lookup index to an existing ticket DB."""
    columns = {
        row[1] for row in connection.execute("PRAGMA table_info(tickets)").fetchall()
    }
    if "owner_id" not in columns:
        connection.execute("ALTER TABLE tickets ADD COLUMN owner_id INTEGER")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_tickets_owner_id ON tickets(owner_id)"
    )


def initialize_database():
    """Creates the tickets table if it doesn't exist."""
    db_path = _get_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tickets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id TEXT NOT NULL UNIQUE,
                    analysis_id TEXT NOT NULL,
                    ioc TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    summary TEXT,
                    recommendations TEXT,
                    owner_id INTEGER
                )
            ''')
            ensure_owner_schema(conn)
            conn.commit()
            logger.info("Ticketing database initialized successfully at %s.", db_path)
    except sqlite3.Error as e:
        logger.error(f"Database initialization failed for %s: {e}", db_path)
        raise

def create_incident_ticket(job_result: dict, analysis_id: str, owner_id=None):
    """
    Creates a new incident ticket in the database from a job result.

    Args:
        job_result (dict): The final result dictionary from the IOC investigator.
        analysis_id (str): The unique ID for the analysis run.
        owner_id (int, optional): The authenticated user who initiated the run.

    Returns:
        str: The UUID of the created ticket, or None if creation failed.
    """
    db_path = _get_db_path()
    try:
        verdict = job_result.get('verdict', 'UNKNOWN')
        identifier = _ticket_identifier(job_result)
        if not identifier:
            logger.error(
                "Failed to create incident ticket for analysis %s: no usable identifier",
                analysis_id,
            )
            return None

        summary = job_result.get('summary')
        if not isinstance(summary, str) or not summary.strip():
            summary = _build_fallback_summary(job_result, identifier)
            logger.warning(
                "Ticket summary missing or invalid for analysis %s; generated a deterministic fallback",
                analysis_id,
            )
        recommendations = job_result.get('recommendations', '')

        ticket_id = str(uuid.uuid4())
        created_at = datetime.utcnow().isoformat()

        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO tickets (
                    ticket_id, analysis_id, ioc, verdict, status, created_at,
                    summary, recommendations, owner_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ticket_id, analysis_id, identifier, verdict, 'open',
                created_at, summary, json.dumps(recommendations), owner_id,
            ))
            conn.commit()

        logger.info("Successfully created incident ticket %s for identifier %s.", ticket_id, identifier)
        return ticket_id
    except sqlite3.Error as e:
        logger.error("Failed to create incident ticket for identifier %s: %s", identifier if 'identifier' in locals() else None, e)
    except Exception as e:
        logger.error(f"An unexpected error occurred while creating a ticket: {e}")
    return None

def get_all_tickets(owner_id=None):
    """Retrieve tickets for one owner, or all tickets when owner_id is None."""
    db_path = _get_db_path()
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if owner_id is None:
                cursor.execute("SELECT * FROM tickets ORDER BY created_at DESC")
            else:
                cursor.execute(
                    "SELECT * FROM tickets WHERE owner_id = ? ORDER BY created_at DESC",
                    (owner_id,),
                )
            tickets = [dict(row) for row in cursor.fetchall()]
            return tickets
    except sqlite3.Error as e:
        logger.error(f"Failed to retrieve tickets: {e}")
        return []
