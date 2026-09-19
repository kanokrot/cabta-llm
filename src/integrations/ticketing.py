
import sqlite3
import uuid
import json
from datetime import datetime
import logging

import os

logger = logging.getLogger(__name__)

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
        summary = job_result.get('summary', '')
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
                ticket_id, analysis_id, job_result['ioc'], verdict, 'open',
                created_at, summary, json.dumps(recommendations), owner_id,
            ))
            conn.commit()

        logger.info(f"Successfully created incident ticket {ticket_id} for IOC {job_result['ioc']}.")
        return ticket_id
    except sqlite3.Error as e:
        logger.error(f"Failed to create incident ticket for IOC {job_result.get('ioc')}: {e}")
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
