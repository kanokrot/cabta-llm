
import sqlite3
import uuid
import json
from datetime import datetime
import logging

import os

logger = logging.getLogger(__name__)

def _get_db_path():
    return os.environ.get('TICKETING_DB_PATH', 'data/tickets/tickets.db')


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
                    recommendations TEXT
                )
            ''')
            conn.commit()
            logger.info("Ticketing database initialized successfully at %s.", db_path)
    except sqlite3.Error as e:
        logger.error(f"Database initialization failed for %s: {e}", db_path)
        raise

def create_incident_ticket(job_result: dict, analysis_id: str):
    """
    Creates a new incident ticket in the database from a job result.

    Args:
        job_result (dict): The final result dictionary from the IOC investigator.
        analysis_id (str): The unique ID for the analysis run.

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
                INSERT INTO tickets (ticket_id, analysis_id, ioc, verdict, status, created_at, summary, recommendations)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (ticket_id, analysis_id, job_result['ioc'], verdict, 'open', created_at, summary, json.dumps(recommendations)))
            conn.commit()

        logger.info(f"Successfully created incident ticket {ticket_id} for IOC {job_result['ioc']}.")
        return ticket_id
    except sqlite3.Error as e:
        logger.error(f"Failed to create incident ticket for IOC {job_result.get('ioc')}: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while creating a ticket: {e}")
    return None

def get_all_tickets():
    """Retrieves all tickets from the database."""
    db_path = _get_db_path()
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tickets ORDER BY created_at DESC")
            tickets = [dict(row) for row in cursor.fetchall()]
            return tickets
    except sqlite3.Error as e:
        logger.error(f"Failed to retrieve tickets: {e}")
        return []

