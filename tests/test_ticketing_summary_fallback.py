"""Ticket summaries are deterministic and never store non-text values."""

import sqlite3

import pytest

from src.integrations.ticketing import create_incident_ticket, initialize_database


@pytest.fixture
def ticket_db(tmp_path, monkeypatch):
    db_path = tmp_path / "tickets.db"
    monkeypatch.setenv("TICKETING_DB_PATH", str(db_path))
    initialize_database()
    return db_path


def _create_and_read(db_path, result, analysis_id):
    ticket_id = create_incident_ticket(result, analysis_id)
    assert ticket_id
    connection = sqlite3.connect(db_path)
    try:
        row = connection.execute(
            "SELECT ioc, verdict, summary FROM tickets WHERE ticket_id = ?",
            (ticket_id,),
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    return row


def test_malware_without_summary_uses_sha256_as_identifier(ticket_db):
    sha256 = "a" * 64
    ioc, verdict, summary = _create_and_read(
        ticket_db,
        {
            "file_info": {"filename": "invoice.exe"},
            "hashes": {"sha256": sha256},
            "verdict": "MALICIOUS",
            "composite_score": 85,
            "coverage": {"sources_ok": 4, "sources_applicable": 6},
        },
        "malware-no-summary",
    )
    assert ioc == sha256
    assert verdict == "MALICIOUS"
    assert summary == f"{sha256} classified as MALICIOUS (score 85/100, coverage 4/6)"


def test_malware_text_file_dict_summary_falls_back_without_llm_text(ticket_db):
    ioc, verdict, summary = _create_and_read(
        ticket_db,
        {
            "file_info": {"filename": "script.txt"},
            "verdict": "SUSPICIOUS",
            "composite_score": 61.5,
            "summary": {"lines": 42, "findings": ["embedded script"]},
            "llm_analysis": "Do not copy this narrative into the ticket.",
        },
        "malware-dict-summary",
    )
    assert ioc == "script.txt"
    assert verdict == "SUSPICIOUS"
    assert summary == "script.txt classified as SUSPICIOUS (score 61.5/100)"
    assert "Do not copy" not in summary


def test_email_without_summary_uses_sender_identifier(ticket_db):
    ioc, verdict, summary = _create_and_read(
        ticket_db,
        {
            "ioc": "soc@example.org",
            "email_data": {
                "subject": "Invoice overdue",
                "from": "soc@example.org",
            },
            "verdict": "PHISHING",
            "composite_score": 82,
            "llm_analysis": {"analysis": "Untrusted narrative text."},
        },
        "email-no-summary",
    )
    assert ioc == "soc@example.org"
    assert verdict == "PHISHING"
    assert summary == "soc@example.org classified as PHISHING (score 82/100)"
    assert "Untrusted narrative" not in summary


def test_ioc_provided_summary_is_preserved(ticket_db):
    provided = "198.51.100.10 classified as MALICIOUS (threat score 88/100)"
    ioc, verdict, summary = _create_and_read(
        ticket_db,
        {
            "ioc": "198.51.100.10",
            "verdict": "MALICIOUS",
            "threat_score": 88,
            "coverage": {"sources_ok": 5, "sources_applicable": 6},
            "summary": provided,
        },
        "ioc-existing-summary",
    )
    assert ioc == "198.51.100.10"
    assert verdict == "MALICIOUS"
    assert summary == provided


def test_playbook_provided_summary_is_preserved(ticket_db):
    provided = "Playbook 'IOC Triage' completed (12 steps) — highest verdict: MALICIOUS"
    ioc, verdict, summary = _create_and_read(
        ticket_db,
        {
            "ioc": "bad.example",
            "verdict": "MALICIOUS",
            "summary": provided,
            "recommendations": "",
        },
        "playbook-existing-summary",
    )
    assert ioc == "bad.example"
    assert verdict == "MALICIOUS"
    assert summary == provided
