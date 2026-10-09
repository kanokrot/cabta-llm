#!/usr/bin/env python3
"""Backfill empty ticket summaries; defaults to a read-only dry run."""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
DEFAULT_TICKET_DB = REPO_ROOT / "data" / "tickets" / "tickets.db"
DEFAULT_ANALYSIS_DB = Path.home() / ".blue-team-assistant" / "cache" / "analysis_jobs.db"
DEFAULT_AGENT_DB = Path.home() / ".blue-team-assistant" / "cache" / "agent.db"


def _readonly_connection(path: Path) -> sqlite3.Connection | None:
    if not path.is_file():
        return None
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)


def _json_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except (TypeError, ValueError):
            return {}
        return decoded if isinstance(decoded, dict) else {}
    return {}


def _generic_identifier(value: Any) -> bool:
    return not isinstance(value, str) or not value.strip() or value.strip().lower() in {
        "unknown",
        "unknown_ioc",
        "n/a",
        "none",
    }


def _joined_payload(ticket: dict[str, Any], job: dict[str, Any] | None, session: dict[str, Any] | None) -> dict[str, Any]:
    """Collect only deterministic engine fields; never use LLM narrative text."""
    payload: dict[str, Any] = {}
    if job:
        params = _json_mapping(job.get("params"))
        result = _json_mapping(job.get("result"))
        for source in (params, result):
            for key in (
                "ioc", "sha256", "filename", "file_info", "hashes", "email_data",
                "subject", "sender", "from", "threat_score", "composite_score", "coverage",
            ):
                if key in source and key not in payload:
                    payload[key] = source[key]
        if "threat_score" not in payload and "composite_score" not in payload:
            if job.get("score") is not None:
                payload["threat_score"] = job["score"]
        # Older AnalysisManager rows may keep the score/verdict only in columns.
        if "verdict" not in payload and job.get("verdict"):
            payload["verdict"] = job["verdict"]
    if session:
        metadata = _json_mapping(session.get("metadata"))
        ioc_result = _json_mapping(metadata.get("ioc_investigation_result"))
        for key in ("ioc", "sha256", "filename", "file_info", "hashes", "email_data", "subject", "sender", "from", "threat_score", "composite_score", "coverage"):
            if key not in payload and key in ioc_result:
                payload[key] = ioc_result[key]

    ticket_ioc = ticket.get("ioc")
    if not _generic_identifier(ticket_ioc):
        payload["ioc"] = ticket_ioc
    payload["verdict"] = ticket.get("verdict") or payload.get("verdict")
    return payload


def _load_history(path: Path, query: str, fields: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    connection = _readonly_connection(path)
    if connection is None:
        return {}
    try:
        connection.row_factory = sqlite3.Row
        return {
            row["id"]: {field: row[field] for field in fields}
            for row in connection.execute(query)
        }
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Read and report only (the default).")
    mode.add_argument("--apply", action="store_true", help="Back up the ticket DB, then write eligible summaries.")
    parser.add_argument("--db", type=Path, default=DEFAULT_TICKET_DB)
    parser.add_argument("--analysis-db", type=Path, default=DEFAULT_ANALYSIS_DB)
    parser.add_argument("--agent-db", type=Path, default=DEFAULT_AGENT_DB)
    args = parser.parse_args()

    if not args.db.is_file():
        raise SystemExit(f"Ticket database not found: {args.db}")

    # Only create a backup when a real update was explicitly requested.
    backup_path = None
    if args.apply:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup_path = args.db.with_name(f"{args.db.name}.{timestamp}.bak")
        shutil.copy2(args.db, backup_path)

    analysis_rows = _load_history(
        args.analysis_db,
        "SELECT id, params, result, verdict, score FROM analysis_jobs",
        ("params", "result", "verdict", "score"),
    )
    session_rows = _load_history(
        args.agent_db,
        "SELECT id, metadata, playbook_id, goal FROM agent_sessions",
        ("metadata", "playbook_id", "goal"),
    )

    if args.apply:
        ticket_connection = sqlite3.connect(str(args.db))
    else:
        ticket_connection = _readonly_connection(args.db)
        if ticket_connection is None:
            raise SystemExit(f"Ticket database not found: {args.db}")
    ticket_connection.row_factory = sqlite3.Row
    try:
        rows = ticket_connection.execute(
            "SELECT ticket_id, analysis_id, ioc, verdict, summary "
            "FROM tickets WHERE summary IS NULL OR summary = '' ORDER BY created_at, id"
        ).fetchall()
        candidates = []
        skipped = []
        for row in rows:
            ticket = dict(row)
            job = analysis_rows.get(ticket["analysis_id"])
            session = session_rows.get(ticket["analysis_id"])
            if job is None and session is None:
                skipped.append((ticket, "no matching analysis job or agent session"))
                continue

            payload = _joined_payload(ticket, job, session)
            # Reuse ticketing's exact deterministic fallback formatter.
            from src.integrations.ticketing import _build_fallback_summary, _ticket_identifier

            identifier = _ticket_identifier(payload)
            if _generic_identifier(identifier) or not isinstance(payload.get("verdict"), str) or not payload["verdict"].strip():
                skipped.append((ticket, "joined record lacks an identifier or verdict"))
                continue
            candidates.append((ticket, _build_fallback_summary(payload, identifier)))

        if args.apply:
            try:
                ticket_connection.execute("BEGIN IMMEDIATE")
                updated = 0
                for ticket, summary in candidates:
                    cursor = ticket_connection.execute(
                        "UPDATE tickets SET summary = ? "
                        "WHERE ticket_id = ? AND (summary IS NULL OR summary = '')",
                        (summary, ticket["ticket_id"]),
                    )
                    updated += cursor.rowcount
                ticket_connection.commit()
            except Exception:
                ticket_connection.rollback()
                raise
            outcome = f"filled={updated}"
        else:
            outcome = f"would_fill={len(candidates)}"

        print(f"{outcome} skipped={len(skipped)} eligible_empty={len(rows)}")
        if backup_path is not None:
            print(f"backup={backup_path}")
        fill_samples = [
            ("would_fill" if not args.apply else "filled", ticket, summary)
            for ticket, summary in candidates[:5]
        ]
        skip_samples = [("skipped", ticket, reason) for ticket, reason in skipped[:5]]
        samples = fill_samples + skip_samples
        if len(samples) < 10:
            remaining = candidates[len(fill_samples):]
            samples.extend(
                ("would_fill" if not args.apply else "filled", ticket, summary)
                for ticket, summary in remaining[: 10 - len(samples)]
            )
        if len(samples) < 10:
            samples.extend(("skipped", ticket, reason) for ticket, reason in skipped[len(skip_samples): 10 - len(samples) + len(skip_samples)])
        print("samples:")
        for action, ticket, detail in samples[:10]:
            print(
                f"  {action}: ticket_id={ticket['ticket_id']} "
                f"analysis_id={ticket['analysis_id']} detail={detail}"
            )
    finally:
        ticket_connection.close()


if __name__ == "__main__":
    main()
