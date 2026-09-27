"""Compute Flow B and Flow C operational metrics from agent.db.

The SQLite database is opened read-only. The only output written by this
script is the CSV report beside this file.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
from pathlib import Path
from typing import Any


DEFAULT_DB_PATH = r"C:\Users\ACER\.blue-team-assistant\cache\agent.db"
OUTPUT_PATH = Path(__file__).with_name("operational_metrics_output.csv")
STEP_LIMIT_PATTERN = re.compile(
    r"exceeded maximum step count|Step limit \(",
    re.IGNORECASE,
)
TABLE_HEADER = ("group", "metric", "numerator", "denominator", "rate")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-path", default=DEFAULT_DB_PATH)
    parser.add_argument("--since", help="Include sessions created at or after this ISO value")
    return parser.parse_args()


def open_read_only(path: str) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def rate(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0.000000"
    return f"{numerator / denominator:.6f}"


def session_rows(
    connection: sqlite3.Connection,
    since: str | None,
) -> list[sqlite3.Row]:
    connection.row_factory = sqlite3.Row
    if since:
        cursor = connection.execute(
            """
            SELECT id, playbook_id, status, summary, findings, metadata
            FROM agent_sessions
            WHERE created_at >= ?
            ORDER BY created_at, id
            """,
            (since,),
        )
    else:
        cursor = connection.execute(
            """
            SELECT id, playbook_id, status, summary, findings, metadata
            FROM agent_sessions
            ORDER BY created_at, id
            """
        )
    return cursor.fetchall()


def flow_name(playbook_id: Any) -> str:
    return "Flow C" if playbook_id is not None else "Flow B"


def session_text(session: sqlite3.Row) -> str:
    values = (
        session["summary"],
        session["findings"],
        session["metadata"],
    )
    return " ".join(str(value) for value in values if value is not None)


def parse_tool_success(tool_result: Any) -> bool:
    try:
        parsed = json.loads(tool_result)
    except (TypeError, json.JSONDecodeError):
        return False
    return isinstance(parsed, dict) and "error" not in parsed


def metric_row(
    group: str,
    metric: str,
    numerator: int,
    denominator: int,
) -> dict[str, str | int]:
    return {
        "group": group,
        "metric": metric,
        "numerator": numerator,
        "denominator": denominator,
        "rate": rate(numerator, denominator),
    }


def compute_metrics(
    connection: sqlite3.Connection,
    sessions: list[sqlite3.Row],
) -> list[dict[str, str | int]]:
    session_ids = {
        "Flow B": [session["id"] for session in sessions if flow_name(session["playbook_id"]) == "Flow B"],
        "Flow C": [session["id"] for session in sessions if flow_name(session["playbook_id"]) == "Flow C"],
    }
    rows: list[dict[str, str | int]] = []

    for group in ("Flow B", "Flow C"):
        ids = session_ids[group]
        placeholders = ",".join("?" for _ in ids)

        if ids:
            if group == "Flow C":
                step_rows = connection.execute(
                    f"""
                    SELECT tool_result
                    FROM agent_steps
                    WHERE step_type = 'tool_call'
                      AND session_id IN ({placeholders})
                    """,
                    ids,
                ).fetchall()
                step_successes = [parse_tool_success(row[0]) for row in step_rows]
            else:
                step_rows = connection.execute(
                    f"""
                    SELECT status
                    FROM audit_log
                    WHERE action_type = 'tool_call'
                      AND session_id IN ({placeholders})
                    """,
                    ids,
                ).fetchall()
                step_successes = [row[0] == "success" for row in step_rows]
        else:
            step_successes = []

        rows.append(
            metric_row(
                group,
                "step_success_rate",
                sum(step_successes),
                len(step_successes),
            )
        )

        group_sessions = [
            session for session in sessions if flow_name(session["playbook_id"]) == group
        ]
        completed = sum(session["status"] == "completed" for session in group_sessions)
        non_completed = [
            session for session in group_sessions if session["status"] != "completed"
        ]
        step_limit_abort = sum(
            bool(STEP_LIMIT_PATTERN.search(session_text(session)))
            for session in non_completed
        )
        other_non_completed = len(non_completed) - step_limit_abort

        rows.append(
            metric_row(
                group,
                "completion_rate",
                completed,
                len(group_sessions),
            )
        )
        rows.append(
            metric_row(
                group,
                "completion_rate_step_limit_abort_breakdown",
                step_limit_abort,
                len(non_completed),
            )
        )
        rows.append(
            metric_row(
                group,
                "completion_rate_other_non_completed_breakdown",
                other_non_completed,
                len(non_completed),
            )
        )

        if ids:
            approval_rows = connection.execute(
                f"""
                SELECT action_type, status
                FROM audit_log
                WHERE requires_approval = 1
                  AND session_id IN ({placeholders})
                  AND action_type IN ('approval_granted', 'approval_rejected')
                  AND status <> 'pending'
                """,
                ids,
            ).fetchall()
        else:
            approval_rows = []

        rejected = sum(
            row["status"] == "rejected" or row["action_type"] == "approval_rejected"
            for row in approval_rows
        )
        rows.append(
            metric_row(
                group,
                "human_override_rate",
                rejected,
                len(approval_rows),
            )
        )

    return rows


def write_csv(rows: list[dict[str, str | int]]) -> None:
    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=TABLE_HEADER)
        writer.writeheader()
        writer.writerows(rows)


def print_table(rows: list[dict[str, str | int]]) -> None:
    print(" | ".join(TABLE_HEADER))
    for row in rows:
        print(" | ".join(str(row[column]) for column in TABLE_HEADER))


def main() -> None:
    args = parse_args()
    connection = open_read_only(args.db_path)
    try:
        sessions = session_rows(connection, args.since)
        rows = compute_metrics(connection, sessions)
    finally:
        connection.close()

    print_table(rows)
    write_csv(rows)


if __name__ == "__main__":
    main()
