import importlib.util
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "adhoc" / "g3_fire_alerts.py"
SPEC = importlib.util.spec_from_file_location("g3_fire_alerts", SCRIPT)
g3_fire_alerts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(g3_fire_alerts)


def _decision_db(path, decision):
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            """CREATE TABLE agent_steps (
                session_id TEXT, step_number INTEGER, step_type TEXT,
                content TEXT, tool_result TEXT
            )"""
        )
        conn.execute(
            """INSERT INTO agent_steps
               (session_id, step_number, step_type, content, tool_result)
               VALUES (?, ?, 'decision', 'priority_evaluation: condition evaluated', ?)""",
            ("session-1", 1, '{"decision": ' + str(decision).lower() + '}'),
        )
        conn.commit()


def test_reads_priority_evaluation_decision_read_only():
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "agent.db"
        _decision_db(db_path, True)

        decision, error = g3_fire_alerts.read_priority_decision(db_path, "session-1")

    assert decision is True
    assert error == ""


def test_reads_false_priority_evaluation_decision():
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "agent.db"
        _decision_db(db_path, False)

        decision, error = g3_fire_alerts.read_priority_decision(db_path, "session-1")

    assert decision is False
    assert error == ""


def test_g3_decision_expectations_for_a1_a3_a4():
    expected = {alert["id"].split("-")[0]: alert["expected_decision"]
                for alert in g3_fire_alerts.ALERTS if "expected_decision" in alert}

    assert expected == {"A1": True, "A3": False, "A4": False}
