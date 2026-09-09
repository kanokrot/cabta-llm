"""Regression coverage for forensic persistence collection failures."""

from pathlib import Path

import yaml

from src.agent.playbook_engine import (
    _resolve_var,
    _store_single_step_result,
    safe_evaluate_condition,
)


_EXPECTED_CONDITION = (
    "{{hash_reputation_check.malicious}} or "
    "process_ip_reputation_any_malicious == true or "
    "{{persistence_check.suspicious}} or "
    "{{persistence_check_collection_error}}"
)


def _wrapped_success(*, suspicious: bool) -> dict:
    persistence_data = {
        "cron_jobs": {"stdout": "", "stderr": "", "exit_status": 0},
        "systemd_enabled": {
            "stdout": "sshd.service enabled",
            "stderr": "",
            "exit_status": 0,
        },
        "rc_local": {"stdout": "", "stderr": "", "exit_status": 0},
        "suspicious": suspicious,
        "suspicious_findings": [],
    }
    return {
        "result": {
            "status": "success",
            "error": None,
            "suspicious": suspicious,
            "suspicious_findings": [],
            "data": {
                "host": "192.0.2.10",
                "port": 22,
                "persistence_check": persistence_data,
            },
        },
        "server": "remote_tools",
        "tool": "autoruns_check",
    }


def _wrapped_tool_error() -> dict:
    return {
        "result": {
            "status": "error",
            "error": "SSH authentication failed",
            "data": None,
        },
        "server": "remote_tools",
        "tool": "autoruns_check",
    }


def _transport_error() -> dict:
    return {
        "error": "Tool 'mcp:remote_tools/autoruns_check' timed out after 120s",
        "server": "remote_tools",
        "tool": "autoruns_check",
    }


def _evaluate_route(persistence_result: dict) -> tuple[str, dict]:
    playbook_path = (
        Path(__file__).resolve().parents[1]
        / "data"
        / "playbooks"
        / "forensic_triage.yaml"
    )
    playbook = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))
    evaluate_step = next(
        step for step in playbook["steps"] if step["name"] == "evaluate_triage"
    )
    condition = evaluate_step["condition"]["if"]
    assert condition == _EXPECTED_CONDITION

    context = {
        "hash_reputation_check": {"malicious": False},
        "process_ip_reputation_any_malicious": False,
    }
    _store_single_step_result(context, "persistence_check", persistence_result)
    route = (
        evaluate_step["condition"]["then"]
        if safe_evaluate_condition(condition, context)
        else evaluate_step["condition"]["else"]
    )
    return route, context


def test_suspicious_success_routes_to_confirm_incident():
    route, context = _evaluate_route(_wrapped_success(suspicious=True))

    assert _resolve_var("persistence_check.suspicious", context) is True
    assert context["persistence_check_collection_error"] is False
    assert route == "confirm_incident"


def test_non_suspicious_success_routes_to_document_benign():
    route, context = _evaluate_route(_wrapped_success(suspicious=False))

    assert _resolve_var("persistence_check.suspicious", context) is False
    assert context["persistence_check_collection_error"] is False
    assert route == "document_benign"


def test_wrapped_tool_error_routes_to_confirm_incident():
    route, context = _evaluate_route(_wrapped_tool_error())

    assert _resolve_var("persistence_check.suspicious", context) is None
    assert context["persistence_check_collection_error"] is True
    assert route == "confirm_incident"


def test_transport_error_routes_to_confirm_incident():
    route, context = _evaluate_route(_transport_error())

    assert _resolve_var("persistence_check.suspicious", context) is None
    assert context["persistence_check_collection_error"] is True
    assert route == "confirm_incident"
