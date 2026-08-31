"""Regression coverage for for_each aggregate condition syntax in playbooks."""

from unittest.mock import MagicMock

import pytest

from src.agent.playbook_engine import PlaybookEngine


@pytest.fixture
def builtin_playbooks():
    agent_loop = MagicMock()
    agent_loop.config = {}
    engine = PlaybookEngine(agent_loop=agent_loop, agent_store=MagicMock())
    return engine


def _condition_for_step(playbook, step_name):
    step = next(step for step in playbook["steps"] if step["name"] == step_name)
    return step["condition"]


def test_for_each_conditions_use_any_malicious_keys(builtin_playbooks):
    email_condition = _condition_for_step(
        builtin_playbooks.get_playbook("email_investigation"),
        "evaluate_email_threat",
    )
    forensic_condition = _condition_for_step(
        builtin_playbooks.get_playbook("forensic_triage"),
        "evaluate_triage",
    )
    phishing_condition = _condition_for_step(
        builtin_playbooks.get_playbook("phishing_investigation"),
        "evaluate_phishing",
    )

    assert "{{url_urlhaus.malicious}}" not in email_condition
    assert "{{attachment_hash_check.malicious}}" not in email_condition
    assert "url_urlhaus_any_malicious == true" in email_condition
    assert "attachment_hash_check_any_malicious == true" in email_condition

    assert "{{process_ip_reputation.malicious}}" not in forensic_condition
    assert "process_ip_reputation_any_malicious == true" in forensic_condition

    assert "{{url_check.malicious}}" not in phishing_condition
    assert "{{attachment_hash_check.malicious}}" not in phishing_condition
    assert "url_check_any_malicious == true" in phishing_condition
    assert "attachment_hash_check_any_malicious == true" in phishing_condition
