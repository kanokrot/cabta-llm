"""Tests for _collect_malicious_iocs() and the playbook completion ticketing hook."""

from unittest.mock import MagicMock, patch

import pytest

from src.agent.playbook_engine import PlaybookEngine, _collect_malicious_iocs


# ---------------------------------------------------------------------------
# _collect_malicious_iocs
# ---------------------------------------------------------------------------

def test_only_individually_malicious_items_are_returned():
    context = {
        "hash_threat_check_results": [
            {"result": {"malicious": True}},
            {"result": {"malicious": False}},
            {"result": {"malicious": True}},
        ],
        "hash_threat_check_items": ["hash_a", "hash_b", "hash_c"],
        "hash_threat_check_any_malicious": True,
    }
    assert _collect_malicious_iocs(context) == ["hash_a", "hash_c"]


def test_length_mismatch_zips_to_shorter_without_raising():
    context = {
        "ip_reputation_results": [
            {"result": {"malicious": True}},
            {"result": {"malicious": True}},
        ],
        "ip_reputation_items": ["1.1.1.1"],  # shorter than results
        "ip_reputation_any_malicious": True,
    }
    assert _collect_malicious_iocs(context) == ["1.1.1.1"]


def test_deduplicates_ioc_from_multiple_steps_preserving_first_occurrence():
    context = {
        "hash_threat_check_results": [{"result": {"malicious": True}}],
        "hash_threat_check_items": ["abc123"],
        "hash_threat_check_any_malicious": True,
        "malwoverview_triage_results": [{"result": {"malicious": True}}],
        "malwoverview_triage_items": ["abc123"],
        "malwoverview_triage_any_malicious": True,
    }
    assert _collect_malicious_iocs(context) == ["abc123"]


def test_no_malicious_flags_returns_empty_list():
    context = {
        "hash_threat_check_results": [{"result": {"malicious": False}}],
        "hash_threat_check_items": ["hash_a"],
        "hash_threat_check_any_malicious": False,
    }
    assert _collect_malicious_iocs(context) == []
    assert _collect_malicious_iocs({}) == []


# ---------------------------------------------------------------------------
# Ticketing hook (in the "All steps completed" block of _run_step_loop)
# ---------------------------------------------------------------------------

def _make_engine(ticketing_config):
    agent_loop = MagicMock()
    agent_loop.config = ticketing_config
    store = MagicMock()
    engine = PlaybookEngine(agent_loop=agent_loop, agent_store=store)
    return engine


@pytest.mark.asyncio
async def test_ticket_created_once_per_distinct_malicious_ioc():
    engine = _make_engine({"ticketing": {"create_on_verdict": ["MALICIOUS", "SUSPICIOUS"]}})
    context = {
        "verdict": "MALICIOUS",
        "hash_threat_check_results": [
            {"result": {"malicious": True}},
            {"result": {"malicious": False}},
        ],
        "hash_threat_check_items": ["hash_a", "hash_b"],
        "hash_threat_check_any_malicious": True,
    }
    with patch("src.agent.playbook_engine.create_incident_ticket") as mock_ticket:
        await engine._run_step_loop(
            session_id="sess-1",
            playbook_id="pb-1",
            pb={"name": "Test Playbook"},
            steps=[],
            step_map={},
            context=context,
            current_step=None,
            step_number=0,
            case_id=None,
        )
    mock_ticket.assert_called_once()
    args, _ = mock_ticket.call_args
    assert args[0]["ioc"] == "hash_a"
    assert args[1] == "sess-1"


@pytest.mark.asyncio
async def test_ticket_not_created_when_verdict_not_in_create_on_verdict():
    engine = _make_engine({"ticketing": {"create_on_verdict": ["MALICIOUS", "SUSPICIOUS"]}})
    context = {
        "verdict": "CLEAN",
        "hash_threat_check_results": [{"result": {"malicious": True}}],
        "hash_threat_check_items": ["hash_a"],
        "hash_threat_check_any_malicious": True,
    }
    with patch("src.agent.playbook_engine.create_incident_ticket") as mock_ticket:
        await engine._run_step_loop(
            session_id="sess-2",
            playbook_id="pb-1",
            pb={"name": "Test Playbook"},
            steps=[],
            step_map={},
            context=context,
            current_step=None,
            step_number=0,
            case_id=None,
        )
    mock_ticket.assert_not_called()
