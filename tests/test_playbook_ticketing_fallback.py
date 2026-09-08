"""Tests for fallback ticket identifiers at playbook completion."""

from unittest.mock import MagicMock, patch

import pytest

from src.agent.playbook_engine import PlaybookEngine


def _make_engine(ticketing_config):
    agent_loop = MagicMock()
    agent_loop.config = ticketing_config
    return PlaybookEngine(agent_loop=agent_loop, agent_store=MagicMock())


async def _run_completed_playbook(engine, context):
    await engine._run_step_loop(
        session_id="fallback-session",
        playbook_id="fallback-playbook",
        pb={"name": "Fallback Playbook"},
        steps=[],
        step_map={},
        context=context,
        current_step=None,
        step_number=0,
        case_id=None,
    )


def _ticketing_engine():
    return _make_engine({"ticketing": {"create_on_verdict": ["MALICIOUS"]}})


@pytest.mark.asyncio
async def test_fallback_ticket_uses_direct_context_ioc():
    with patch("src.agent.playbook_engine.create_incident_ticket") as mock_ticket:
        await _run_completed_playbook(
            _ticketing_engine(), {"verdict": "MALICIOUS", "ioc": "direct-ioc"},
        )

    mock_ticket.assert_called_once()
    assert mock_ticket.call_args.args[0]["ioc"] == "direct-ioc"


@pytest.mark.asyncio
async def test_fallback_ticket_uses_ioc_investigation_result_ioc():
    context = {
        "verdict": "MALICIOUS",
        "ioc_lookup": {
            "ioc": "investigated-ioc",
            "verdict": "MALICIOUS",
            "threat_score": 95,
            "sources": {},
            "ioc_type": "domain",
        },
    }
    with patch("src.agent.playbook_engine.create_incident_ticket") as mock_ticket:
        await _run_completed_playbook(_ticketing_engine(), context)

    mock_ticket.assert_called_once()
    assert mock_ticket.call_args.args[0]["ioc"] == "investigated-ioc"


@pytest.mark.asyncio
async def test_fallback_ticket_uses_local_full_analysis_sha256():
    context = {
        "verdict": "MALICIOUS",
        "local_full_analysis": {"hashes": {"sha256": "sha256-value"}},
    }
    with patch("src.agent.playbook_engine.create_incident_ticket") as mock_ticket:
        await _run_completed_playbook(_ticketing_engine(), context)

    mock_ticket.assert_called_once()
    assert mock_ticket.call_args.args[0]["ioc"] == "sha256-value"


@pytest.mark.asyncio
async def test_fallback_ticket_uses_file_path():
    with patch("src.agent.playbook_engine.create_incident_ticket") as mock_ticket:
        await _run_completed_playbook(
            _ticketing_engine(),
            {"verdict": "MALICIOUS", "file_path": "C:/samples/suspicious.exe"},
        )

    mock_ticket.assert_called_once()
    assert mock_ticket.call_args.args[0]["ioc"] == "C:/samples/suspicious.exe"


@pytest.mark.asyncio
async def test_fallback_ticket_uses_unknown_ioc_as_last_resort():
    with patch("src.agent.playbook_engine.create_incident_ticket") as mock_ticket:
        await _run_completed_playbook(_ticketing_engine(), {"verdict": "MALICIOUS"})

    mock_ticket.assert_called_once()
    assert mock_ticket.call_args.args[0]["ioc"] == "unknown_ioc"


@pytest.mark.asyncio
async def test_nonempty_malicious_iocs_create_one_ticket_per_ioc_without_fallback():
    context = {
        "verdict": "MALICIOUS",
        "collected_malicious_iocs": ["hash_a", "hash_c"],
        "ioc": "fallback-must-not-be-used",
    }
    with patch("src.agent.playbook_engine.create_incident_ticket") as mock_ticket:
        await _run_completed_playbook(_ticketing_engine(), context)

    assert mock_ticket.call_count == len(context["collected_malicious_iocs"])
    assert [call.args[0]["ioc"] for call in mock_ticket.call_args_list] == [
        "hash_a", "hash_c",
    ]


@pytest.mark.asyncio
async def test_fallback_does_not_create_ticket_when_verdict_is_not_configured():
    engine = _make_engine({"ticketing": {"create_on_verdict": ["MALICIOUS"]}})
    context = {"verdict": "CLEAN", "ioc": "must-not-be-ticketed"}
    with patch("src.agent.playbook_engine.create_incident_ticket") as mock_ticket:
        await _run_completed_playbook(engine, context)

    mock_ticket.assert_not_called()
