"""Regression evidence for unsuffixed references to ``for_each`` results."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.agent.playbook_engine import PlaybookEngine, PlaybookStep, _resolve_var


@pytest.mark.asyncio
async def test_for_each_execution_only_populates_suffixed_context_keys():
    """Supporting evidence: the loop runs, but no unsuffixed key is stored."""
    store = MagicMock()
    agent_loop = MagicMock()
    agent_loop.config = {}
    agent_loop.run_tool = AsyncMock(return_value={"malicious": True})

    engine = PlaybookEngine(agent_loop=agent_loop, agent_store=store)
    step = PlaybookStep.from_dict(
        {
            "name": "sample_lookup",
            "tool": "sample_tool",
            "for_each": "samples",
            "params": {"sample": "{{item}}"},
        }
    )
    context = {"samples": ["one", "two"]}

    await engine._run_step_loop(
        session_id="test-session",
        playbook_id="test-playbook",
        pb={"name": "For-each context regression"},
        steps=[step],
        step_map={"sample_lookup": step},
        context=context,
        current_step=step,
        step_number=0,
        case_id=None,
    )

    assert context.get("sample_lookup_results") is not None
    assert context.get("sample_lookup") is None


def test_unsuffixed_template_reference_should_detect_malicious_loop_result():
    """The downstream playbook spelling should expose the malicious finding."""
    context = {
        "url_urlhaus_results": [
            {"malicious": True, "indicator": "https://malicious.example"}
        ],
        "url_urlhaus_any_malicious": True,
        "url_urlhaus_items": ["https://malicious.example"],
    }

    resolved_value = _resolve_var("url_urlhaus.malicious", context)
    expected_malicious_flag = True

    assert resolved_value == expected_malicious_flag, (
        "BUG: for_each result stored under 'url_urlhaus_results' is not "
        "accessible via unsuffixed template '{{url_urlhaus.malicious}}' — "
        "see playbook_engine.py:1261-1264"
    )
