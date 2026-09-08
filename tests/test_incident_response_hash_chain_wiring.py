"""Integration coverage for the computed-file-hash reputation chain."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.agent.playbook_engine import PlaybookEngine, _resolve_var
from src.agent.tool_registry import extract_file_hash_pairs


def _engine_and_steps():
    agent_loop = MagicMock()
    agent_loop.config = {}
    agent_loop._notify = MagicMock()
    store = MagicMock()
    engine = PlaybookEngine(agent_loop=agent_loop, agent_store=store)
    playbook = engine._cache["incident_response"]
    wanted = {
        "forensic_file_analysis",
        "extract_file_hashes",
        "computed_hash_threat_check",
        "quarantine_artifacts",
    }
    steps_by_name = {
        step.name: step for step in playbook["_parsed_steps"] if step.name in wanted
    }
    return engine, agent_loop, store, playbook, steps_by_name


async def _run_hash_chain(file_paths, malicious_hashes=()):
    engine, agent_loop, _store, playbook, steps_by_name = _engine_and_steps()
    chain_names = [
        "forensic_file_analysis",
        "extract_file_hashes",
        "computed_hash_threat_check",
    ]
    steps = [steps_by_name[name] for name in chain_names]
    hashes_by_path = {
        file_path: f"sha256-{index}" for index, file_path in enumerate(file_paths)
    }

    async def run_tool(tool_name, params):
        if tool_name == "mcp:forensics_tools/file_metadata":
            return {
                "result": {"hashes": {"sha256": hashes_by_path[params["file_path"]]}},
                "server": "forensics_tools",
                "tool": "file_metadata",
            }
        if tool_name == "extract_file_hash_pairs":
            return await extract_file_hash_pairs(**params)
        if tool_name == "mcp:threat_intel_tools/malwarebazaar_hash_lookup":
            hash_value = params["hash_value"]
            result = (
                {"query_status": "ok", "data": [{"sha256_hash": hash_value}]}
                if hash_value in malicious_hashes
                else {"query_status": "no_results"}
            )
            return {
                "result": result,
                "server": "threat_intel_tools",
                "tool": "malwarebazaar_hash_lookup",
            }
        raise AssertionError(f"unexpected tool: {tool_name}")

    agent_loop.run_tool = AsyncMock(side_effect=run_tool)
    context = {"extract_incident_iocs": {"file_paths": file_paths}}
    await engine._run_step_loop(
        session_id="hash-chain-test",
        playbook_id="incident_response",
        pb=playbook,
        steps=steps,
        step_map={step.name: step for step in steps},
        context=context,
        current_step=steps[0],
        step_number=0,
        case_id=None,
    )
    return engine, steps_by_name, context, hashes_by_path


@pytest.mark.asyncio
async def test_computed_hash_malicious_result_is_aggregated_and_quarantine_param_resolves():
    file_paths = ["first.exe", "second.exe"]
    malicious_hash = "sha256-1"

    engine, steps_by_name, context, _hashes_by_path = await _run_hash_chain(
        file_paths, malicious_hashes=(malicious_hash,)
    )

    assert context["computed_hash_threat_check_any_malicious"] is True
    assert malicious_hash in context["collected_malicious_iocs"]
    quarantine_params = engine._interpolate_params(
        steps_by_name["quarantine_artifacts"].params, context
    )
    assert _resolve_var("collected_malicious_iocs", context) is not None
    assert isinstance(quarantine_params["file_path"], list)
    assert malicious_hash in quarantine_params["file_path"]


@pytest.mark.asyncio
async def test_computed_hash_clean_results_are_not_collected_as_malicious():
    _engine, _steps_by_name, context, hashes_by_path = await _run_hash_chain(
        ["first.exe", "second.exe"]
    )

    assert context["computed_hash_threat_check_any_malicious"] is False
    assert not set(hashes_by_path.values()).intersection(context["collected_malicious_iocs"])


@pytest.mark.asyncio
async def test_empty_file_path_list_completes_the_hash_chain_without_error():
    _engine, _steps_by_name, context, _hashes_by_path = await _run_hash_chain([])

    assert context["forensic_file_analysis_results"] == []
    assert context["extract_file_hashes"]["hashes"] == []
    assert context["computed_hash_threat_check_results"] == []
    assert context["computed_hash_threat_check_any_malicious"] is False
    assert context["collected_malicious_iocs"] == []
