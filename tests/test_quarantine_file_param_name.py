"""Test that quarantine_file step in incident_response.yaml uses the
correct parameter name matching the tool_registry.py executor signature."""

import tempfile
from pathlib import Path

import pytest
import yaml

from src.agent import tool_registry

PLAYBOOK_PATH = Path(__file__).parent.parent / "data" / "playbooks" / "incident_response.yaml"


def test_quarantine_file_step_uses_correct_param_name():
    """quarantine_file executor expects 'file_path', not 'targets'."""
    with open(PLAYBOOK_PATH, "r", encoding="utf-8") as f:
        playbook = yaml.safe_load(f)

    steps = playbook.get("steps", [])
    quarantine_steps = [s for s in steps if s.get("tool") == "quarantine_file"]

    assert quarantine_steps, "No quarantine_file step found in incident_response.yaml"

    for step in quarantine_steps:
        params = step.get("params", {})
        assert "file_path" in params, (
            f"Step '{step.get('name')}' uses wrong param name. "
            f"Found keys: {list(params.keys())}. Executor expects 'file_path'."
        )
        assert "targets" not in params, (
            f"Step '{step.get('name')}' still has stale 'targets' param name."
        )


@pytest.mark.asyncio
async def test_quarantine_file_rejects_list_file_path():
    result = await tool_registry.quarantine_file(file_path=["sample.exe"])

    assert result["status"] == "error"
    assert result["simulated"] is True
    assert result["error"] == "file_path must be a string, got list"


@pytest.mark.asyncio
async def test_quarantine_file_rejects_sha256_ioc():
    sha256 = "a" * 64

    result = await tool_registry.quarantine_file(file_path=sha256)

    assert result["status"] == "error"
    assert result["simulated"] is True
    assert result["error"] == (
        f"file_path appears to be an IOC, not a filesystem path: {sha256}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("ip_address", ["192.0.2.10", "2001:db8::10"])
async def test_quarantine_file_rejects_ip_ioc(ip_address):
    result = await tool_registry.quarantine_file(file_path=ip_address)

    assert result["status"] == "error"
    assert result["simulated"] is True
    assert result["error"] == (
        f"file_path appears to be an IOC, not a filesystem path: {ip_address}"
    )


@pytest.mark.asyncio
async def test_quarantine_file_rejects_domain_ioc():
    domain = "malicious.example"

    result = await tool_registry.quarantine_file(file_path=domain)

    assert result["status"] == "error"
    assert result["simulated"] is True
    assert result["error"] == (
        f"file_path appears to be an IOC, not a filesystem path: {domain}"
    )


@pytest.mark.asyncio
async def test_quarantine_file_missing_normal_path_still_succeeds(monkeypatch):
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
        temp_path = Path(temp_dir)
        simulated_actions_dir = temp_path / "simulated_actions"
        monkeypatch.setattr(tool_registry, "_SIMULATED_ACTIONS_DIR", simulated_actions_dir)
        missing_path = temp_path / "missing_sample.exe"

        result = await tool_registry.quarantine_file(file_path=str(missing_path))

    assert result["status"] == "success"
    assert result["simulated"] is True
    assert result["message"] == "simulated, source file not found"
    assert result["record"]["note"] == "simulated, source file not found"
