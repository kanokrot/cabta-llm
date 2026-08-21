"""Test that quarantine_file step in incident_response.yaml uses the
correct parameter name matching the tool_registry.py executor signature."""

import yaml
from pathlib import Path

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
