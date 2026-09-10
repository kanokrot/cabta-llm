"""Regression coverage for forensic_triage confirm_incident network IOCs."""

from pathlib import Path

import pytest
import yaml

from src.agent.playbook_engine import PlaybookEngine
from src.agent.tool_registry import ToolRegistry


PLAYBOOK_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "playbooks"
    / "forensic_triage.yaml"
)


def _confirm_incident_step():
    playbook = yaml.safe_load(PLAYBOOK_PATH.read_text(encoding="utf-8"))
    return next(
        step for step in playbook["steps"] if step["name"] == "confirm_incident"
    )


@pytest.mark.asyncio
async def test_confirm_incident_passes_network_iocs_to_generate_rules():
    step = _confirm_incident_step()
    mapper_result = {
        "result": {
            "capabilities": [],
            "mitre_attacks": [
                {
                    "technique": "PowerShell",
                    "id": "T1059.001",
                    "tactic": "Execution",
                }
            ],
        },
        "server": "forensics_tools",
        "tool": "mitre_attack_mapper",
    }
    extracted_iocs = {
        "iocs": {
            "ipv4": ["203.0.113.42"],
            "domains": ["malicious.test"],
            "urls": ["https://malicious.test/payload"],
            "emails": [],
            "hashes": {"md5": [], "sha1": [], "sha256": []},
        }
    }
    context = {
        "map_attack_technique": mapper_result,
        "extract_iocs": extracted_iocs,
    }

    engine = object.__new__(PlaybookEngine)
    params = engine._interpolate_params(step["params"], context)

    assert params["network_iocs"] is extracted_iocs
    assert "iocs" not in params

    registry = ToolRegistry()
    registry.register_default_tools({})
    schema = registry.get_tool("generate_rules").parameters
    assert "network_iocs" in schema["properties"]

    result = await registry.execute_local_tool("generate_rules", **params)

    assert "error" not in result
    assert "suricata" in result["rules"]
    assert "firewall" in result["rules"]
    assert len(result["rules"]["suricata"]) == 3
    assert len(result["rules"]["firewall"]) == 3
