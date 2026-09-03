"""Contract tests for the forensics MITRE ATT&CK mapper tool."""

from src.detection.rule_generator import RuleGenerator
from src.mcp_servers import forensics_tools
from src.mcp_servers.forensics_tools import mitre_attack_mapper


def test_mitre_attack_mapper_returns_capa_compatible_shape():
    findings = {
        "persistence": "A scheduled task launched PowerShell at logon",
        "network": "No suspicious remote connections",
        "file": "No suspicious file was supplied",
    }

    result = mitre_attack_mapper(findings)

    assert result["capabilities"] == []
    assert result["mitre_attacks"]
    for attack in result["mitre_attacks"]:
        assert set(attack) == {"technique", "id", "tactic"}
        assert isinstance(attack["technique"], str)
        assert attack["id"].startswith("T")
        assert isinstance(attack["tactic"], str)


def test_mitre_attack_mapper_returns_empty_shape_for_empty_findings():
    expected = {"capabilities": [], "mitre_attacks": []}

    assert mitre_attack_mapper({}) == expected
    assert mitre_attack_mapper({
        "persistence": "",
        "network": "",
        "file": "",
    }) == expected


def test_mitre_attack_mapper_deduplicates_by_technique_id():
    result = mitre_attack_mapper({
        "persistence": "PowerShell execution was observed",
        "network": "Another PowerShell command was observed",
    })

    technique_ids = [attack["id"] for attack in result["mitre_attacks"]]
    assert technique_ids.count("T1059.001") == 1
    assert len(technique_ids) == len(set(technique_ids))


def test_mitre_attack_mapper_output_works_with_generate_capa_rules():
    mapped = mitre_attack_mapper({
        "persistence": {"command": "schtasks /create", "suspicious": True},
        "network": ["PowerShell", "downloadstring"],
    })

    generated = RuleGenerator.generate_capa_rules(mapped)

    assert "error" not in generated
    assert generated["sigma"]


def test_mitre_attack_mapper_is_registered_with_fastmcp():
    registered_tools = forensics_tools.mcp._tool_manager._tools

    assert "mitre_attack_mapper" in registered_tools
