"""Regression coverage for for_each results used as downstream input params."""

from pathlib import Path

import pytest
import yaml

from src.agent.playbook_engine import PlaybookEngine
from src.mcp_servers.forensics_tools import mitre_attack_mapper


PLAYBOOK_DIR = Path(__file__).resolve().parents[1] / "data" / "playbooks"


def _step(playbook_name, step_name):
    playbook = yaml.safe_load(
        (PLAYBOOK_DIR / playbook_name).read_text(encoding="utf-8")
    )
    return next(step for step in playbook["steps"] if step["name"] == step_name)


def _nested_value(mapping, path):
    value = mapping
    for key in path:
        value = value[key]
    return value


CASES = [
    pytest.param(
        "forensic_triage.yaml",
        "map_attack_technique",
        ("findings", "network"),
        "process_ip_reputation",
        [
            {
                "result": {
                    "ip": "203.0.113.7",
                    "lists_checked": 4,
                    "lists_found": 1,
                    "findings": [{"list": "Spamhaus DROP", "found": True}],
                    "malicious": True,
                    "risk_level": "medium",
                },
                "server": "threat_intel_tools",
                "tool": "blocklist_check",
            }
        ],
        ["203.0.113.7"],
        {
            "persistence_check": {},
            "hash_reputation_check": {},
        },
        id="forensic-mitre-network-results",
    ),
    pytest.param(
        "alert_triage.yaml",
        "high_priority_response",
        ("enriched_iocs",),
        "threatfox_all",
        [
            {
                "result": {
                    "indicator": "evil.example",
                    "malicious": True,
                    "malware": "ExampleRAT",
                },
                "server": "threat_intel_tools",
                "tool": "threatfox_ioc_lookup",
            }
        ],
        ["evil.example"],
        {"alert_text": "Suspicious IOC observed in alert"},
        id="alert-trigger-enriched-results",
    ),
    pytest.param(
        "email_investigation.yaml",
        "confirm_malicious_email",
        ("threat_intel",),
        "threatfox_all",
        [
            {
                "result": {
                    "indicator": "https://evil.example/payload",
                    "malicious": True,
                    "confidence": 90,
                },
                "server": "threat_intel_tools",
                "tool": "threatfox_ioc_lookup",
            }
        ],
        ["https://evil.example/payload"],
        {
            "parse_email": {},
            "extract_email_iocs": {},
        },
        id="email-generate-rules-threat-intel-results",
    ),
    pytest.param(
        "incident_response.yaml",
        "cross_correlate_findings",
        ("network_analysis", "port_check"),
        "suspicious_port_check",
        [
            {
                "result": {
                    "ip": "198.51.100.9",
                    "open_ports": [22, 4444],
                    "suspicious": True,
                },
                "server": "network_tools",
                "tool": "port_check",
            }
        ],
        ["198.51.100.9"],
        {
            "extract_incident_iocs": {},
            "threatfox_check_ipv4_results": [],
            "threatfox_check_domains_results": [],
            "threatfox_check_urls_results": [],
            "threatfox_check_sha256_results": [],
            "zeek_log_analysis": {},
            "suricata_alert_analysis": {},
            "timeline_analysis": {},
        },
        id="incident-correlation-port-results",
    ),
]


@pytest.mark.parametrize(
    (
        "playbook_name",
        "consumer_step",
        "param_path",
        "producer_step",
        "iteration_results",
        "iteration_items",
        "fixture_context",
    ),
    CASES,
)
def test_for_each_input_param_uses_and_resolves_results(
    playbook_name,
    consumer_step,
    param_path,
    producer_step,
    iteration_results,
    iteration_items,
    fixture_context,
):
    step = _step(playbook_name, consumer_step)
    expected_template = f"{{{{{producer_step}_results}}}}"
    bare_template = f"{{{{{producer_step}}}}}"
    configured_value = _nested_value(step["params"], param_path)

    assert configured_value == expected_template
    assert configured_value != bare_template

    # Placeholder values only to satisfy fail-fast; they are not the real field contract.
    context = {
        **fixture_context,
        f"{producer_step}_results": iteration_results,
        f"{producer_step}_items": iteration_items,
        f"{producer_step}_any_malicious": True,
        f"{producer_step}_any_suspicious": False,
    }
    engine = object.__new__(PlaybookEngine)
    interpolated = engine._interpolate_params(step["params"], context)
    resolved_value = _nested_value(interpolated, param_path)

    assert resolved_value is iteration_results
    assert resolved_value is not None
    assert resolved_value != bare_template

    if producer_step == "process_ip_reputation":
        assert isinstance(interpolated["findings"]["network"], list)
        mapped = mitre_attack_mapper(interpolated["findings"])
        assert set(mapped) == {"capabilities", "mitre_attacks"}
