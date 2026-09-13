import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from src.integrations.threat_intel import ThreatIntelligence
from src.scoring.intelligent_scoring import IntelligentScoring
from src.utils.helpers import determine_verdict


REPO_ROOT = Path(__file__).resolve().parents[1]


def _assigned_string_list(path, variable_name):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == variable_name:
            return ast.literal_eval(node.value)
    raise AssertionError(f"Could not find {variable_name} in {path}")


def _task_source_names(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "append":
            continue
        if not isinstance(node.func.value, ast.Name) or node.func.value.id != "tasks":
            continue
        if not node.args or not isinstance(node.args[0], ast.Tuple):
            continue
        first = node.args[0].elts[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            names.add(first.value)
    return names


def test_tier_sources_and_comprehensive_tasks_are_one_to_one():
    scoring_path = REPO_ROOT / "src" / "scoring" / "intelligent_scoring.py"
    threat_intel_path = REPO_ROOT / "src" / "integrations" / "threat_intel.py"

    tier_sources = set()
    for variable_name in (
        "high_confidence_sources",
        "medium_confidence_sources",
        "low_confidence_sources",
    ):
        tier_sources.update(_assigned_string_list(scoring_path, variable_name))

    task_sources = _task_source_names(threat_intel_path)

    assert tier_sources == task_sources


def _build_wire_test_intelligence():
    intelligence = ThreatIntelligence.__new__(ThreatIntelligence)
    intelligence._ioc_cache = Mock()
    intelligence._ioc_cache.get.return_value = None

    root_methods = (
        "check_virustotal",
        "check_threatfox",
        "check_abuseipdb",
        "check_shodan",
        "check_feodotracker",
        "check_tor_exit_nodes",
        "check_c2_trackers",
        "check_alienvault",
        "check_urlhaus",
        "check_malwarebazaar",
    )
    for method_name in root_methods:
        setattr(
            intelligence,
            method_name,
            AsyncMock(return_value={"status": "âœ—", "score": 0}),
        )

    extended_methods = (
        "check_greynoise",
        "check_censys",
        "check_talos",
        "check_criminalip",
        "check_ipqualityscore",
        "check_spamhaus",
        "check_ip2proxy",
        "check_pulsedive",
        "check_phishtank",
        "check_triage",
        "check_threatzone",
    )
    intelligence.extended = SimpleNamespace(
        **{
            method_name: AsyncMock(return_value={"status": "âœ—", "score": 0})
            for method_name in extended_methods
        }
    )
    intelligence.threat_feeds = SimpleNamespace(
        check_ssl_blacklist=AsyncMock(return_value={"status": "âœ—", "score": 0}),
        check_usom=AsyncMock(return_value={"status": "âœ—", "score": 0}),
    )
    return intelligence


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ioc,ioc_type",
    [("192.0.2.1", "ipv4"), ("a" * 40, "sha1")],
)
async def test_sslblacklist_is_called_for_supported_ioc_types(ioc, ioc_type):
    intelligence = _build_wire_test_intelligence()

    result = await intelligence.investigate_ioc_comprehensive(ioc, ioc_type)

    intelligence.threat_feeds.check_ssl_blacklist.assert_awaited_once_with(ioc)
    assert "sslblacklist" in result["sources"]


def _build_hash_intelligence(source_results):
    intelligence = ThreatIntelligence.__new__(ThreatIntelligence)
    intelligence._ioc_cache = Mock()
    intelligence._ioc_cache.get.return_value = None

    intelligence.check_virustotal = AsyncMock(
        return_value=source_results["virustotal"]
    )
    intelligence.check_threatfox = AsyncMock(
        return_value=source_results["threatfox"]
    )
    intelligence.check_malwarebazaar = AsyncMock(
        return_value=source_results["malwarebazaar"]
    )
    intelligence.check_alienvault = AsyncMock(
        return_value=source_results["alienvault"]
    )
    intelligence.extended = SimpleNamespace(
        check_triage=AsyncMock(return_value=source_results["triage"]),
        check_threatzone=AsyncMock(return_value=source_results["threatzone"]),
    )
    return intelligence


@pytest.mark.asyncio
async def test_hash_source_accounting_excludes_unscheduled_placeholders():
    intelligence = _build_hash_intelligence({
        "virustotal": {"status": "✓", "score": 80},
        "threatfox": {"status": "✗", "score": 0},
        "malwarebazaar": {"status": "✗", "score": 0},
        "alienvault": {"status": "✗", "score": 0},
        "triage": {"status": "⚠", "error": "Timeout"},
        "threatzone": {"status": "⚠", "error": "Service unavailable"},
    })

    result = await intelligence.investigate_ioc_comprehensive(
        "a" * 64,
        "sha256",
    )
    coverage = IntelligentScoring.calculate_source_coverage(result)

    assert result["sources_checked"] == 6
    assert result["sources_flagged"] == 1
    assert coverage == {
        "sources_flagged": 1,
        "sources_clean": 3,
        "sources_unavailable": 2,
        "sources_stale": 0,
        "total_sources_attempted": 6,
        "sources_skipped_not_applicable": 18,
    }
    assert result["sources"]["c2_trackers"] == {
        "status": "⏳",
        "message": "Pending",
        "not_applicable": True,
    }


def test_skipped_sources_do_not_inflate_verdict_coverage():
    coverage = IntelligentScoring.calculate_source_coverage({
        "sources": {
            "attempted": {"status": "⚠", "error": "Timeout"},
            **{
                f"skipped_{index}": {
                    "status": "➖",
                    "message": "IP only",
                    "not_applicable": True,
                }
                for index in range(5)
            },
        }
    })

    assert coverage["total_sources_attempted"] == 1
    assert coverage["sources_unavailable"] == 1
    assert coverage["sources_skipped_not_applicable"] == 5
    assert determine_verdict(22, coverage) == "UNKNOWN"
