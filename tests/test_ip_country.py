import json
from unittest.mock import Mock

import pytest

from src.tools.ioc_investigator import IOCInvestigator
from src.utils import ip_geo


@pytest.fixture(autouse=True)
def clear_ip_country_cache():
    ip_geo._lookup_public_ip_country.cache_clear()
    yield
    ip_geo._lookup_public_ip_country.cache_clear()


def test_lookup_ip_country_returns_uppercase_two_letter_code(monkeypatch):
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = json.dumps(
        {"status": "success", "country": "United States", "countryCode": "us"}
    ).encode()
    urlopen = Mock(return_value=response)
    monkeypatch.setattr(ip_geo, "urlopen", urlopen)

    assert ip_geo.lookup_ip_country("8.8.8.8") == "US"
    urlopen.assert_called_once()
    assert urlopen.call_args.kwargs["timeout"] == 3


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1"])
def test_lookup_ip_country_skips_non_public_addresses(monkeypatch, address):
    urlopen = Mock(side_effect=AssertionError("network call should be skipped"))
    monkeypatch.setattr(ip_geo, "urlopen", urlopen)

    assert ip_geo.lookup_ip_country(address) is None
    urlopen.assert_not_called()


def test_lookup_ip_country_returns_none_on_lookup_failure(monkeypatch):
    monkeypatch.setattr(ip_geo, "urlopen", Mock(side_effect=TimeoutError("timeout")))

    assert ip_geo.lookup_ip_country("8.8.4.4") is None


def test_lookup_ip_country_caches_success(monkeypatch):
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = b'{"status":"success","countryCode":"CA"}'
    urlopen = Mock(return_value=response)
    monkeypatch.setattr(ip_geo, "urlopen", urlopen)

    assert ip_geo.lookup_ip_country("1.1.1.1") == "CA"
    assert ip_geo.lookup_ip_country("1.1.1.1") == "CA"
    urlopen.assert_called_once()


class _NoLLM:
    async def analyze_ioc_results(self, *args, **kwargs):
        return {}


def _make_investigator(monkeypatch, sources=None):
    investigator = IOCInvestigator.__new__(IOCInvestigator)
    investigator.config = {
        "analysis": {"enable_llm": False},
        "ticketing": {"create_on_verdict": []},
    }
    investigator.notification_manager = None
    investigator.rag_kb = None
    investigator.llm_analyzer = _NoLLM()

    class ThreatIntel:
        async def investigate_ioc_comprehensive(self, *args, **kwargs):
            return {
                "sources": sources or {},
                "sources_checked": 0,
                "sources_flagged": 0,
            }

    investigator.threat_intel = ThreatIntel()
    investigator._trusted_infrastructure_match = lambda *_args: None
    async def no_domain_enrichment(_domain):
        return None

    investigator._enrich_domain = no_domain_enrichment
    monkeypatch.setattr(
        "src.tools.ioc_investigator.IntelligentScoring.calculate_ioc_score",
        lambda _results: 37,
    )
    monkeypatch.setattr(
        "src.tools.ioc_investigator.IntelligentScoring.calculate_source_coverage",
        lambda _results: {"total_sources_attempted": 0, "sources_flagged": 0},
    )
    monkeypatch.setattr(
        "src.tools.ioc_investigator.RuleGenerator.generate_ioc_rules",
        lambda *_args: {},
    )
    return investigator


@pytest.mark.asyncio
async def test_investigator_adds_country_only_for_ip_and_preserves_verdict_score(monkeypatch):
    monkeypatch.setattr("src.tools.ioc_investigator.lookup_ip_country", lambda _ip: "US")
    investigator = _make_investigator(monkeypatch)

    ip_result = await investigator.investigate("8.8.8.8")
    domain_result = await investigator.investigate("example.com")

    assert ip_result["country_code"] == "US"
    assert ip_result["verdict"] == domain_result["verdict"]
    assert ip_result["threat_score"] == domain_result["threat_score"] == 37
    assert "country_code" not in domain_result
    assert "country_name" not in domain_result


@pytest.mark.asyncio
async def test_investigator_prefers_provider_code_before_helper(monkeypatch):
    helper = Mock(side_effect=AssertionError("provider code should win"))
    monkeypatch.setattr("src.tools.ioc_investigator.lookup_ip_country", helper)
    investigator = _make_investigator(
        monkeypatch,
        sources={
            "ip2proxy": {"country": "ca"},
            "criminalip": {"country": "Canada"},
        },
    )

    result = await investigator.investigate("8.8.8.8")

    assert result["country_code"] == "CA"
    assert result["country_name"] == "Canada"
    helper.assert_not_called()


@pytest.mark.asyncio
async def test_failing_country_helper_leaves_result_identical(monkeypatch):
    investigator = _make_investigator(monkeypatch)
    monkeypatch.setattr("src.tools.ioc_investigator.lookup_ip_country", lambda _ip: None)
    baseline = await investigator.investigate("8.8.8.8")
    monkeypatch.setattr(
        "src.tools.ioc_investigator.lookup_ip_country",
        Mock(side_effect=RuntimeError("lookup unavailable")),
    )
    result = await investigator.investigate("8.8.8.8")

    assert result == baseline
    assert "country_code" not in result
    assert "country_name" not in result
    assert result["verdict"] == "CLEAN"
    assert result["threat_score"] == 37
