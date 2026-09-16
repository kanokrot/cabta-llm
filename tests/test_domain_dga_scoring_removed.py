from types import SimpleNamespace

import pytest

from src.tools.ioc_investigator import IOCInvestigator


def _enrichment(*, newly_registered=False, is_dga=False):
    return {
        "domain_age": {
            "domain_age_days": 7 if newly_registered else 365,
            "is_newly_registered": newly_registered,
        },
        "dga_analysis": {
            "is_dga": is_dga,
            "confidence": 0.95 if is_dga else 0.05,
            "dga_family_guess": "鹽鹹" if is_dga else None,
        },
    }


def _make_investigator(monkeypatch, enrichment, sources=None):
    investigator = IOCInvestigator.__new__(IOCInvestigator)
    investigator.config = {
        "analysis": {"enable_llm": False},
        "ticketing": {"create_on_verdict": ["MALICIOUS", "SUSPICIOUS"]},
    }
    investigator.rag_kb = None

    async def investigate_ioc_comprehensive(*args, **kwargs):
        return {
            "sources": sources or {},
            "sources_checked": len(sources or {}),
            "sources_flagged": len(sources or {}),
        }

    investigator.threat_intel = SimpleNamespace(
        investigate_ioc_comprehensive=investigate_ioc_comprehensive
    )

    async def enrich_domain(domain):
        return enrichment

    monkeypatch.setattr(investigator, "_enrich_domain", enrich_domain)
    return investigator


@pytest.mark.asyncio
async def test_newly_registered_domain_without_ti_source_scores_zero(monkeypatch):
    investigator = _make_investigator(
        monkeypatch, _enrichment(newly_registered=True)
    )

    result = await investigator.investigate("newly-registered-example.test")

    assert result["threat_score"] == 0


@pytest.mark.asyncio
async def test_dga_domain_without_ti_source_scores_zero(monkeypatch):
    investigator = _make_investigator(monkeypatch, _enrichment(is_dga=True))

    result = await investigator.investigate("dga-example.test")

    assert result["threat_score"] == 0


@pytest.mark.asyncio
async def test_newly_registered_dga_domain_without_ti_source_scores_zero(monkeypatch):
    investigator = _make_investigator(
        monkeypatch, _enrichment(newly_registered=True, is_dga=True)
    )

    result = await investigator.investigate("newly-dga-example.test")

    assert result["threat_score"] == 0


@pytest.mark.asyncio
async def test_domain_and_dga_metadata_do_not_change_malicious_ti_score(monkeypatch):
    malicious_sources = {
        "feodotracker": {"status": "FLAGGED", "score": 100},
    }

    enriched_investigator = _make_investigator(
        monkeypatch,
        _enrichment(newly_registered=True, is_dga=True),
        sources=malicious_sources,
    )
    enriched_result = await enriched_investigator.investigate(
        "newly-dga-malicious.test"
    )

    plain_investigator = _make_investigator(
        monkeypatch, {}, sources=malicious_sources
    )
    plain_result = await plain_investigator.investigate("malicious.test")

    assert enriched_result["threat_score"] == plain_result["threat_score"]
    assert enriched_result["threat_score"] > 0


@pytest.mark.asyncio
async def test_investigator_preserves_domain_and_dga_metadata(monkeypatch):
    enrichment = _enrichment(newly_registered=True, is_dga=True)
    investigator = _make_investigator(monkeypatch, enrichment)

    result = await investigator.investigate("newly-dga-example.test")

    assert result["threat_score"] == 0
    assert result["domain_enrichment"] == enrichment
    assert result["domain_enrichment"]["domain_age"]["is_newly_registered"] is True
    assert result["domain_enrichment"]["dga_analysis"]["is_dga"] is True
    assert "domain_age_days" in result["domain_enrichment"]["domain_age"]
    assert "dga_family_guess" in result["domain_enrichment"]["dga_analysis"]


@pytest.mark.asyncio
async def test_investigator_preserves_newly_registered_and_dga_recommendations(monkeypatch):
    enrichment = _enrichment(newly_registered=True, is_dga=True)
    investigator = _make_investigator(monkeypatch, enrichment)

    result = await investigator.investigate("newly-dga-example.test")

    recommendations = " ".join(result["recommendations"])
    assert "newly registered" in recommendations
    assert "DGA" in recommendations
