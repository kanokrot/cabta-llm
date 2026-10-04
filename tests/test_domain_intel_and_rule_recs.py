from types import SimpleNamespace

import pytest

from src.tools.ioc_investigator import IOCInvestigator
from src.web.visibility import serialize_report_job


class StubLLM:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error

    async def analyze_ioc_results(self, *args, **kwargs):
        if self.error:
            raise self.error
        return self.response


def _make_investigator(monkeypatch, llm, domain_enrichment):
    investigator = IOCInvestigator.__new__(IOCInvestigator)
    investigator.config = {
        "analysis": {"enable_llm": True},
        "ticketing": {"create_on_verdict": []},
    }
    investigator.rag_kb = None
    investigator.notification_manager = None
    investigator.llm_analyzer = llm

    async def investigate_ioc_comprehensive(*args, **kwargs):
        return {
            "sources": {"test_source": {"status": "✓", "found": False}},
            "sources_checked": 1,
            "sources_flagged": 0,
        }

    investigator.threat_intel = SimpleNamespace(
        investigate_ioc_comprehensive=investigate_ioc_comprehensive
    )
    investigator._trusted_infrastructure_match = lambda *args: None

    async def enrich_domain(_domain):
        return domain_enrichment

    investigator._enrich_domain = enrich_domain
    monkeypatch.setattr(
        "src.tools.ioc_investigator.IntelligentScoring.calculate_ioc_score",
        lambda _results: 0,
    )
    monkeypatch.setattr(
        "src.tools.ioc_investigator.IntelligentScoring.calculate_source_coverage",
        lambda _results: {
            "total_sources_attempted": 1,
            "sources_flagged": 0,
            "sources_clean": 1,
        },
    )
    monkeypatch.setattr(
        "src.tools.ioc_investigator.RuleGenerator.generate_ioc_rules",
        lambda *_args: {},
    )
    return investigator


def _enrichment(newly_registered=False, is_dga=True):
    return {
        "domain_age": {
            "domain": "kurs.if.ua",
            "creation_date": "1992-12-01T00:00:00+00:00",
            "age_days": 12360,
            "is_newly_registered": newly_registered,
            "risk_level": "none",
            "error": None,
            "registrar": "drop",
            "raw_whois": {"drop": True},
        },
        "dga_analysis": {
            "domain": "kurs.if.ua",
            "sld": "kurs",
            "entropy": 2.0,
            "consonant_ratio": 0.75,
            "ngram_score": 0.3333,
            "confidence": 85,
            "is_dga": is_dga,
            "dga_family_guess": "family-name",
            "dictionary_match": {
                "coverage": 0.5,
                "word_count": 2,
                "words_found": [f"word-{i}" for i in range(50)],
                "extra": "drop",
            },
            "extra": {"drop": True},
        },
    }


@pytest.mark.asyncio
async def test_llm_and_rule_based_recommendations_are_stored_separately(monkeypatch):
    llm_recommendations = ["LLM recommendation"]
    investigator = _make_investigator(
        monkeypatch,
        StubLLM(response={
            "verdict": "CLEAN",
            "analysis": "No findings.",
            "recommendations": llm_recommendations,
        }),
        _enrichment(is_dga=True),
    )

    result = await investigator.investigate("kurs.if.ua")
    expected_rule_based = investigator._generate_recommendations("CLEAN", {})
    expected_rule_based.append("DGA result: is_dga=True, confidence=85")

    assert result["recommendations"] == llm_recommendations
    assert result["recommendations_rule_based"] == expected_rule_based
    assert result["recommendations_source"] == "llm"
    assert result["recommendations"] is not result["recommendations_rule_based"]
    result["recommendations"].append("mutated")
    assert "mutated" not in result["recommendations_rule_based"]


@pytest.mark.asyncio
async def test_llm_failure_preserves_fallback_recommendations(monkeypatch):
    investigator = _make_investigator(
        monkeypatch,
        StubLLM(error=RuntimeError("LLM unavailable")),
        _enrichment(is_dga=True),
    )

    result = await investigator.investigate("kurs.if.ua")
    expected = investigator._generate_recommendations("CLEAN", {})
    expected.append("DGA result: is_dga=True, confidence=85")

    assert result["recommendations"] == expected
    assert result["recommendations_rule_based"] == expected
    assert result["recommendations_source"] == "rule_based"
    assert result["recommendations"] is not result["recommendations_rule_based"]


@pytest.mark.asyncio
async def test_newly_registered_line_is_first_in_both_lists(monkeypatch):
    investigator = _make_investigator(
        monkeypatch,
        StubLLM(response={
            "verdict": "CLEAN",
            "analysis": "Review required.",
            "recommendations": ["LLM recommendation"],
        }),
        _enrichment(newly_registered=True, is_dga=False),
    )

    result = await investigator.investigate("kurs.if.ua")
    assert "Domain is newly registered (<30 days) - high risk indicator" in result["recommendations"][0]
    assert "Domain is newly registered (<30 days) - high risk indicator" in result["recommendations_rule_based"][0]


def test_domain_enrichment_is_bounded_and_same_for_roles():
    job = {
        "id": "job",
        "analysis_type": "ioc",
        "params": {"value": "kurs.if.ua", "ioc_type": "domain"},
        "result": {
            "domain_enrichment": _enrichment(),
            "recommendations_rule_based": ["rule one", {"drop": True}, 3],
            "recommendations_source": "llm",
        },
    }

    admin = serialize_report_job(job, role="admin")["result"]
    soc = serialize_report_job(
        job, role="SOC Analyst Tier 1-2", viewer_user_id=99
    )["result"]
    assert admin == soc
    assert admin["recommendations_rule_based"] == ["rule one", 3]
    assert admin["recommendations_source"] == "llm"
    safe = admin["domain_enrichment"]
    assert "registrar" not in safe["domain_age"]
    assert "raw_whois" not in safe["domain_age"]
    assert len(safe["dga_analysis"]["dictionary_match"]["words_found"]) == 10
    assert "extra" not in safe["dga_analysis"]
    assert "extra" not in safe["dga_analysis"]["dictionary_match"]


def test_serializer_drops_invalid_optional_values_and_handles_missing_keys():
    job = {
        "id": "job",
        "analysis_type": "ioc",
        "params": {"value": "example.com", "ioc_type": "domain"},
        "result": {
            "domain_enrichment": {
                "domain_age": {
                    "domain": 123,
                    "creation_date": {"drop": True},
                    "age_days": True,
                    "is_newly_registered": "false",
                    "risk_level": 7,
                    "error": "failed https://example.test/?token=secret",
                },
                "dga_analysis": {
                    "entropy": "2.0",
                    "confidence": True,
                    "is_dga": 1,
                    "dga_family_guess": None,
                    "dictionary_match": {
                        "coverage": "0.5",
                        "word_count": False,
                        "words_found": ["ok", {"drop": True}],
                    },
                },
            },
            "recommendations_rule_based": "wrong",
            "recommendations_source": "other",
        },
    }
    result = serialize_report_job(job, role="admin")["result"]
    assert result["domain_enrichment"] == {
        "domain_age": {"error": "failed [url]"},
        "dga_analysis": {"dictionary_match": {"words_found": ["ok"]}},
    }
    assert "recommendations_rule_based" not in result
    assert "recommendations_source" not in result

    plain = serialize_report_job(
        {"id": "plain", "analysis_type": "ioc", "params": {}, "result": {}},
        role="admin",
    )["result"]
    assert "domain_enrichment" not in plain
    assert "recommendations_rule_based" not in plain
    assert "recommendations_source" not in plain
