import re
from pathlib import Path
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader


def _render(result):
    templates_dir = Path(__file__).resolve().parents[1] / "templates"
    template = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=True,
    ).get_template("report_view.html")
    return template.render(
        job={
            "id": "domain-intel-test",
            "ioc": result.get("ioc", "kurs.if.ua"),
            "score": 0,
            "result": result,
        },
        request=SimpleNamespace(
            query_params={},
            url=SimpleNamespace(path="/report/domain-intel-test"),
            state=SimpleNamespace(user={"role": "admin"}),
        ),
    )


def _domain_result(*, domain="kurs.if.ua", is_dga=True, confidence=67):
    return {
        "ioc": domain,
        "domain_enrichment": {
            "domain_age": {
                "domain": domain,
                "creation_date": "1992-01-02T00:00:00+00:00",
                "age_days": 12360,
                "is_newly_registered": False,
                "risk_level": "low",
            },
            "dga_analysis": {
                "domain": domain,
                "sld": domain.split(".")[0],
                "entropy": 2.5,
                "consonant_ratio": 0.4,
                "ngram_score": 0.1,
                "confidence": confidence,
                "is_dga": is_dga,
                "dga_family_guess": None,
                "dictionary_match": {
                    "coverage": 1.0,
                    "word_count": 1,
                    "words_found": ["kurs"],
                },
            },
        },
    }


def test_domain_intelligence_card_shows_weak_signal_for_kurs():
    rendered = _render(_domain_result())

    assert "Domain intelligence" in rendered
    assert "12360" in rendered or "12,360" in rendered
    assert "Weak signal" in rendered
    assert "Not flagged" not in rendered


def test_domain_intelligence_card_shows_not_flagged_for_non_dga():
    rendered = _render(_domain_result(domain="edgesuite.net", is_dga=False))

    assert "Domain intelligence" in rendered
    assert "Not flagged" in rendered


def test_domain_intelligence_card_is_absent_for_old_result():
    assert "Domain intelligence" not in _render({"ioc": "kurs.if.ua"})


def test_recommendation_columns_and_old_single_list_behavior():
    both = {
        "ioc": "kurs.if.ua",
        "recommendations": ["AI item"],
        "recommendations_rule_based": ["Rule item"],
        "recommendations_source": "llm",
        "llm_analysis": {
            "verdict": "CLEAN",
            "analysis": "Analysis",
            "recommendations": ["AI item"],
        },
    }
    rendered_both = _render(both)
    assert re.search(r">AI analysis<", rendered_both)
    # The Phase 2 recommendations redesign labels this column "Rule-based"
    # and marks it as always on.
    assert re.search(r">Rule-based<", rendered_both)
    assert ">ALWAYS ON</span>" in rendered_both

    old_job = {
        "ioc": "kurs.if.ua",
        "recommendations": ["Legacy item"],
        "llm_analysis": {
            "verdict": "CLEAN",
            "analysis": "Analysis",
            "recommendations": ["AI-only item"],
        },
    }
    rendered_old = _render(old_job)
    assert ">AI analysis<" not in rendered_old
    assert ">Rule-based playbook<" not in rendered_old
    assert "Legacy item" in rendered_old


def test_recommendations_are_escaped():
    malicious = "<script>alert(1)</script>"
    rendered = _render({"recommendations": [malicious]})

    assert malicious not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
