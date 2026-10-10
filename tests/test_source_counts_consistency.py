import asyncio
from pathlib import Path
import re
from types import SimpleNamespace

from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from src.web.routes.analysis import get_analysis
from src.web.routes.reports import get_report_html
from src.web.source_classification import count_source_classes


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _source_fixture():
    sources = {
        "threatfox": {"status": "flagged", "score": 90},
        "spamhaus": {"status": "flagged", "score": 80},
        "usom": {"status": "flagged", "score": 85},
        "context-extra": {"status": "flagged", "score": 65},
    }
    sources.update(
        {f"clean-{index}": {"status": "clean", "score": 0} for index in range(8)}
    )
    sources.update(
        {
            f"error-{index}": {"status": "error", "error": "HTTP 503"}
            for index in range(5)
        }
    )
    sources.update(
        {
            f"na-{index}": {"status": "not_applicable", "not_applicable": True}
            for index in range(11)
        }
    )
    return sources


def _result():
    return {
        "ioc": "217.60.77.63",
        "ioc_type": "ipv4",
        "verdict": "MALICIOUS",
        "threat_score": 99,
        "sources": _source_fixture(),
        "score_breakdown": {
            "threatfox": {
                "flagged": True,
                "score_used": 90,
                "weight": 0.33961,
                "scored": True,
            },
            "spamhaus": {
                "flagged": True,
                "score_used": 80,
                "weight": 0.69593,
                "scored": True,
            },
        },
    }


def _job(result):
    return {
        "id": "c15312ebdddd9",
        "analysis_type": "ioc",
        "status": "completed",
        "progress": 100,
        "verdict": result["verdict"],
        "score": result["threat_score"],
        "params": {"value": result["ioc"], "ioc_type": result["ioc_type"]},
        "user_id": 1,
        "result": result,
    }


def _request(path, app):
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "raw_path": path.encode("utf-8"),
            "query_string": b"",
            "headers": [],
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("testclient", 50000),
            "app": app,
        }
    )


def test_shared_counts_match_ioc_fixture():
    result = _result()
    counts = count_source_classes(result["sources"], result["score_breakdown"])

    assert counts["flagged"] == 4
    assert counts["scored_flagged"] == 2
    assert counts["context_flagged"] == 2
    assert counts["responded"] == 12
    assert counts["errors"] == 5
    assert counts["na"] == 11
    assert counts["attempted"] == 17


def test_report_route_renders_shared_source_counts():
    result = _result()
    job = _job(result)
    app = SimpleNamespace(
        state=SimpleNamespace(
            analysis_manager=SimpleNamespace(get_job=lambda analysis_id: job),
            templates=Jinja2Templates(directory=str(PROJECT_ROOT / "templates")),
        )
    )
    request = _request("/api/reports/c15312ebdddd9/html", app)
    current_user = {"role": "admin", "id": 1}

    response = asyncio.run(get_report_html(request, job["id"], current_user))
    html = response.body.decode("utf-8")

    assert "4 FLAGGED" in html
    assert "2 scored · 2 context" in html
    assert "12 RESPONDED" in html
    assert "5 ERRORS" in html
    assert "11 N/A" in html


def test_ioc_handler_attaches_helper_counts_to_result(monkeypatch):
    from src.web.routes import analysis as analysis_routes

    job = _job(_result())
    monkeypatch.setattr(
        analysis_routes,
        "_get_readable_job",
        lambda request, analysis_id, current_user: job,
    )
    request = _request("/api/analysis/c15312ebdddd9", SimpleNamespace())
    current_user = {"role": "admin", "id": 1}

    payload = asyncio.run(get_analysis(request, job["id"], current_user))
    expected = count_source_classes(
        _result()["sources"], _result()["score_breakdown"]
    )

    assert payload["result"]["source_counts"] == expected


def test_ioc_handler_source_counts_for_soc_analyst(monkeypatch):
    from src.web.routes import analysis as analysis_routes

    job = _job(_result())
    monkeypatch.setattr(
        analysis_routes,
        "_get_readable_job",
        lambda request, analysis_id, current_user: job,
    )
    request = _request("/api/analysis/c15312ebdddd9", SimpleNamespace())
    current_user = {"role": "SOC Analyst Tier 1-2", "id": 2}

    payload = asyncio.run(get_analysis(request, job["id"], current_user))
    result = payload.get("result")
    print("SOC Analyst Tier 1-2 payload['result']:", result)

    assert isinstance(result, dict)
    assert result.get("source_counts") == count_source_classes(
        result.get("sources"), result.get("score_breakdown")
    )


def test_ioc_handler_does_not_mutate_job_result_across_calls(monkeypatch):
    from src.web.routes import analysis as analysis_routes

    job = _job(_result())
    monkeypatch.setattr(
        analysis_routes,
        "_get_readable_job",
        lambda request, analysis_id, current_user: job,
    )
    request = _request("/api/analysis/c15312ebdddd9", SimpleNamespace())
    current_user = {"role": "admin", "id": 1}

    assert "source_counts" not in job["result"]
    first_payload = asyncio.run(get_analysis(request, job["id"], current_user))
    assert "source_counts" in first_payload["result"]
    assert "source_counts" not in job["result"]
    second_payload = asyncio.run(get_analysis(request, job["id"], current_user))
    assert "source_counts" in second_payload["result"]
    assert "source_counts" not in job["result"]


def test_templates_do_not_recount_flagged_or_responded_sources():
    report_template = (PROJECT_ROOT / "templates/report_view.html").read_text(
        encoding="utf-8"
    )
    ioc_template = (PROJECT_ROOT / "templates/analysis_ioc.html").read_text(
        encoding="utf-8"
    )

    assert "namespace(flagged=0, responded=0" not in report_template
    assert not re.search(
        r"source_summary\.(?:flagged|responded|errors|na)\s*=", report_template
    )
    assert "sourcesFlagged++" not in ioc_template
    assert "var sourcesChecked" not in ioc_template
    assert "item.flagged === true) sourcesFlagged" not in ioc_template
