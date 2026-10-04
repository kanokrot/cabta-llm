import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.analysis_manager import AnalysisManager
from src.web.app import _register_page_routes
from src.web.page_auth import PageAuthMiddleware
from src.web.security import SESSION_COOKIE_NAME
from src.web.visibility import INCIDENT_RESPONDER, SOC, serialize_report_job
from tests.test_page_auth_guard import _session_cookie


def _job(user_id=42):
    return {
        "id": "report-job",
        "analysis_type": "ioc",
        "status": "completed",
        "progress": 100,
        "verdict": "CLEAN",
        "score": 0,
        "user_id": user_id,
        "params": {"value": "kurs.if.ua", "ioc_type": "domain"},
        "result": {
            "sources": {
                "circl": {
                    "source": "CIRCL",
                    "status": "⚠",
                    "error": "HTTP 401",
                    "found": False,
                },
                "nested": {"status": "✓", "payload": {"secret": "drop"}},
                "lists": {"status": "✓", "malware_families": list(range(50))},
            },
            "llm_analysis": {
                "verdict": "CLEAN",
                "analysis": "The source status is degraded.",
                "recommendations": ["Review", {"drop": True}, 3],
                "hallucination_warning": "Check source names.",
                "rag_relevance_warning": "drop",
            },
        },
    }


def test_detailed_sources_keep_allowed_details_only():
    detailed = serialize_report_job(_job(), role="admin")["result"]["sources"]
    reduced = serialize_report_job(_job(), role=SOC, viewer_user_id=99)["result"]["sources"]

    assert detailed["circl"]["error"] == "HTTP 401"
    assert detailed["circl"]["found"] is False
    assert "error" not in reduced["circl"]
    assert "found" not in reduced["circl"]
    assert "payload" not in detailed["nested"]
    assert len(detailed["lists"]["malware_families"]) == 20


def test_source_detail_sanitization_and_bounds():
    job = _job()
    sources = job["result"]["sources"]
    sources["unsafe"] = {
        "status": "⚠",
        "error": "failed https://x.test/a?apikey=abc123",
        "message": "m" * 400,
        "api_key": "never",
        "x_token": "never",
        "nested": {"drop": True},
        "sources_found": list(range(50)),
    }

    safe = serialize_report_job(job, role="admin")["result"]["sources"]["unsafe"]

    assert "http" not in safe["error"].lower()
    assert "abc123" not in safe["error"]
    assert "api_key" not in safe
    assert "x_token" not in safe
    assert len(safe["message"]) == 200
    assert "nested" not in safe
    assert len(safe["sources_found"]) == 20


@pytest.mark.parametrize("role", ["admin", INCIDENT_RESPONDER])
def test_detailed_roles_receive_source_details(role):
    result = serialize_report_job(_job(), role=role, viewer_user_id=99)["result"]
    assert "error" in result["sources"]["circl"]


def test_soc_owner_receives_source_details_but_non_owner_does_not():
    owner = serialize_report_job(_job(42), role=SOC, viewer_user_id=42)["result"]
    non_owner = serialize_report_job(_job(42), role=SOC, viewer_user_id=99)["result"]

    assert "error" in owner["sources"]["circl"]
    assert "error" not in non_owner["sources"]["circl"]


def test_llm_analysis_is_bounded_and_allowlisted_for_all_roles():
    for role, viewer_user_id in (("admin", 99), (INCIDENT_RESPONDER, 99), (SOC, 42), (SOC, 99)):
        llm_analysis = serialize_report_job(
            _job(42), role=role, viewer_user_id=viewer_user_id
        )["result"]["llm_analysis"]
        assert set(llm_analysis) <= {
            "verdict", "analysis", "recommendations", "hallucination_warning"
        }
        assert "rag_relevance_warning" not in llm_analysis


def test_llm_analysis_is_absent_without_verdict_or_analysis():
    job = _job()
    job["result"]["llm_analysis"] = {"recommendations": ["only"]}
    result = serialize_report_job(job, role="admin")["result"]
    assert "llm_analysis" not in result


def _page_app(tmp_path):
    app = FastAPI()
    app.add_middleware(PageAuthMiddleware)
    app.state.analysis_manager = AnalysisManager(db_path=str(tmp_path / "analysis.db"))
    _register_page_routes(app)
    return app


def test_report_route_redirects_logged_in_user_and_preserves_query(tmp_path, monkeypatch):
    app = _page_app(tmp_path)
    job_id = app.state.analysis_manager.create_job("ioc", {"value": "kurs.if.ua"})
    token = _session_cookie(monkeypatch, tmp_path)
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, token)
        response = client.get(f"/report/{job_id}?print=1", follow_redirects=False)

    assert response.status_code == 307
    assert response.headers["location"] == f"/api/reports/{job_id}/html?print=1"


def test_report_route_redirects_unauthenticated_to_login(tmp_path):
    with TestClient(_page_app(tmp_path)) as client:
        response = client.get("/report/nope", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"].startswith("/login?next=")


def test_report_route_keeps_missing_job_404_for_authenticated_user(tmp_path, monkeypatch):
    app = _page_app(tmp_path)
    token = _session_cookie(monkeypatch, tmp_path)
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, token)
        response = client.get("/report/missing", follow_redirects=False)

    assert response.status_code == 404
    assert "Report not found" in response.text
