from __future__ import annotations

import csv
import io

import pytest
from fastapi.testclient import TestClient

from src.web.routes import analysis as analysis_routes
from tests.test_history_scoping import (
    ADMIN,
    SOC,
    TEAM_LEAD,
    _history_response,
    _seed_jobs,
    _summary_app,
    _user,
)


class AuditRecorder:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    def add_cross_user_read_audit(self, **kwargs):
        entry = dict(kwargs)
        entry["action"] = "cross_user_read"
        self.entries.append(entry)
        return f"audit-{len(self.entries)}"


def _set_audit_recorder(app, recorder: AuditRecorder) -> None:
    app.state.agent_store = recorder


def _export_response(client: TestClient, **params):
    return client.get("/api/analysis/history/export", params=params)


def _csv_rows(response) -> list[list[str]]:
    text = response.content.decode("utf-8-sig")
    return list(csv.reader(io.StringIO(text, newline="")))


def test_export_role_scope_matches_list_for_admin_team_lead_and_analyst(
    tmp_path, monkeypatch
) -> None:
    admin_app = _summary_app(tmp_path / "admin", _user(ADMIN, 900))
    _seed_jobs(admin_app.state.analysis_manager)
    with TestClient(admin_app) as client:
        expected_admin = [item["id"] for item in _history_response(client)["items"]]
        response = _export_response(client)
    assert response.status_code == 200
    assert [row[0] for row in _csv_rows(response)[1:]] == expected_admin

    lead_app = _summary_app(tmp_path / "lead", _user(TEAM_LEAD, 900))
    _seed_jobs(lead_app.state.analysis_manager)
    monkeypatch.setattr(analysis_routes, "get_user_ids_by_role", lambda _role: [101, 202])
    with TestClient(lead_app) as client:
        expected_lead = [item["id"] for item in _history_response(client)["items"]]
        response = _export_response(client)
    assert response.status_code == 200
    assert [row[0] for row in _csv_rows(response)[1:]] == expected_lead

    analyst_app = _summary_app(tmp_path / "analyst", _user(SOC, 101))
    _seed_jobs(analyst_app.state.analysis_manager)
    with TestClient(analyst_app) as client:
        expected_analyst = [item["id"] for item in _history_response(client)["items"]]
        response = _export_response(client)
    assert response.status_code == 200
    assert [row[0] for row in _csv_rows(response)[1:]] == expected_analyst


@pytest.mark.parametrize(
    "params",
    [
        {"group": "in_progress"},
        {"type": "ioc"},
        {"q": "analyst-target"},
        {"range": "7d"},
        {"sort": "score", "order": "asc"},
        {"sort": "verdict", "order": "desc"},
        {"status": "failed", "sort": "date", "order": "asc"},
    ],
)
def test_export_ids_and_order_match_list_filters(tmp_path, params) -> None:
    app = _summary_app(tmp_path, _user(ADMIN, 900))
    _seed_jobs(app.state.analysis_manager)

    with TestClient(app) as client:
        expected = [item["id"] for item in _history_response(client, **params)["items"]]
        response = _export_response(client, **params)

    assert response.status_code == 200
    assert [row[0] for row in _csv_rows(response)[1:]] == expected


def test_export_returns_413_before_team_lead_audit_when_over_cap(tmp_path, monkeypatch) -> None:
    app = _summary_app(tmp_path, _user(TEAM_LEAD, 900))
    _seed_jobs(app.state.analysis_manager)
    recorder = AuditRecorder()
    _set_audit_recorder(app, recorder)
    monkeypatch.setattr(analysis_routes, "get_user_ids_by_role", lambda _role: [101, 202])
    monkeypatch.setattr(analysis_routes, "HISTORY_EXPORT_CAP", 1)

    with TestClient(app) as client:
        response = _export_response(client)

    assert response.status_code == 413
    assert recorder.entries == []


def test_export_headers_bom_crlf_and_columns(tmp_path) -> None:
    app = _summary_app(tmp_path, _user(ADMIN, 900))
    _seed_jobs(app.state.analysis_manager)

    with TestClient(app) as client:
        response = _export_response(client)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv; charset=utf-8")
    assert response.headers["content-disposition"] == (
        'attachment; filename="analysis-history.csv"'
    )
    assert response.content.startswith(b"\xef\xbb\xbf")
    assert b"\r\n" in response.content
    assert _csv_rows(response)[0] == [
        "id", "type", "target", "verdict", "verdict_group",
        "score", "status", "created_at", "completed_at",
    ]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("=1+1", "'=1+1"),
        ("+CMD()", "'+CMD()"),
        ("-2+3", "'-2+3"),
        ("@SUM(A:A)", "'@SUM(A:A)"),
        ("\t=CMD()", "'\t=CMD()"),
        ("\r=CMD()", "'\r=CMD()"),
        ("\tabc", "'\tabc"),
        ("   =1+1 ", "'   =1+1 "),
        ("normal text", "normal text"),
        (None, ""),
    ],
)
def test_csv_text_sanitizer_vectors(value, expected) -> None:
    assert analysis_routes.sanitize_csv_text(value) == expected


def test_csv_score_is_numeric_and_negative_values_are_preserved() -> None:
    job = {
        "id": "job-1",
        "analysis_type": "ioc",
        "params": {"value": "normal"},
        "status": "completed",
        "verdict": "CLEAN",
        "score": -1,
        "created_at": "2026-10-05T00:00:00+00:00",
        "completed_at": "2026-10-05T00:01:00+00:00",
        "result": {},
        "verdict_group": "clean",
    }
    assert analysis_routes._history_csv_row(job, ADMIN)[5] == -1


def test_unauthenticated_export_matches_list_status(tmp_path) -> None:
    app = _summary_app(tmp_path)
    with TestClient(app) as client:
        list_response = client.get("/api/analysis/history/")
        export_response = _export_response(client)

    assert export_response.status_code == list_response.status_code == 401


def test_team_lead_export_audits_only_cross_user_rows(tmp_path, monkeypatch) -> None:
    app = _summary_app(tmp_path, _user(TEAM_LEAD, 900))
    _seed_jobs(app.state.analysis_manager)
    recorder = AuditRecorder()
    _set_audit_recorder(app, recorder)
    monkeypatch.setattr(analysis_routes, "get_user_ids_by_role", lambda _role: [101, 202])

    with TestClient(app) as client:
        expected = _history_response(client)["items"]
        recorder.entries.clear()
        response = _export_response(client)

    assert response.status_code == 200
    expected_audits = len(expected)
    assert len(recorder.entries) == expected_audits
    assert all(entry["resource_type"] == "analysis" for entry in recorder.entries)


def test_admin_and_analyst_export_without_audits(tmp_path) -> None:
    for index, user in enumerate((_user(ADMIN, 900), _user(SOC, 101))):
        app = _summary_app(tmp_path / str(index), user)
        _seed_jobs(app.state.analysis_manager)
        recorder = AuditRecorder()
        _set_audit_recorder(app, recorder)
        with TestClient(app) as client:
            response = _export_response(client)
        assert response.status_code == 200
        assert recorder.entries == []
