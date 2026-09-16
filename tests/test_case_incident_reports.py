"""Tests for editable, one-to-one case incident reports."""

import sqlite3
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.case_store import CaseStore, _severity_to_4tier
from src.web.auth import get_current_user
from src.web.routes.cases import router as cases_router


@pytest.fixture
def store(tmp_path):
    return CaseStore(db_path=str(tmp_path / "cases.db"))


@pytest.fixture
def client_and_store(store):
    app = FastAPI()
    app.state.case_store = store
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 101,
        "email": "analyst@example.test",
        "username": "analyst",
        "role": "SOC Analyst Tier 1-2",
        "is_active": 1,
    }
    app.include_router(cases_router, prefix="/cases")
    return TestClient(app), store


def test_create_incident_report_round_trips_list_fields(store):
    case_id = store.create_case("Phishing incident")
    report = store.create_incident_report(
        case_id,
        threat_type="Phishing",
        findings=["Malicious link", "Credential theft"],
        analysis=["Header analysis"],
        impact=["Mailbox compromised"],
        remediation=["Reset password"],
        reference=["INC-2026-001"],
    )

    assert report["case_id"] == case_id
    assert report["threat_type"] == "Phishing"
    assert report["findings"] == ["Malicious link", "Credential theft"]
    assert report["analysis"] == ["Header analysis"]
    assert report["impact"] == ["Mailbox compromised"]
    assert report["remediation"] == ["Reset password"]
    assert report["reference"] == ["INC-2026-001"]


def test_create_incident_report_rejects_duplicate(store):
    case_id = store.create_case("Duplicate report")
    store.create_incident_report(case_id, threat_type="Original")

    with pytest.raises(sqlite3.IntegrityError):
        store.create_incident_report(case_id, threat_type="Overwrite")

    assert store.get_incident_report(case_id)["threat_type"] == "Original"


def test_get_incident_report_returns_none_when_missing(store):
    case_id = store.create_case("No report")
    assert store.get_incident_report(case_id) is None


def test_update_incident_report_is_partial_and_bumps_timestamp(store):
    case_id = store.create_case("Partial update")
    original = store.create_incident_report(
        case_id,
        threat_type="Malware",
        target_ip="10.0.0.8",
        findings=["Initial finding"],
    )
    time.sleep(0.002)

    assert store.update_incident_report(
        case_id, threat_description="Updated description", findings=["Updated finding"]
    ) is True

    updated = store.get_incident_report(case_id)
    assert updated["threat_type"] == "Malware"
    assert updated["target_ip"] == "10.0.0.8"
    assert updated["threat_description"] == "Updated description"
    assert updated["findings"] == ["Updated finding"]
    assert updated["updated_at"] > original["updated_at"]


def test_update_incident_report_returns_false_when_missing(store):
    assert store.update_incident_report("missing", threat_type="Phishing") is False


@pytest.mark.parametrize(
    ("case_severity", "expected"),
    [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ],
)
def test_severity_to_4tier(case_severity, expected):
    assert _severity_to_4tier(case_severity) == expected


def test_post_incident_report_prefills_case_severity(client_and_store):
    client, store = client_and_store
    case_id = store.create_case("High severity", severity="high")

    response = client.post(f"/cases/{case_id}/incident-report", json={})

    assert response.status_code == 200
    assert response.json()["severity_4tier"] == "High"


def test_post_duplicate_incident_report_returns_409_without_overwrite(client_and_store):
    client, store = client_and_store
    case_id = store.create_case("Conflict")
    first = client.post(
        f"/cases/{case_id}/incident-report", json={"threat_type": "Original"}
    )

    second = client.post(
        f"/cases/{case_id}/incident-report", json={"threat_type": "Overwrite"}
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert store.get_incident_report(case_id)["threat_type"] == "Original"


def test_patch_incident_report_updates_fields(client_and_store):
    client, store = client_and_store
    case_id = store.create_case("Editable")
    store.create_incident_report(case_id, threat_type="Before", target_ip="10.0.0.1")

    response = client.patch(
        f"/cases/{case_id}/incident-report",
        json={"threat_type": "After", "findings": ["Confirmed"]},
    )

    assert response.status_code == 200
    assert response.json()["threat_type"] == "After"
    assert response.json()["target_ip"] == "10.0.0.1"
    assert response.json()["findings"] == ["Confirmed"]


def test_get_incident_report_returns_404_when_missing(client_and_store):
    client, store = client_and_store
    case_id = store.create_case("No incident report")

    response = client.get(f"/cases/{case_id}/incident-report")

    assert response.status_code == 404


def test_get_incident_report_pdf_returns_404_when_no_report(client_and_store):
    client, store = client_and_store
    case_id = store.create_case("No report yet")

    response = client.get(f"/cases/{case_id}/incident-report/pdf")

    assert response.status_code == 404


def test_get_incident_report_pdf_returns_pdf_bytes(client_and_store):
    client, store = client_and_store
    case_id = store.create_case("Has report")
    store.create_incident_report(
        case_id, threat_type="Phishing", findings=["test"]
    )

    response = client.get(f"/cases/{case_id}/incident-report/pdf")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content[:4] == b"%PDF"
    assert "inline" in response.headers.get("content-disposition", "")


def test_get_incident_report_pdf_download_query_param_forces_attachment(
    client_and_store,
):
    client, store = client_and_store
    case_id = store.create_case("Download variant")
    store.create_incident_report(case_id, threat_type="Malware")

    response = client.get(f"/cases/{case_id}/incident-report/pdf?download=1")

    assert response.status_code == 200
    assert "attachment" in response.headers.get("content-disposition", "")
    assert f"incident-report-{case_id}.pdf" in response.headers.get(
        "content-disposition", ""
    )


def test_get_incident_report_pdf_returns_500_and_cleans_up_on_generation_failure(
    client_and_store, monkeypatch
):
    import src.web.routes.cases as cases_route

    case_id = client_and_store[1].create_case("Will fail")
    client_and_store[1].create_incident_report(case_id, threat_type="X")

    monkeypatch.setattr(
        cases_route, "generate_incident_report_pdf", lambda data, path: None
    )

    response = client_and_store[0].get(f"/cases/{case_id}/incident-report/pdf")

    assert response.status_code == 500
