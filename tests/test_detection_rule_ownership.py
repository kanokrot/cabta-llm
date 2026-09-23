"""Security and persistence coverage for detection-rule ownership."""

from __future__ import annotations

import importlib.util
import io
import sqlite3
import zipfile
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient

from src.web.analysis_manager import AnalysisManager
from src.web.routes import reports


ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = ROOT / "src" / "db" / "migrations" / "012_add_detection_rule_ownership.py"
THREAT_HUNTER_ID = 42
OTHER_THREAT_HUNTER_ID = 99


def _load_migration():
    spec = importlib.util.spec_from_file_location(
        "migration_012_detection_rule_ownership", MIGRATION_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _user(user_id=1, role="admin"):
    return {
        "id": user_id,
        "email": f"{role.lower().replace(' ', '.')}@example.test",
        "username": role.lower().replace(" ", "_"),
        "role": role,
        "is_active": 1,
    }


@pytest.fixture
def ownership_client(tmp_path):
    reports._rule_export_states.clear()
    app = FastAPI()
    from src.web.auth import get_current_user

    current_user = _user()
    app.dependency_overrides[get_current_user] = lambda: current_user
    manager = AnalysisManager(db_path=str(tmp_path / "analysis_jobs.db"))
    job_id = manager.create_job("ioc", {"value": "ownership-test"})
    manager.complete_job(
        job_id,
        {
            "detection_rules": {
                "kql": "DeviceProcessEvents | take 10",
                "sigma": "title: Ownership test\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: cmd.exe\n  condition: selection\n",
                "yara": 'rule OwnershipTest { condition: true }',
            }
        },
    )
    _load_migration().migrate(manager._db_path)
    app.state.analysis_manager = manager
    app.state.templates = Jinja2Templates(directory=str(ROOT / "templates"))
    app.include_router(reports.router, prefix="/api/reports")
    with TestClient(app) as client:
        yield client, manager, job_id, current_user
    reports._rule_export_states.clear()


def _approve(client, job_id, rule_type):
    response = client.post(
        f"/api/reports/{job_id}/rules/{rule_type}/approve",
        json={"approved_by": "reviewer"},
    )
    assert response.status_code == 200


def _ownership_row(manager, job_id, rule_type):
    with sqlite3.connect(manager._db_path) as connection:
        return connection.execute(
            "SELECT analysis_id, rule_type, last_edited_by, last_edited_at "
            "FROM detection_rule_ownership WHERE analysis_id = ? AND rule_type = ?",
            (job_id, rule_type),
        ).fetchone()


def test_migration_creates_table_and_is_idempotent(tmp_path):
    db_path = tmp_path / "analysis_jobs.db"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "CREATE TABLE analysis_jobs (id TEXT PRIMARY KEY)"
        )

    migration = _load_migration()
    migration.migrate(db_path)
    migration.migrate(db_path)

    with sqlite3.connect(db_path) as connection:
        columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(detection_rule_ownership)"
            )
        ]
        assert columns == [
            "analysis_id",
            "rule_type",
            "last_edited_by",
            "last_edited_at",
        ]
        assert connection.execute(
            "PRAGMA index_list(detection_rule_ownership)"
        ).fetchall()


def test_update_detection_rule_upserts_latest_editor(ownership_client):
    _, manager, job_id, _ = ownership_client

    assert manager.update_detection_rule(
        job_id, "kql", "DeviceProcessEvents | take 5", editor_user_id=THREAT_HUNTER_ID
    ) is True
    first = _ownership_row(manager, job_id, "kql")
    assert first[:3] == (job_id, "kql", THREAT_HUNTER_ID)
    assert first[3]

    assert manager.update_detection_rule(
        job_id, "kql", "DeviceProcessEvents | take 1", editor_user_id=OTHER_THREAT_HUNTER_ID
    ) is True
    second = _ownership_row(manager, job_id, "kql")
    assert second[:3] == (job_id, "kql", OTHER_THREAT_HUNTER_ID)
    assert second[3]
    with sqlite3.connect(manager._db_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM detection_rule_ownership "
            "WHERE analysis_id = ? AND rule_type = ?",
            (job_id, "kql"),
        ).fetchone()[0] == 1


def test_update_detection_rule_rolls_back_content_if_ownership_write_fails(
    ownership_client,
):
    _, manager, job_id, _ = ownership_client
    original = manager.get_job(job_id)["result"]["detection_rules"]["kql"]

    with pytest.raises(ValueError):
        manager.update_detection_rule(
            job_id,
            "kql",
            "DeviceProcessEvents | take 1",
            editor_user_id="not-an-integer",
        )

    assert manager.get_job(job_id)["result"]["detection_rules"]["kql"] == original
    assert _ownership_row(manager, job_id, "kql") is None


def test_threat_hunter_can_download_rule_they_own(ownership_client):
    client, _, job_id, current_user = ownership_client
    current_user.update(_user(THREAT_HUNTER_ID, "Threat Hunter"))
    edited = client.put(
        f"/api/reports/{job_id}/rules/kql",
        json={"content": "DeviceProcessEvents | take 5"},
    )
    assert edited.status_code == 200
    current_user.update(_user(1, "admin"))
    _approve(client, job_id, "kql")
    current_user.update(_user(THREAT_HUNTER_ID, "Threat Hunter"))

    response = client.get(f"/api/reports/{job_id}/rules/kql/download")
    assert response.status_code == 200


def test_threat_hunter_cannot_download_rule_owned_by_someone_else(ownership_client):
    client, _, job_id, current_user = ownership_client
    current_user.update(_user(OTHER_THREAT_HUNTER_ID, "Threat Hunter"))
    edited = client.put(
        f"/api/reports/{job_id}/rules/kql",
        json={"content": "DeviceProcessEvents | take 5"},
    )
    assert edited.status_code == 200
    current_user.update(_user(1, "admin"))
    _approve(client, job_id, "kql")
    current_user.update(_user(THREAT_HUNTER_ID, "Threat Hunter"))

    response = client.get(f"/api/reports/{job_id}/rules/kql/download")
    assert response.status_code == 403


def test_threat_hunter_can_download_unowned_rule(ownership_client):
    client, _, job_id, current_user = ownership_client
    _approve(client, job_id, "kql")
    current_user.update(_user(THREAT_HUNTER_ID, "Threat Hunter"))

    response = client.get(f"/api/reports/{job_id}/rules/kql/download")
    assert response.status_code == 200


def test_threat_hunter_zip_skips_rules_owned_by_someone_else(ownership_client):
    client, _, job_id, current_user = ownership_client
    current_user.update(_user(THREAT_HUNTER_ID, "Threat Hunter"))
    assert client.put(
        f"/api/reports/{job_id}/rules/kql",
        json={"content": "DeviceProcessEvents | take 5"},
    ).status_code == 200
    current_user.update(_user(OTHER_THREAT_HUNTER_ID, "Threat Hunter"))
    assert client.put(
        f"/api/reports/{job_id}/rules/sigma",
        json={"content": "title: Other owner\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: powershell.exe\n  condition: selection\n"},
    ).status_code == 200
    current_user.update(_user(1, "admin"))
    for rule_type in ("kql", "sigma", "yara"):
        _approve(client, job_id, rule_type)

    current_user.update(_user(THREAT_HUNTER_ID, "Threat Hunter"))
    response = client.get(
        f"/api/reports/{job_id}/rules/export/zip",
        params={"rule_types": "kql,sigma,yara"},
    )
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert archive.namelist() == ["kql.kql", "yara.yar"]


@pytest.mark.parametrize(
    "role,user_id",
    [
        ("SOC Analyst Tier 1-2", 10),
        ("Incident Responder", 11),
        ("Team Lead", 12),
        ("admin", 1),
    ],
)
def test_non_threat_hunter_roles_download_every_rule(ownership_client, role, user_id):
    client, _, job_id, current_user = ownership_client
    current_user.update(_user(THREAT_HUNTER_ID, "Threat Hunter"))
    assert client.put(
        f"/api/reports/{job_id}/rules/kql",
        json={"content": "DeviceProcessEvents | take 5"},
    ).status_code == 200
    current_user.update(_user(1, "admin"))
    _approve(client, job_id, "kql")
    _approve(client, job_id, "sigma")
    current_user.update(_user(user_id, role))

    for rule_type in ("kql", "sigma"):
        assert client.get(
            f"/api/reports/{job_id}/rules/{rule_type}/download"
        ).status_code == 200

    zip_response = client.get(
        f"/api/reports/{job_id}/rules/export/zip",
        params={"rule_types": "kql,sigma"},
    )
    assert zip_response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(zip_response.content)) as archive:
        assert archive.namelist() == ["kql.kql", "sigma.yml"]


@pytest.mark.parametrize(
    "role,user_id",
    [
        ("SOC Analyst Tier 1-2", 10),
        ("Incident Responder", 11),
        ("Threat Hunter", THREAT_HUNTER_ID),
        ("Team Lead", 12),
        ("admin", 1),
    ],
)
def test_report_view_keeps_rule_content_shared(ownership_client, role, user_id):
    client, _, job_id, current_user = ownership_client
    current_user.update(_user(user_id, role))

    response = client.get(f"/api/reports/{job_id}/html")
    assert response.status_code == 200
    assert "DeviceProcessEvents | take 10" in response.text
