from __future__ import annotations

import importlib.util
import re
import sqlite3
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web import auth as auth_core
from src.web.app import _register_page_routes
from src.web.routes import access_requests


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "src" / "db" / "migrations"


def _load_migration(filename: str):
    spec = importlib.util.spec_from_file_location(filename[:-3], MIGRATIONS / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _auth_db(path: Path) -> None:
    for filename in (
        "001_create_users.py",
        "002_add_username_and_admin_role.py",
        "004_add_team_lead_role.py",
        "010_add_access_requests.py",
    ):
        _load_migration(filename).migrate(str(path))


def _page_app(role: str) -> FastAPI:
    app = FastAPI()
    _register_page_routes(app)
    app.dependency_overrides[auth_core.get_current_user] = lambda: {
        "id": 1,
        "email": "reviewer@example.test",
        "username": "reviewer",
        "role": role,
        "is_active": 1,
    }
    return app


def test_admin_pending_counts_actions_and_legacy_ids(monkeypatch, tmp_path):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    for index in range(3):
        access_requests.create_access_request(
            name=f"Requester {index}",
            email=f"requester{index}@example.test",
            requested_role="Team Lead",
            reason="Need access.",
        )

    with TestClient(_page_app("admin")) as client:
        response = client.get("/management")

    assert response.status_code == 200
    assert 'id="pending-request-count">3</strong>' in response.text
    assert 'class="mgmt-stat mgmt-stat-pending"' in response.text
    assert 'id="request-count">3</span>' in response.text
    assert response.text.count("AccessRequests.decide(") == 6
    assert response.text.count('class="mgmt-row" data-request-id=') == 3
    assert 'id="empty-access-requests" hidden' in response.text
    for legacy_id in (
        "request-count",
        "access-request-table",
        "empty-access-requests",
    ):
        assert f'id="{legacy_id}"' in response.text
    assert "Preview with example" not in response.text
    assert "EXAMPLE" not in response.text


def test_admin_empty_queue_has_clear_state_and_no_rows(monkeypatch, tmp_path):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))

    with TestClient(_page_app("admin")) as client:
        response = client.get("/management")

    assert response.status_code == 200
    assert 'id="pending-request-count">0</strong>' in response.text
    assert 'class="mgmt-stat mgmt-stat-pending"' in response.text
    assert 'id="request-count">0</span>' in response.text
    assert 'id="empty-access-requests"' in response.text
    assert "Queue is clear" in response.text
    assert "No pending access requests." in response.text
    assert 'data-request-id="' not in response.text


def test_team_lead_sees_invite_form_without_admin_queue(monkeypatch, tmp_path):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))

    with TestClient(_page_app("Team Lead")) as client:
        response = client.get("/management")

    assert response.status_code == 200
    for element_id in (
        "team-member-invite-form",
        "team-member-email",
        "team-member-role",
    ):
        assert f'id="{element_id}"' in response.text
    assert 'id="access-request-table"' not in response.text
    assert "PENDING ACCESS REQUESTS" not in response.text
    assert "TEAM <em>MANAGEMENT</em>" in response.text
    assert "Invite team member" in response.text


def test_public_request_fields_are_escaped(monkeypatch, tmp_path):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    access_requests.create_access_request(
        name="<script>alert('name')</script>",
        email="<script>@example.test",
        requested_role="Team Lead",
        reason="<script>alert('reason')</script>",
    )

    with TestClient(_page_app("admin")) as client:
        response = client.get("/management")

    assert response.status_code == 200
    assert "&lt;script&gt;" in response.text
    assert "&lt;script&gt;alert(&#39;name&#39;)&lt;/script&gt;" in response.text
    assert "&lt;script&gt;alert(&#39;reason&#39;)&lt;/script&gt;" in response.text
    assert "&lt;script&gt;@example.test" in response.text
    assert "<script>alert('name')</script>" not in response.text
    assert "<script>alert('reason')</script>" not in response.text
    assert "<script>@example.test" not in response.text


def test_management_page_hides_base_subtitle_and_has_no_mockup_examples(monkeypatch, tmp_path):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))

    with TestClient(_page_app("admin")) as client:
        response = client.get("/management")

    assert response.status_code == 200
    assert "ADMIN REVIEW QUEUE · INVITATION FLOW" in response.text
    assert "Admin review queue" not in response.text
    assert "Preview with example" not in response.text
    assert "EXAMPLE" not in response.text


def test_management_css_uses_only_prefixed_classes_and_square_corners():
    css = (ROOT / "static" / "css" / "management.css").read_text(encoding="utf-8")
    selectors = re.findall(r"([^{}]+)\{", css)
    class_names = re.findall(r"(?<![\w-])\.([A-Za-z_][\w-]*)", " ".join(selectors))
    assert class_names
    unprefixed = [name for name in class_names if not name.startswith("mgmt-")]
    assert not unprefixed, unprefixed
    radii = re.findall(r"border-radius\s*:\s*([^;]+);", css)
    assert radii
    assert all(value.strip() == "0" for value in radii)

    script = (ROOT / "static" / "js" / "management.js").read_text(encoding="utf-8")
    assert 'pendingTileCard.classList.toggle("mgmt-stat-pending-active", count > 0)' in script
    assert 'pendingTileCard.classList.toggle("mgmt-stat-pending-empty", count === 0)' in script
    assert "const count = tbody ? tbody.rows.length : 0" in script

    tickets_css = (ROOT / "static" / "css" / "tickets.css").read_text(encoding="utf-8")
    tickets_radii = re.findall(r"border-radius\s*:\s*([^;]+);", tickets_css)
    assert tickets_radii
    assert all(value.strip() == "0" for value in tickets_radii)
