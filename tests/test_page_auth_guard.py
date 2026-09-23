from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.web import auth as auth_core
from src.web.auth import TEAM_LEAD, VALID_ROLES, get_current_user
from src.web.page_auth import PageAuthMiddleware
from src.web.security import SESSION_COOKIE_NAME, safe_relative_path
from src.web.routes import tickets as tickets_routes
from src.integrations.ticketing import create_incident_ticket, initialize_database


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "src" / "db" / "migrations"
PROTECTED_PAGES = (
    "/",
    "/dashboard",
    "/agent/chat",
    "/agent/investigations",
    "/agent/playbooks",
    "/analysis/ioc",
    "/analysis/file",
    "/analysis/email",
    "/history",
    "/cases",
    "/cases/x",
    "/tickets",
    "/soc-operations",
    "/report/x",
    "/management",
    "/mcp/servers",
    "/settings",
)


def _load_migration(filename: str):
    spec = importlib.util.spec_from_file_location(
        filename[:-3], MIGRATIONS / filename
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
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
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO users (email, username, password_hash, role, is_active) "
            "VALUES (?, ?, ?, ?, 1)",
            ("guard@example.test", "guard-user", "hash", "admin"),
        )
        connection.commit()


def _session_cookie(monkeypatch, tmp_path: Path) -> str:
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    monkeypatch.setenv("AUTH_JWT_SECRET", "page-auth-guard-test-secret")
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT id, email, username, role, is_active FROM users "
            "WHERE username = ?",
            ("guard-user",),
        ).fetchone()
    assert row is not None
    user = {
        "id": row[0],
        "email": row[1],
        "username": row[2],
        "role": row[3],
        "is_active": row[4],
    }
    return auth_core.create_access_token(user)


def _middleware_app() -> FastAPI:
    app = FastAPI(docs_url="/api/docs", redoc_url="/api/redoc")
    app.add_middleware(PageAuthMiddleware)

    @app.get("/")
    async def root(request: Request):
        user = getattr(request.state, "user", None)
        return {"user_id": user["id"] if user else None}

    @app.get("/{path:path}")
    async def page_probe(request: Request, path: str):
        user = getattr(request.state, "user", None)
        return {"path": path, "user_id": user["id"] if user else None}

    return app


@pytest.mark.parametrize("path", PROTECTED_PAGES)
def test_private_pages_redirect_unauthenticated_to_safe_next(path: str) -> None:
    with TestClient(_middleware_app()) as client:
        response = client.get(path, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == (
        f"/login?next={quote(safe_relative_path(path), safe='')}"
    )


@pytest.mark.parametrize(
    "path",
    (
        "/login",
        "/register",
        "/accept-invite",
        "/request-access",
        "/static/app.css",
    ),
)
def test_public_pages_and_static_paths_pass_without_session(path: str) -> None:
    with TestClient(_middleware_app()) as client:
        response = client.get(path, follow_redirects=False)

    assert response.status_code == 200


def test_api_paths_pass_through_and_do_not_add_cors_headers() -> None:
    with TestClient(_middleware_app()) as client:
        response = client.get(
            "/api/probe",
            headers={"Origin": "https://untrusted.example"},
        )

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize(
    "path",
    ("/api/docs", "/api/docs/oauth2-redirect", "/api/redoc", "/openapi.json"),
)
def test_documentation_paths_redirect_without_session(path: str) -> None:
    with TestClient(_middleware_app()) as client:
        response = client.get(path, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == (
        f"/login?next={quote(safe_relative_path(path), safe='')}"
    )


def test_valid_session_allows_docs_and_sets_request_user(monkeypatch, tmp_path) -> None:
    token = _session_cookie(monkeypatch, tmp_path)
    app = _middleware_app()
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, token)
        docs = client.get("/api/docs", follow_redirects=False)
        page = client.get("/dashboard", follow_redirects=False)
        client.cookies.delete(SESSION_COOKIE_NAME)
        bearer_page = client.get(
            "/agent/chat",
            headers={"Authorization": f"Bearer {token}"},
            follow_redirects=False,
        )

    assert docs.status_code == 200
    assert page.status_code == 200
    assert page.json()["user_id"] == 1
    assert bearer_page.status_code == 200
    assert bearer_page.json()["user_id"] == 1


def _tickets_app(user: dict | None = None) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(PageAuthMiddleware)
    app.include_router(tickets_routes.router, prefix="/api")
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app


def test_api_tickets_requires_authentication(monkeypatch) -> None:
    monkeypatch.setattr(tickets_routes, "get_all_tickets", lambda: [])
    with TestClient(_tickets_app()) as client:
        response = client.get("/api/tickets", follow_redirects=False)

    assert response.status_code == 401


def _seed_tickets(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "tickets.db"
    monkeypatch.setenv("TICKETING_DB_PATH", str(db_path))
    initialize_database()
    result = {"ioc": "198.51.100.1", "verdict": "MALICIOUS"}
    create_incident_ticket(result, "owner-12", owner_id=12)
    create_incident_ticket(result, "owner-34", owner_id=34)
    create_incident_ticket(result, "legacy-ownerless")


@pytest.mark.parametrize("role", sorted(VALID_ROLES))
def test_api_tickets_all_authenticated_roles_can_read(role, monkeypatch, tmp_path) -> None:
    _seed_tickets(monkeypatch, tmp_path)
    user = {
        "id": 12,
        "email": "reader@example.test",
        "username": "reader",
        "role": role,
        "is_active": 1,
    }

    with TestClient(_tickets_app(user)) as client:
        response = client.get("/api/tickets")

    assert response.status_code == 200


@pytest.mark.parametrize("role", [
    "SOC Analyst Tier 1-2",
    "Incident Responder",
    "Threat Hunter",
])
def test_api_tickets_scoped_roles_see_only_their_owned_tickets(role, monkeypatch, tmp_path) -> None:
    _seed_tickets(monkeypatch, tmp_path)
    user = {
        "id": 12,
        "email": "reader@example.test",
        "username": "reader",
        "role": role,
        "is_active": 1,
    }

    with TestClient(_tickets_app(user)) as client:
        response = client.get("/api/tickets")

    assert response.status_code == 200
    tickets = response.json()["tickets"]
    assert [ticket["analysis_id"] for ticket in tickets] == ["owner-12"]


@pytest.mark.parametrize("role", [TEAM_LEAD, "admin"])
def test_api_tickets_team_lead_and_admin_see_all_owners_and_legacy(role, monkeypatch, tmp_path) -> None:
    _seed_tickets(monkeypatch, tmp_path)
    user = {
        "id": 12,
        "email": "reader@example.test",
        "username": "reader",
        "role": role,
        "is_active": 1,
    }

    with TestClient(_tickets_app(user)) as client:
        response = client.get("/api/tickets")

    assert response.status_code == 200
    assert {ticket["analysis_id"] for ticket in response.json()["tickets"]} == {
        "owner-12", "owner-34", "legacy-ownerless",
    }


def test_safe_relative_path_blocks_external_next() -> None:
    assert safe_relative_path("https://attacker.example") == "/"
