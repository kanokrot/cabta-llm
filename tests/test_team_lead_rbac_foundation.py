"""Phase 1 Team Lead role and migration safety coverage."""

from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.auth import TEAM_LEAD, VALID_ROLES, get_current_user
from src.web.routes import admin as admin_routes
from src.web.routes import agent as agent_routes
from src.web.routes import chat as chat_routes
from src.web.routes import config_api


ROOT = Path(__file__).parents[1]
MIGRATIONS = ROOT / "src" / "db" / "migrations"


def _load_migration(filename: str):
    path = MIGRATIONS / filename
    spec = importlib.util.spec_from_file_location(filename.replace(".", "_"), path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _team_lead() -> dict:
    return {
        "id": 900,
        "email": "lead@example.test",
        "username": "team-lead",
        "role": TEAM_LEAD,
        "is_active": 1,
    }


def _app_with_user(router, prefix: str) -> FastAPI:
    app = FastAPI()
    app.dependency_overrides[get_current_user] = _team_lead
    app.include_router(router, prefix=prefix)
    return app


def test_team_lead_is_a_valid_role_but_not_admin() -> None:
    assert TEAM_LEAD in VALID_ROLES
    assert TEAM_LEAD != "admin"


def test_team_lead_is_blocked_from_admin_invite() -> None:
    app = _app_with_user(admin_routes.router, "/api/admin")

    with TestClient(app) as client:
        response = client.post(
            "/api/admin/users/invite",
            json={"email": "new-user@example.test", "role": "SOC Analyst Tier 1-2"},
        )

    assert response.status_code == 403


@pytest.mark.parametrize("method", ("get", "post"))
def test_team_lead_is_blocked_from_system_settings(method: str) -> None:
    app = _app_with_user(config_api.router, "/api/config")

    with TestClient(app) as client:
        if method == "post":
            response = client.post("/api/config/settings", json={})
        else:
            response = client.get("/api/config/settings")

    assert response.status_code == 403


def test_team_lead_is_blocked_from_flow_b_chat() -> None:
    app = _app_with_user(chat_routes.router, "/api/chat")

    with TestClient(app) as client:
        response = client.post(
            "/api/chat",
            json={"message": "investigate example.com"},
        )

    assert response.status_code == 403


def test_team_lead_is_blocked_from_flow_b_agent_routes() -> None:
    app = _app_with_user(agent_routes.router, "/api/agent")

    with TestClient(app) as client:
        response = client.get("/api/agent/sessions")

    assert response.status_code == 403


def _create_current_auth_db(path: Path) -> None:
    migration_001 = _load_migration("001_create_users.py")
    migration_002 = _load_migration("002_add_username_and_admin_role.py")

    with sqlite3.connect(str(path)) as connection:
        migration_001.upgrade(connection)
        migration_002.upgrade(connection)
        connection.execute(
            """
            INSERT INTO users
                (id, email, username, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                10,
                "soc@example.test",
                "soc-user",
                "hash-soc",
                "SOC Analyst Tier 1-2",
                1,
                "2026-01-01T00:00:00+00:00",
            ),
        )
        connection.execute(
            """
            INSERT INTO users
                (id, email, username, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                20,
                "ir@example.test",
                "ir-user",
                "hash-ir",
                "Incident Responder",
                1,
                "2026-01-02T00:00:00+00:00",
            ),
        )
        connection.execute(
            """
            INSERT INTO auth_sessions (jti, user_id, expires_at, created_at)
            VALUES (?, ?, ?, ?)
            """,
            ("session-1", 10, 2000000000, "2026-01-03T00:00:00+00:00"),
        )
        connection.execute(
            """
            INSERT INTO invite_tokens
                (token, email, role, invited_by, expires_at, used_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "invite-1",
                "pending@example.test",
                "Threat Hunter",
                20,
                2000000000,
                None,
                "2026-01-04T00:00:00+00:00",
            ),
        )


def _database_snapshot(connection: sqlite3.Connection) -> dict:
    return {
        "users": connection.execute(
            "SELECT id, email, username, password_hash, role, is_active, created_at "
            "FROM users ORDER BY id"
        ).fetchall(),
        "auth_sessions": connection.execute(
            "SELECT jti, user_id, expires_at, revoked_at, created_at "
            "FROM auth_sessions ORDER BY jti"
        ).fetchall(),
        "invite_tokens": connection.execute(
            "SELECT token, email, role, invited_by, expires_at, used_at, created_at "
            "FROM invite_tokens ORDER BY token"
        ).fetchall(),
        "schema": connection.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE type IN ('table', 'index') ORDER BY type, name"
        ).fetchall(),
    }


def test_team_lead_migration_preserves_data_and_is_idempotent(tmp_path) -> None:
    db_path = tmp_path / "auth.db"
    _create_current_auth_db(db_path)
    migration = _load_migration("004_add_team_lead_role.py")

    with sqlite3.connect(str(db_path)) as connection:
        before = _database_snapshot(connection)

    migration.migrate(str(db_path))

    with sqlite3.connect(str(db_path)) as connection:
        after_first = _database_snapshot(connection)
        assert after_first["users"] == before["users"]
        assert after_first["auth_sessions"] == before["auth_sessions"]
        assert after_first["invite_tokens"] == before["invite_tokens"]
        assert connection.execute("PRAGMA foreign_keys").fetchone() == (0,)

        connection.execute(
            """
            INSERT INTO users
                (email, username, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "lead-db@example.test",
                "lead-db",
                "hash-lead",
                "Team Lead",
                1,
                "2026-01-05T00:00:00+00:00",
            ),
        )
        connection.execute(
            """
            INSERT INTO invite_tokens
                (token, email, role, invited_by, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "invite-lead",
                "lead-db@example.test",
                "Team Lead",
                10,
                2000000000,
                "2026-01-05T00:00:00+00:00",
            ),
        )
        connection.commit()
        snapshot_with_new_role = _database_snapshot(connection)

    migration.migrate(str(db_path))

    with sqlite3.connect(str(db_path)) as connection:
        assert _database_snapshot(connection) == snapshot_with_new_role


def test_team_lead_migration_rolls_back_on_failure(tmp_path) -> None:
    db_path = tmp_path / "auth.db"
    _create_current_auth_db(db_path)
    migration = _load_migration("004_add_team_lead_role.py")

    with sqlite3.connect(str(db_path)) as connection:
        before = _database_snapshot(connection)

    real_connection = sqlite3.connect(str(db_path))

    class FailingConnection:
        def execute(self, sql, parameters=()):
            if sql.strip().upper().startswith("ALTER TABLE USERS_NEW"):
                raise sqlite3.OperationalError("forced migration failure")
            return real_connection.execute(sql, parameters)

        def commit(self):
            return real_connection.commit()

        def rollback(self):
            return real_connection.rollback()

    with pytest.raises(sqlite3.OperationalError, match="forced migration failure"):
        migration.upgrade(FailingConnection())
    real_connection.close()

    with sqlite3.connect(str(db_path)) as connection:
        assert _database_snapshot(connection) == before
