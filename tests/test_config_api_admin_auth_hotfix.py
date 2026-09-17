"""Negative coverage for admin-only configuration endpoints."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.auth import get_current_user
from src.web.routes.config_api import router


ENDPOINTS = (
    ("get", "/api/config/health"),
    ("get", "/api/config/info"),
    ("get", "/api/config/tools"),
    ("get", "/api/config/settings"),
    ("post", "/api/config/settings"),
    ("get", "/api/config/ollama-models"),
    ("get", "/api/config/ollama-health"),
    ("get", "/api/config/system-status"),
)

NON_ADMIN_ROLES = (
    "SOC Analyst Tier 1-2",
    "Incident Responder",
    "Threat Hunter",
    "Team Lead",
)


def _app(user: dict | None = None) -> FastAPI:
    app = FastAPI()
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    app.include_router(router, prefix="/api/config")
    return app


def _request(client: TestClient, method: str, path: str):
    if method == "post":
        return client.post(path, json={})
    return client.get(path)


@pytest.mark.parametrize("method,path", ENDPOINTS)
def test_every_config_endpoint_rejects_unauthenticated(method: str, path: str):
    with TestClient(_app()) as client:
        assert _request(client, method, path).status_code == 401


@pytest.mark.parametrize("role", NON_ADMIN_ROLES)
@pytest.mark.parametrize("method,path", ENDPOINTS)
def test_every_config_endpoint_is_admin_only(role: str, method: str, path: str):
    user = {"id": 1, "email": "user@example.test", "role": role, "is_active": 1}
    with TestClient(_app(user)) as client:
        assert _request(client, method, path).status_code == 403
