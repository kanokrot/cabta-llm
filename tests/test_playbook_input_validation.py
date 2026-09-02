"""Fail-fast validation coverage for required playbook inputs."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.agent.playbook_engine import (
    PlaybookEngine,
    PlaybookStep,
    PlaybookValidationError,
)
from src.web.routes.chat import router as chat_router
from src.web.routes.playbooks import router as playbooks_router


def _engine_with_playbook(input_params=None):
    engine = object.__new__(PlaybookEngine)
    engine.store = MagicMock()
    playbook = {
        "id": "validation-test",
        "name": "Validation test",
        "_parsed_steps": [PlaybookStep(name="first_step", tool="test_tool")],
    }
    if input_params is not None:
        playbook["input_params"] = input_params
    engine._cache = {"validation-test": playbook}
    return engine


def _required(name):
    return {"name": name, "required": True}


def test_resolve_playbook_reports_all_missing_required_params():
    engine = _engine_with_playbook([
        _required("host_identifier"),
        _required("remote_username"),
        _required("remote_key_path"),
    ])

    with pytest.raises(PlaybookValidationError) as exc_info:
        engine._resolve_playbook(
            "validation-test",
            {"host_identifier": "server.example.test"},
        )

    assert str(exc_info.value) == (
        "Playbook 'validation-test' is missing required params: "
        "remote_username, remote_key_path"
    )


def test_resolve_playbook_treats_whitespace_only_string_as_missing():
    engine = _engine_with_playbook([
        _required("file_path"),
        _required("analysis_context"),
    ])

    with pytest.raises(
        PlaybookValidationError,
        match=r"missing required params: file_path$",
    ):
        engine._resolve_playbook(
            "validation-test",
            {"file_path": "   ", "analysis_context": {"verdict": "CLEAN"}},
        )


def test_resolve_playbook_accepts_populated_non_string_required_param():
    engine = _engine_with_playbook([_required("analysis_context")])
    analysis_context = {"file_type": "PE", "verdict": "MALICIOUS"}

    _pb, _playbook_id, _steps, resolved = engine._resolve_playbook(
        "validation-test",
        {"analysis_context": analysis_context},
    )

    assert resolved["analysis_context"] is analysis_context


def test_resolve_playbook_accepts_complete_multiple_required_params():
    engine = _engine_with_playbook([
        _required("host_identifier"),
        _required("remote_username"),
        _required("remote_key_path"),
    ])
    supplied = {
        "host_identifier": "server.example.test",
        "remote_username": "analyst",
        "remote_key_path": "C:/keys/id_ed25519",
    }

    _pb, _playbook_id, _steps, resolved = engine._resolve_playbook(
        "validation-test",
        supplied,
    )

    assert resolved == supplied


@pytest.mark.asyncio
async def test_start_validation_failure_creates_no_session():
    engine = _engine_with_playbook([
        _required("host_identifier"),
        _required("remote_username"),
    ])

    with pytest.raises(PlaybookValidationError):
        await engine.start(
            "validation-test",
            {"host_identifier": "server.example.test"},
        )

    engine.store.create_session.assert_not_called()


def test_resolve_playbook_without_input_params_is_unchanged():
    engine = _engine_with_playbook()
    supplied = {"file_path": "C:/samples/malware.exe"}

    _pb, _playbook_id, _steps, resolved = engine._resolve_playbook(
        "validation-test",
        supplied,
    )

    assert resolved == supplied


def test_playbook_run_route_maps_validation_error_to_http_400():
    engine = SimpleNamespace(
        start=AsyncMock(side_effect=PlaybookValidationError("missing required params"))
    )
    app = FastAPI()
    app.state.playbook_engine = engine
    app.include_router(playbooks_router, prefix="/api/playbooks")

    response = TestClient(app).post(
        "/api/playbooks/validation-test/run",
        json={"params": {"host_identifier": "server.example.test"}},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "missing required params"}


def test_chat_route_maps_validation_error_to_http_400():
    engine = SimpleNamespace(
        start=AsyncMock(side_effect=PlaybookValidationError("missing required params"))
    )
    app = FastAPI()
    app.state.agent_loop = MagicMock()
    app.state.playbook_engine = engine
    app.include_router(chat_router, prefix="/api/chat")

    response = TestClient(app).post(
        "/api/chat",
        json={
            "message": "server.example.test",
            "playbook_id": "validation-test",
        },
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "missing required params"}
