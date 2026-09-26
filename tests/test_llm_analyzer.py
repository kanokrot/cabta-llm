import asyncio

import aiohttp
import pytest

from src.integrations import llm_analyzer
from src.integrations.llm_analyzer import LLMAnalyzer


class _FakeResponse:
    def __init__(self, payload, status=200):
        self.status = status
        self.payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def json(self):
        return self.payload

    async def text(self):
        return ""


class _RequestContext:
    def __init__(self, outcome):
        self.outcome = outcome

    async def __aenter__(self):
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None


class _FakeSession:
    def __init__(self, outcomes, attempts):
        self.outcomes = outcomes
        self.attempts = attempts

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    def post(self, url, headers=None, json=None):
        index = self.attempts[0]
        self.attempts[0] += 1
        return _RequestContext(self.outcomes[index])


def _analyzer():
    return LLMAnalyzer(
        {
            "llm": {
                "provider": "vllm",
                "vllm_base_url": "http://vllm.test",
                "vllm_model": "test-model",
            }
        }
    )


def _success_response():
    return _FakeResponse(
        {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": '{"verdict":"CLEAN"}'},
                }
            ]
        }
    )


def _connector_error():
    from aiohttp.client_reqrep import ConnectionKey

    key = ConnectionKey("vllm.test", 80, False, None, None, None, None)
    return aiohttp.ClientConnectorError(key, OSError("connection refused"))


def _patch_sessions(monkeypatch, outcomes):
    attempts = [0]

    def make_session(*args, **kwargs):
        return _FakeSession(outcomes, attempts)

    monkeypatch.setattr(llm_analyzer.aiohttp, "ClientSession", make_session)
    return attempts


@pytest.mark.asyncio
async def test_vllm_timeout_retries_once_then_succeeds(monkeypatch):
    attempts = _patch_sessions(
        monkeypatch,
        [asyncio.TimeoutError(), _success_response()],
    )

    result = await _analyzer()._call_vllm_api("test prompt")

    assert result == {"verdict": "CLEAN"}
    assert attempts[0] == 2


@pytest.mark.asyncio
async def test_vllm_connector_failure_retries_once_then_returns_none(monkeypatch):
    attempts = _patch_sessions(
        monkeypatch,
        [_connector_error(), _connector_error()],
    )

    result = await _analyzer()._call_vllm_api("test prompt")

    assert result is None
    assert attempts[0] == 2


@pytest.mark.asyncio
async def test_ioc_summary_preserves_vllm_exception_detail(monkeypatch):
    attempts = _patch_sessions(
        monkeypatch,
        [ValueError("malformed response")],
    )

    result = await _analyzer().analyze_ioc_results(
        "kilijuxy.workers.dev",
        "domain",
        {
            "threat_score": 0,
            "sources_checked": 9,
            "sources_flagged": 0,
            "sources": {},
        },
    )

    assert attempts[0] == 1
    assert result["error"] == "Failed to get LLM response"
    assert result["provider"] == "vllm"
    assert result["exception_type"] == "ValueError"
    assert result["exception_message"] == "malformed response"


@pytest.mark.asyncio
async def test_vllm_success_does_not_retry(monkeypatch):
    attempts = _patch_sessions(monkeypatch, [_success_response()])

    result = await _analyzer()._call_vllm_api("test prompt")

    assert result == {"verdict": "CLEAN"}
    assert attempts[0] == 1
