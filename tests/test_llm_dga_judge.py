import asyncio
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest
from aiohttp.client_reqrep import ConnectionKey

from src.tools.ioc_investigator import IOCInvestigator
from src.utils import llm_dga_judge


class _AsyncContext:
    def __init__(self, value):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _Response:
    def __init__(self, status=200, data=None, body=""):
        self.status = status
        self._data = data or {}
        self._body = body

    async def json(self):
        return self._data

    async def text(self):
        return self._body


def _mock_session(response):
    session = MagicMock()
    session.post.return_value = _AsyncContext(response)
    return _AsyncContext(session)


def _mock_session_post_error(error):
    session = MagicMock()
    session.post.side_effect = error
    return _AsyncContext(session)


@pytest.mark.asyncio
async def test_judge_domain_success(monkeypatch):
    response = _Response(
        data={
            "response": (
                '{"llm_verdict":"dga",'
                '"llm_reasoning":"random-looking domain label"}'
            )
        }
    )
    monkeypatch.setattr(
        llm_dga_judge.aiohttp,
        "ClientSession",
        MagicMock(return_value=_mock_session(response)),
    )

    result = await llm_dga_judge.judge_domain(
        "xj29qv-example.test",
        {"llm": {"ollama_endpoint": "http://localhost:11434", "model": "qwen2.5:3b"}},
    )

    assert result == {
        "domain": "xj29qv-example.test",
        "llm_verdict": "dga",
        "llm_reasoning": "random-looking domain label",
        "error": None,
    }


@pytest.mark.asyncio
async def test_judge_domain_malformed_json(monkeypatch):
    response = _Response(data={"response": "not valid json"})
    monkeypatch.setattr(
        llm_dga_judge.aiohttp,
        "ClientSession",
        MagicMock(return_value=_mock_session(response)),
    )

    result = await llm_dga_judge.judge_domain("example.test", {})

    assert result["domain"] == "example.test"
    assert result["llm_verdict"] == "uncertain"
    assert result["llm_reasoning"] == ""
    assert result["error"]


@pytest.mark.asyncio
async def test_judge_domain_connector_error(monkeypatch):
    connection_key = ConnectionKey(
        host="127.0.0.1",
        port=11434,
        is_ssl=False,
        ssl=None,
        proxy=None,
        proxy_auth=None,
        proxy_headers_hash=None,
    )
    error = aiohttp.ClientConnectorError(
        connection_key,
        OSError("connection refused"),
    )
    session_context = _mock_session_post_error(error)
    monkeypatch.setattr(
        llm_dga_judge.aiohttp,
        "ClientSession",
        MagicMock(return_value=session_context),
    )

    result = await llm_dga_judge.judge_domain("example.test", {})

    assert result["llm_verdict"] == "uncertain"
    assert result["llm_reasoning"] == ""
    assert result["error"]


@pytest.mark.asyncio
async def test_judge_domain_timeout(monkeypatch):
    session_context = _mock_session_post_error(
        asyncio.TimeoutError("timed out")
    )
    monkeypatch.setattr(
        llm_dga_judge.aiohttp,
        "ClientSession",
        MagicMock(return_value=session_context),
    )

    result = await llm_dga_judge.judge_domain("example.test", {})

    assert result["llm_verdict"] == "uncertain"
    assert result["llm_reasoning"] == ""
    assert result["error"] == "Ollama request timed out"


@pytest.mark.asyncio
async def test_judge_domain_non_200_status(monkeypatch):
    response = _Response(
        status=500,
        body="internal server error",
    )
    monkeypatch.setattr(
        llm_dga_judge.aiohttp,
        "ClientSession",
        MagicMock(return_value=_mock_session(response)),
    )

    result = await llm_dga_judge.judge_domain("example.test", {})

    assert result == {
        "domain": "example.test",
        "llm_verdict": "uncertain",
        "llm_reasoning": "",
        "error": "Ollama API error 500: internal server error",
    }


@pytest.mark.asyncio
async def test_vllm_truncation_is_labeled_and_logged(monkeypatch, caplog):
    response = _Response(
        data={
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {"role": "assistant", "content": "{"},
                }
            ]
        }
    )
    monkeypatch.setattr(
        llm_dga_judge.aiohttp,
        "ClientSession",
        MagicMock(return_value=_mock_session(response)),
    )

    with caplog.at_level("WARNING"):
        result = await llm_dga_judge._judge_via_vllm(
            "example.test",
            {"llm": {"vllm_base_url": "http://vllm.test"}},
        )

    assert result["error"] == "vLLM response truncated due to max_tokens"
    assert "vLLM response truncated due to max_tokens" in caplog.text


@pytest.mark.asyncio
async def test_vllm_timeout_log_includes_exception_type(monkeypatch, caplog):
    session_context = _mock_session_post_error(asyncio.TimeoutError())
    monkeypatch.setattr(
        llm_dga_judge.aiohttp,
        "ClientSession",
        MagicMock(return_value=session_context),
    )

    with caplog.at_level("WARNING"):
        result = await llm_dga_judge._judge_via_vllm(
            "example.test",
            {"llm": {"vllm_base_url": "http://vllm.test"}},
        )

    assert result["error"] == "vLLM request timed out"
    assert "vLLM request timed out (TimeoutError)" in caplog.text


def test_vllm_parser_error_names_the_provider():
    with pytest.raises(ValueError, match="Could not parse JSON from vLLM response"):
        llm_dga_judge._parse_json_response("not valid json", "vLLM")


@pytest.mark.asyncio
async def test_enrich_domain_preserves_rule_dga_and_adds_llm_judgment(monkeypatch):
    investigator = IOCInvestigator.__new__(IOCInvestigator)
    investigator.config = {"llm": {"model": "qwen2.5:3b"}}

    rule_result = {
        "domain": "example.test",
        "is_dga": True,
        "confidence": 54,
    }
    llm_result = {
        "domain": "example.test",
        "llm_verdict": "dga",
        "llm_reasoning": "random-looking label",
        "error": None,
    }

    monkeypatch.setattr(
        "src.tools.ioc_investigator.check_domain_age",
        lambda domain: {"domain_age_days": 365},
    )
    monkeypatch.setattr(
        "src.tools.ioc_investigator.detect_dga",
        lambda domain: rule_result,
    )
    monkeypatch.setattr(
        "src.utils.llm_dga_judge.judge_domain",
        AsyncMock(return_value=llm_result),
    )

    result = await investigator._enrich_domain("example.test")

    assert result["dga_analysis"] is rule_result
    assert result["llm_dga_judgment"] == llm_result
