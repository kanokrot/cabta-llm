import asyncio
import logging

import aiohttp
import pytest

from src.integrations.llm_analyzer import LLMAnalyzer


class _TimeoutRequest:
    async def __aenter__(self):
        raise asyncio.TimeoutError()

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class _MockSession:
    def __init__(self, *, timeout):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    def post(self, *args, **kwargs):
        return _TimeoutRequest()


def _config():
    return {
        'llm': {
            'provider': 'vllm',
            'vllm_base_url': 'http://mock-vllm.invalid',
            'vllm_model': 'vllm-spark-01/gemma4-26b-uncensored',
        },
        'api_keys': {},
    }


def test_vllm_timeout_is_separate_from_shared_timeout():
    analyzer = LLMAnalyzer(_config())

    assert analyzer.vllm_timeout.total == 45
    assert analyzer.vllm_timeout.connect == 10
    assert analyzer.timeout.total == 120


@pytest.mark.asyncio
async def test_vllm_timeout_log_contains_exception_class(monkeypatch, caplog):
    monkeypatch.setattr(aiohttp, 'ClientSession', _MockSession)
    analyzer = LLMAnalyzer(_config())

    with caplog.at_level(logging.ERROR):
        result = await analyzer._call_vllm_api('test prompt')

    assert result is None
    assert '[LLM] vLLM API call failed: TimeoutError:' in caplog.text
