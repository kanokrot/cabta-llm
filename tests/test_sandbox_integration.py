import pytest

from src.integrations import sandbox_integration
from src.integrations.sandbox_integration import SandboxIntegration


TEST_HASH = "a" * 64
HA_URL = "https://www.hybrid-analysis.com/api/v2/search/hash"


class FakeResponse:
    def __init__(self, status, payload=None, body=""):
        self.status = status
        self._payload = payload
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return None

    async def json(self):
        return self._payload

    async def text(self):
        return self._body


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.get_calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return None

    def get(self, url, **kwargs):
        self.get_calls.append((url, kwargs))
        return self.response


def make_integration(monkeypatch, session):
    monkeypatch.setattr(
        sandbox_integration.aiohttp,
        "ClientSession",
        lambda **kwargs: session,
    )
    return SandboxIntegration({"api_keys": {"hybrid_analysis": "test-key"}})


@pytest.mark.asyncio
async def test_hybrid_hash_lookup_uses_get_query_parameter(monkeypatch):
    session = FakeSession(
        FakeResponse(
            200,
            payload=[{"verdict": "benign"}],
        )
    )
    integration = make_integration(monkeypatch, session)

    result = await integration._check_hybrid_analysis(TEST_HASH)

    assert result["found"] is True
    assert len(session.get_calls) == 1
    url, kwargs = session.get_calls[0]
    assert url == HA_URL
    assert TEST_HASH not in url
    assert kwargs["params"] == {"hash": TEST_HASH}
    assert kwargs["headers"] == {
        "api-key": "test-key",
        "User-Agent": "Blue Team Assistant",
        "accept": "application/json",
    }


@pytest.mark.asyncio
async def test_hybrid_hash_lookup_parses_realistic_mapping_response(
    monkeypatch,
):
    session = FakeSession(
        FakeResponse(
            200,
            payload={
                "sha256s": [TEST_HASH],
                "reports": [
                    {
                        "id": "report-id",
                        "environment_id": 160,
                        "state": "SUCCESS",
                        "verdict": "benign",
                    }
                ],
            },
        )
    )
    integration = make_integration(monkeypatch, session)

    result = await integration.check_file_sandboxes(TEST_HASH)

    assert result["hybrid_analysis"]["found"] is True
    assert result["hybrid_analysis"]["verdict"] == "benign"
    assert result["summary"]["available_reports"] >= 1


@pytest.mark.asyncio
async def test_hybrid_hash_lookup_preserves_http_error_body(monkeypatch):
    body = '{"validation_errors":[...],"message":"Input data validation has failed."}'
    session = FakeSession(FakeResponse(400, body=body))
    integration = make_integration(monkeypatch, session)

    result = await integration._check_hybrid_analysis(TEST_HASH)

    assert result["error"] == "HTTP 400"
    assert result["response_body"] == body


@pytest.mark.asyncio
async def test_hybrid_hash_lookup_preserves_exception_detail(monkeypatch):
    connection_error = ConnectionError("connection refused")

    class RaisingSession(FakeSession):
        def get(self, url, **kwargs):
            raise connection_error

    integration = make_integration(monkeypatch, RaisingSession(None))

    result = await integration._check_hybrid_analysis(TEST_HASH)

    assert result["error"] == str(connection_error)
    assert result["exception_type"] == "ConnectionError"
    assert result["exception_message"] == str(connection_error)
