from unittest.mock import AsyncMock, patch

import pytest

from src.integrations.threat_feeds import ThreatFeeds


class _Session:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None


@pytest.mark.asyncio
async def test_sslbl_failed_fetch_is_not_marked_fresh_and_is_retried():
    cert_csv = f"2026-09-15,{'a' * 40},Test C2\n"
    fetch = AsyncMock(side_effect=[cert_csv, None, cert_csv, None])
    feed = ThreatFeeds({})

    with (
        patch.object(feed, "_session", return_value=_Session()),
        patch.object(feed, "_fetch_text", new=fetch),
    ):
        await feed._refresh_sslbl_cache()

        assert feed._sslbl_sha1.last_update > 0
        assert feed._sslbl_ips.last_update == 0
        assert feed._sslbl_ips.is_stale() is True

        await feed._refresh_sslbl_cache()

    assert fetch.await_count == 4
