"""Lightweight asyncio runner for 15-minute notification digests."""

from __future__ import annotations

import asyncio

from .notification_policy import DIGEST_INTERVAL_SECONDS


async def run_digest_loop(manager, stop_event: asyncio.Event | None = None) -> None:
    """Run digest delivery every 15 minutes until application shutdown."""
    while True:
        if stop_event is None:
            await asyncio.sleep(DIGEST_INTERVAL_SECONDS)
        else:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=DIGEST_INTERVAL_SECONDS)
                return
            except asyncio.TimeoutError:
                pass
        try:
            await asyncio.to_thread(manager.send_pending_digests)
        except asyncio.CancelledError:
            raise
        except Exception:
            # NotificationManager is fail-safe; the loop must also stay alive.
            pass
