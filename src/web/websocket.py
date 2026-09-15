"""
Author: Ugur Ates
WebSocket handler for real-time analysis progress.
"""

import asyncio
import json
import logging
from typing import Sequence

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from .auth import authorize_role, get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()


async def _authenticate_websocket(
    websocket: WebSocket, roles: Sequence[str]
) -> dict | None:
    """Accept, then require a first JSON auth message within five seconds."""
    await websocket.accept()
    try:
        message = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)
    except (
        asyncio.TimeoutError,
        WebSocketDisconnect,
        json.JSONDecodeError,
        TypeError,
    ):
        await websocket.close(code=1008)
        return None

    if not isinstance(message, dict) or message.get("type") != "auth":
        await websocket.close(code=1008)
        return None

    token = message.get("token")
    if not isinstance(token, str) or not token:
        await websocket.close(code=1008)
        return None

    try:
        user = get_current_user(token)
        authorize_role(user, roles)
    except (HTTPException, ValueError):
        await websocket.close(code=1008)
        return None
    return user


@router.websocket('/ws/analysis/{analysis_id}')
async def analysis_ws(websocket: WebSocket, analysis_id: str):
    """WebSocket endpoint for real-time analysis progress updates.

    Client connects to ``/ws/analysis/{id}`` and receives JSON messages::

        {"type": "progress", "progress": 45, "step": "Querying VirusTotal..."}
        {"type": "completed", "verdict": "MALICIOUS", "score": 85}
        {"type": "failed", "error": "Timeout"}
    """
    authenticated_user = await _authenticate_websocket(
        websocket, ["SOC Analyst Tier 1-2", "admin"]
    )
    if authenticated_user is None:
        return

    # Phase 2.5 gap: analysis ownership is not yet represented in storage.

    mgr = websocket.app.state.analysis_manager
    queue = mgr.subscribe(analysis_id)

    try:
        # Send current status immediately
        job = mgr.get_job(analysis_id)
        if job:
            await websocket.send_json({
                'type': 'status',
                'status': job.get('status'),
                'progress': job.get('progress', 0),
                'step': job.get('current_step', ''),
            })

            # If already completed, send result and close
            if job.get('status') in ('completed', 'failed'):
                await websocket.send_json({
                    'type': job['status'],
                    'verdict': job.get('verdict'),
                    'score': job.get('score'),
                })
                await websocket.close()
                return

        # Stream updates
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_json(msg)

                # Close after completion or failure
                if msg.get('type') in ('completed', 'failed'):
                    break
            except asyncio.TimeoutError:
                # Send heartbeat
                await websocket.send_json({'type': 'heartbeat'})

    except WebSocketDisconnect:
        logger.debug(f"[WS] Client disconnected: {analysis_id}")
    except Exception as exc:
        logger.debug(f"[WS] Error: {exc}")
    finally:
        mgr.unsubscribe(analysis_id, queue)


@router.websocket('/ws/agent/{session_id}')
async def agent_ws(websocket: WebSocket, session_id: str):
    """WebSocket endpoint for real-time agent investigation updates.

    Uses AgentLoop's pub/sub system for efficient event-driven updates
    instead of polling.
    """
    authenticated_user = await _authenticate_websocket(
        websocket, ["Threat Hunter", "admin"]
    )
    if authenticated_user is None:
        return

    # Phase 2.5 gap: agent session ownership is not yet represented in storage.

    store = websocket.app.state.agent_store
    agent_loop = websocket.app.state.agent_loop
    if not store:
        await websocket.send_json({'type': 'error', 'error': 'Agent store not available'})
        await websocket.close()
        return

    # Send current session state immediately
    session = store.get_session(session_id)
    if not session:
        await websocket.send_json({'type': 'error', 'error': 'Session not found'})
        await websocket.close()
        return

    steps = store.get_steps(session_id)
    await websocket.send_json({
        'type': 'session_state',
        'session': session,
        'steps': steps,
    })

    # If already done, close
    if session.get('status') in ('completed', 'failed', 'cancelled'):
        await websocket.send_json({
            'type': session['status'],
            'summary': session.get('summary', ''),
        })
        await websocket.close()
        return

    # Use pub/sub if agent loop available, otherwise fall back to polling
    if agent_loop:
        queue = agent_loop.subscribe(session_id)
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    await websocket.send_json(msg)
                    if msg.get('type') in ('completed', 'failed', 'cancelled'):
                        break
                except asyncio.TimeoutError:
                    await websocket.send_json({'type': 'heartbeat'})
        except WebSocketDisconnect:
            logger.debug(f"[WS] Agent client disconnected: {session_id}")
        except Exception as exc:
            logger.debug(f"[WS] Agent WS error: {exc}")
        finally:
            agent_loop.unsubscribe(session_id, queue)
    else:
        # Fallback: poll store every 2s
        try:
            last_step_count = len(steps)
            while True:
                await asyncio.sleep(2)
                session = store.get_session(session_id)
                if not session:
                    break

                current_steps = store.get_steps(session_id)
                if len(current_steps) > last_step_count:
                    for step in current_steps[last_step_count:]:
                        await websocket.send_json({'type': 'step', 'step': step})
                    last_step_count = len(current_steps)

                if session.get('status') in ('completed', 'failed', 'cancelled'):
                    await websocket.send_json({
                        'type': session['status'],
                        'summary': session.get('summary', ''),
                    })
                    break

                await websocket.send_json({'type': 'heartbeat'})
        except WebSocketDisconnect:
            logger.debug(f"[WS] Agent client disconnected: {session_id}")
        except Exception as exc:
            logger.debug(f"[WS] Agent WS error: {exc}")
