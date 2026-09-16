"""
Author: Ugur Ates
WebSocket handler for real-time analysis progress.
"""

import asyncio
import json
import logging
from typing import Sequence

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from .auth import TEAM_LEAD, authorize_role, get_current_user, get_user_ids_by_role
from .visibility import (
    VisibilityError,
    serialize_websocket_frame,
)

logger = logging.getLogger(__name__)
router = APIRouter()


async def _send_visible(websocket: WebSocket, payload: dict, *, role: str, flow: str) -> None:
    """Serialize and send exactly one safe WebSocket frame.

    The serializer is deliberately called before touching the socket.  An
    unknown role, flow, or frame therefore fails closed without leaking the
    original payload.
    """
    serializer_flow = {
        "analysis": "websocket_analysis",
        "agent": "websocket_agent",
    }.get(flow, flow)
    visible = serialize_websocket_frame(payload, role=role, flow=serializer_flow)
    await websocket.send_json(visible)


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
        websocket,
        [
            "SOC Analyst Tier 1-2",
            "Incident Responder",
            "Threat Hunter",
            "Team Lead",
            "admin",
        ],
    )
    if authenticated_user is None:
        return

    # Analysis jobs are shared cross-role workflow artifacts.
    # Ownership is intentionally not checked here.

    mgr = websocket.app.state.analysis_manager
    queue = mgr.subscribe(analysis_id)

    try:
        # Send current status immediately
        job = mgr.get_job(analysis_id)
        if job:
            role = authenticated_user['role']
            owner_id = job.get('user_id')
            if role == TEAM_LEAD:
                if owner_id is not None and owner_id not in get_user_ids_by_role('SOC Analyst Tier 1-2'):
                    await websocket.close(code=1008)
                    return
            elif role != 'admin' and owner_id is not None and str(owner_id) != str(authenticated_user.get('id')):
                await websocket.close(code=1008)
                return
        if job:
            await _send_visible(websocket, {
                'type': 'status',
                'status': job.get('status'),
                'progress': job.get('progress', 0),
                'step': job.get('current_step', ''),
            }, role=authenticated_user['role'], flow='analysis')

            # If already completed, send result and close
            if job.get('status') in ('completed', 'failed'):
                await _send_visible(websocket, {
                    'type': job['status'],
                    'verdict': job.get('verdict'),
                    'score': job.get('score'),
                }, role=authenticated_user['role'], flow='analysis')
                await websocket.close()
                return

        # Stream updates
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=30.0)
                await _send_visible(websocket, msg, role=authenticated_user['role'], flow='analysis')

                # Close after completion or failure
                if msg.get('type') in ('completed', 'failed'):
                    break
            except asyncio.TimeoutError:
                # Send heartbeat
                await _send_visible(websocket, {'type': 'heartbeat'}, role=authenticated_user['role'], flow='analysis')

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

    store = websocket.app.state.agent_store
    agent_loop = websocket.app.state.agent_loop
    if not store:
        await _send_visible(websocket, {'type': 'failed', 'error': 'Agent store not available'}, role=authenticated_user['role'], flow='agent')
        await websocket.close()
        return

    # Send current session state immediately
    session = store.get_session(session_id)
    if not session:
        await _send_visible(websocket, {'type': 'failed', 'error': 'Session not found'}, role=authenticated_user['role'], flow='agent')
        await websocket.close()
        return

    if authenticated_user.get('role') != 'admin':
        owner_id = session.get('user_id')
        if owner_id is None or str(owner_id) != str(authenticated_user.get('id')):
            await websocket.close(code=1008)
            return

    steps = store.get_steps(session_id)
    await _send_visible(websocket, {
        'type': 'session_state',
        'session': session,
        'steps': steps,
    }, role=authenticated_user['role'], flow='agent')

    # If already done, close
    if session.get('status') in ('completed', 'failed', 'cancelled'):
        await _send_visible(websocket, {
            'type': session['status'],
            'summary': session.get('summary', ''),
        }, role=authenticated_user['role'], flow='agent')
        await websocket.close()
        return

    # Use pub/sub if agent loop available, otherwise fall back to polling
    if agent_loop:
        queue = agent_loop.subscribe(session_id)
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    await _send_visible(websocket, msg, role=authenticated_user['role'], flow='agent')
                    if msg.get('type') in ('completed', 'failed', 'cancelled'):
                        break
                except asyncio.TimeoutError:
                    await _send_visible(websocket, {'type': 'heartbeat'}, role=authenticated_user['role'], flow='agent')
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
                session = store.get_session(
                    session_id,
                    user_id=(
                        None
                        if authenticated_user.get('role') == 'admin'
                        else authenticated_user.get('id')
                    ),
                )
                if not session:
                    break

                current_steps = store.get_steps(session_id)
                if len(current_steps) > last_step_count:
                    for step in current_steps[last_step_count:]:
                        await _send_visible(websocket, {'type': 'step', 'step': step}, role=authenticated_user['role'], flow='agent')
                    last_step_count = len(current_steps)

                if session.get('status') in ('completed', 'failed', 'cancelled'):
                    await _send_visible(websocket, {
                        'type': session['status'],
                        'summary': session.get('summary', ''),
                    }, role=authenticated_user['role'], flow='agent')
                    break

                await _send_visible(websocket, {'type': 'heartbeat'}, role=authenticated_user['role'], flow='agent')
        except WebSocketDisconnect:
            logger.debug(f"[WS] Agent client disconnected: {session_id}")
        except Exception as exc:
            logger.debug(f"[WS] Agent WS error: {exc}")
