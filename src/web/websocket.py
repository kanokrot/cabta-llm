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
from .security import SESSION_COOKIE_NAME
from .visibility import (
    INCIDENT_RESPONDER,
    VisibilityError,
    can_access_playbook_session,
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
        "playbook": "websocket_playbook",
    }.get(flow, flow)
    visible = serialize_websocket_frame(payload, role=role, flow=serializer_flow)
    await websocket.send_json(visible)


def _stored_agent_verdict(steps: Sequence[dict]) -> str | None:
    """Read the verdict from the persisted final-answer decision, if present."""
    for step in reversed(steps):
        if step.get("step_type") != "final_answer":
            continue
        content = step.get("content")
        if not isinstance(content, str):
            return None
        try:
            decision = json.loads(content)
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(decision, dict):
            return None
        verdict = decision.get("verdict")
        return verdict if isinstance(verdict, str) and verdict else None
    return None


async def _authenticate_websocket(
    websocket: WebSocket, roles: Sequence[str]
) -> dict | None:
    """Authenticate from the upgrade cookie or the legacy first message.

    Browser clients authenticate during the HTTP upgrade using the httpOnly
    session cookie.  Non-browser clients retain the existing first-message
    ``{"type": "auth", "token": "..."}`` protocol.
    """
    cookie_token = websocket.cookies.get(SESSION_COOKIE_NAME)
    if cookie_token:
        try:
            user = get_current_user(cookie_token)
            authorize_role(user, roles)
        except (HTTPException, ValueError):
            await websocket.close(code=1008)
            return None
        await websocket.accept()
        return user

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


def _pending_playbook_approval(store, session_id: str) -> dict | None:
    """Read the persisted approval checkpoint; its live event omits params."""
    steps = store.get_steps(session_id)
    pending = next(
        (step for step in reversed(steps) if step.get("step_type") == "approval_required"),
        None,
    )
    if not isinstance(pending, dict):
        return None
    params = pending.get("tool_params")
    if isinstance(params, str):
        try:
            params = json.loads(params)
        except (TypeError, json.JSONDecodeError):
            params = None
    description = pending.get("content")
    if isinstance(description, str) and description.startswith("Waiting for approval: "):
        description = description[len("Waiting for approval: "):]
    return {
        "type": "approval_required",
        "step": pending.get("step_number"),
        "tool": pending.get("tool_name"),
        "description": description,
        "params": params if isinstance(params, (dict, list)) else {},
    }


def _enrich_playbook_frame(store, session_id: str, frame: dict) -> dict:
    if frame.get("type") != "approval_required":
        return frame
    pending = _pending_playbook_approval(store, session_id)
    if pending is None:
        return frame
    enriched = dict(frame)
    for key in ("step", "tool", "description", "params"):
        if key not in enriched or (key == "params" and not enriched[key]):
            enriched[key] = pending[key]
    return enriched


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
        websocket, ["Threat Hunter", INCIDENT_RESPONDER, "admin"]
    )
    if authenticated_user is None:
        return

    store = websocket.app.state.agent_store
    agent_loop = websocket.app.state.agent_loop
    if not store:
        if authenticated_user.get("role") == INCIDENT_RESPONDER:
            await websocket.close(code=1008)
            return
        await _send_visible(websocket, {'type': 'failed', 'error': 'Agent store not available'}, role=authenticated_user['role'], flow='agent')
        await websocket.close()
        return

    # Send current session state immediately
    session = store.get_session(session_id)
    if not session:
        if authenticated_user.get("role") == INCIDENT_RESPONDER:
            await websocket.close(code=1008)
            return
        await _send_visible(websocket, {'type': 'failed', 'error': 'Session not found'}, role=authenticated_user['role'], flow='agent')
        await websocket.close()
        return

    if not can_access_playbook_session(authenticated_user, session):
        await websocket.close(code=1008)
        return

    flow = "playbook" if authenticated_user.get("role") == INCIDENT_RESPONDER else "agent"

    steps = store.get_steps(session_id)
    await _send_visible(websocket, {
        'type': 'session_state',
        'session': session,
        'steps': steps,
    }, role=authenticated_user['role'], flow=flow)

    if flow == "playbook" and session.get("status") == "waiting_approval":
        pending_approval = _pending_playbook_approval(store, session_id)
        if pending_approval is not None:
            await _send_visible(
                websocket, pending_approval, role=authenticated_user["role"], flow=flow
            )

    # If already done, close
    if session.get('status') in ('completed', 'failed', 'cancelled'):
        completed_frame = {
            'type': session['status'],
            'summary': session.get('summary', ''),
        }
        if flow == "agent" and session.get('status') == 'completed':
            completed_frame['verdict'] = _stored_agent_verdict(steps)
        await _send_visible(
            websocket, completed_frame, role=authenticated_user['role'], flow=flow
        )
        await websocket.close()
        return

    # Use pub/sub if agent loop available, otherwise fall back to polling
    if agent_loop:
        queue = agent_loop.subscribe(session_id)
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    if flow == "playbook" and isinstance(msg, dict):
                        msg = _enrich_playbook_frame(store, session_id, msg)
                    await _send_visible(websocket, msg, role=authenticated_user['role'], flow=flow)
                    if msg.get('type') in ('completed', 'failed', 'cancelled'):
                        break
                except asyncio.TimeoutError:
                    await _send_visible(websocket, {'type': 'heartbeat'}, role=authenticated_user['role'], flow=flow)
        except WebSocketDisconnect:
            logger.debug(f"[WS] Agent client disconnected: {session_id}")
        except VisibilityError as exc:
            logger.debug(f"[WS] Visibility policy rejected agent frame: {exc}")
            if flow == "playbook":
                await websocket.close(code=1008)
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
                if not session or not can_access_playbook_session(authenticated_user, session):
                    if flow == "playbook":
                        await websocket.close(code=1008)
                    break

                current_steps = store.get_steps(session_id)
                if len(current_steps) > last_step_count:
                    for step in current_steps[last_step_count:]:
                        if flow == "playbook" and step.get("step_type") == "approval_required":
                            pending_approval = _pending_playbook_approval(store, session_id)
                            if pending_approval is not None:
                                await _send_visible(
                                    websocket,
                                    pending_approval,
                                    role=authenticated_user["role"],
                                    flow=flow,
                                )
                        else:
                            await _send_visible(
                                websocket,
                                {"type": "step", "step": step},
                                role=authenticated_user["role"],
                                flow=flow,
                            )
                    last_step_count = len(current_steps)

                if session.get('status') in ('completed', 'failed', 'cancelled'):
                    completed_frame = {
                        'type': session['status'],
                        'summary': session.get('summary', ''),
                    }
                    if flow == "agent" and session.get('status') == 'completed':
                        completed_frame['verdict'] = _stored_agent_verdict(current_steps)
                    await _send_visible(
                        websocket, completed_frame,
                        role=authenticated_user['role'], flow=flow,
                    )
                    break

                await _send_visible(websocket, {'type': 'heartbeat'}, role=authenticated_user['role'], flow=flow)
        except WebSocketDisconnect:
            logger.debug(f"[WS] Agent client disconnected: {session_id}")
        except VisibilityError as exc:
            logger.debug(f"[WS] Visibility policy rejected agent frame: {exc}")
            if flow == "playbook":
                await websocket.close(code=1008)
        except Exception as exc:
            logger.debug(f"[WS] Agent WS error: {exc}")
