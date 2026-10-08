"""
Author: Ugur Ates
Chat API routes - Interactive agent conversation.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ...agent.playbook_engine import PlaybookValidationError
from ..auth import authorize_role, get_current_user, require_role
from ..chat_intents import route_chat_message
from ..visibility import serialize_chat_session

logger = logging.getLogger(__name__)
router = APIRouter()


def _owner_scope(current_user: dict) -> Optional[int]:
    return None if current_user.get("role") == "admin" else current_user["id"]


class ChatMessage(BaseModel):
    message: str = Field(..., min_length=1)
    session_id: Optional[str] = None
    playbook_id: Optional[str] = None
    history: list[dict[str, str]] = Field(default_factory=list)


def _parse_structured_params(message: str) -> dict | None:
    """Parse 'key: value' per-line message into a dict.

    Returns None (caller should fall back to plain query/user_input)
    unless every non-empty line contains a colon.
    """
    lines = [line for line in message.splitlines() if line.strip()]
    if not lines:
        return None
    parsed = {}
    for line in lines:
        if ":" not in line:
            return None
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key:
            return None
        parsed[key] = value
    return parsed


@router.post('')
async def send_message(
    request: Request,
    body: ChatMessage,
    current_user: dict = Depends(get_current_user),
):
    """Send a message to the agent.

    If session_id is provided, this is a follow-up message.
    If playbook_id is provided, execute the playbook directly.
    Otherwise, a new investigation is started (LLM may auto-select a playbook).
    """
    role = current_user.get("role")
    if role not in {"Incident Responder", "Threat Hunter", "admin"}:
        raise HTTPException(
            status_code=403,
            detail=f"{role or 'Your role'} cannot access agent chat.",
        )

    if body.playbook_id:
        _authorize_chat_action(current_user, {"Incident Responder", "admin"}, "run incident response playbooks")
    else:
        # Incident Responders can reach the gate for instant replies; an
        # investigation result is rejected by the action authorization below.
        agent_loop = getattr(request.app.state, "agent_loop", None)
        if agent_loop is None:
            raise HTTPException(503, "Agent loop not initialized. Check LLM configuration.")
        instant = await route_chat_message(
            agent_loop, body.message, body.history, role=role,
        )
        if instant is not None:
            return instant
        _authorize_chat_action(current_user, {"Threat Hunter", "admin"}, "start agent investigations")

    agent_loop = request.app.state.agent_loop
    if agent_loop is None:
        raise HTTPException(503, "Agent loop not initialized. Check LLM configuration.")

    # Direct playbook execution from chat
    if body.playbook_id:
        engine = request.app.state.playbook_engine
        if engine is None:
            raise HTTPException(503, "Playbook engine not initialized")
        try:
            # Parse input params from message
            input_data = {"query": body.message, "user_input": body.message}
            structured = _parse_structured_params(body.message)
            if structured:
                input_data.update(structured)
            session_id = await engine.start(
                body.playbook_id,
                input_data,
                case_id=None,
                user_id=current_user["id"],
                role=current_user["role"],
            )
            return {
                "session_id": session_id,
                "status": "processing",
                "playbook_id": body.playbook_id,
                "message": body.message,
            }
        except PlaybookValidationError as e:
            raise HTTPException(400, str(e))
        except ValueError as e:
            raise HTTPException(404, str(e))
        except Exception as e:
            raise HTTPException(500, f"Playbook execution failed: {str(e)}")

    if body.session_id:
        # Follow-up message to existing session
        store = request.app.state.agent_store
        if store is None:
            raise HTTPException(503, "Agent store not initialized")

        session = store.get_session(
            body.session_id,
            user_id=_owner_scope(current_user),
        )
        if session is None:
            raise HTTPException(
                status_code=404,
                detail="Session not found",
            )

        # If session is still active, return status
        if session.get('status') == 'active':
            return {
                "session_id": body.session_id,
                "status": "active",
                "response": "The investigation is still running. Check the progress via WebSocket.",
            }

        # If session is completed/failed, start a new investigation with context
        context = f"(Follow-up to previous investigation: {session.get('goal', '')})\n{body.message}"
        session_id = await agent_loop.investigate(
            context,
            case_id=session.get('case_id'),
            user_id=current_user["id"],
            role=current_user["role"],
        )
        return {
            "session_id": session_id,
            "status": "processing",
            "response": "Follow-up investigation started.",
        }
    else:
        # New investigation - LLM will see available playbooks and may auto-select one
        session_id = await agent_loop.investigate(
            body.message,
            user_id=current_user["id"],
            role=current_user["role"],
        )
        return {
            "session_id": session_id,
            "status": "processing",
            "message": body.message,
        }


@router.get('/sessions')
async def list_chat_sessions(
    request: Request,
    limit: int = 20,
    current_user: dict = Depends(get_current_user),
):
    """List recent chat sessions."""
    authorize_role(current_user, ["Threat Hunter", "admin"])
    store = request.app.state.agent_store
    if store is None:
        return {"sessions": []}
    sessions = store.list_sessions(
        limit=limit,
        user_id=_owner_scope(current_user),
    )
    return {
        "sessions": [serialize_chat_session(session, role=current_user['role']) for session in sessions]
    }


def _authorize_chat_action(current_user: dict, allowed_roles: set[str], action: str) -> None:
    """Keep instant replies available while explaining role-gated chat actions."""
    if current_user.get("role") in allowed_roles:
        return
    role = current_user.get("role", "Your role")
    if role == "Incident Responder":
        detail = f"Incident Responders can run approved playbooks, but cannot {action}. Ask a Threat Hunter or administrator for access."
    elif role == "SOC Analyst Tier 1-2":
        detail = f"SOC Analyst Tier 1-2 can use help and greeting replies, but cannot {action}. Ask a Threat Hunter or administrator for access."
    else:
        detail = f"{role} cannot {action}. Ask an administrator for access."
    raise HTTPException(status_code=403, detail=detail)


@router.get('/sessions/{session_id}')
async def get_chat_session(
    request: Request,
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get a chat session with steps."""
    authorize_role(current_user, ["Threat Hunter", "admin"])
    store = request.app.state.agent_store
    if store is None:
        raise HTTPException(503, "Agent store not initialized")
    session = store.get_session(
        session_id,
        user_id=_owner_scope(current_user),
    )
    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Session not found",
        )
    steps = store.get_steps(session_id)
    session['steps'] = steps
    # Include live state if available
    agent_loop = request.app.state.agent_loop
    if agent_loop:
        live_state = agent_loop.get_state(session_id)
        if live_state:
            session['live_state'] = live_state
    return serialize_chat_session(session, steps=steps, role=current_user['role'])
