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

logger = logging.getLogger(__name__)
router = APIRouter()


def _owner_scope(current_user: dict) -> Optional[int]:
    return None if current_user.get("role") == "admin" else current_user["id"]


class ChatMessage(BaseModel):
    message: str = Field(..., min_length=1)
    session_id: Optional[str] = None
    playbook_id: Optional[str] = None


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
    if body.playbook_id:
        authorize_role(current_user, ["Incident Responder", "admin"])
    else:
        authorize_role(current_user, ["Threat Hunter", "admin"])

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
    store = request.app.state.agent_store
    if store is None:
        return {"sessions": []}
    sessions = store.list_sessions(
        limit=limit,
        user_id=_owner_scope(current_user),
    )
    return {"sessions": sessions}


@router.get('/sessions/{session_id}')
async def get_chat_session(
    request: Request,
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get a chat session with steps."""
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
    return session
