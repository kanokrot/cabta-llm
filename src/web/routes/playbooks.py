"""
Author: Ugur Ates
Playbook API routes.
"""

import logging
import os
import tempfile
from typing import Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from ...agent.playbook_engine import PlaybookValidationError
from ...reporting.html_report_generator import HTMLReportGenerator

logger = logging.getLogger(__name__)
router = APIRouter()


class PlaybookRunRequest(BaseModel):
    params: Dict = {}
    case_id: Optional[str] = None


@router.get('')
async def list_playbooks(request: Request):
    """List all available playbooks."""
    engine = request.app.state.playbook_engine
    if engine:
        return {"playbooks": engine.list_playbooks()}
    store = request.app.state.agent_store
    if store:
        return {"playbooks": store.list_playbooks()}
    return {"playbooks": []}


@router.get('/{playbook_id}')
async def get_playbook(request: Request, playbook_id: str):
    """Get playbook details."""
    engine = request.app.state.playbook_engine
    if engine:
        pb = engine.get_playbook(playbook_id)
        if pb:
            return pb
    store = request.app.state.agent_store
    if store:
        pb = store.get_playbook(playbook_id)
        if pb:
            return pb
    raise HTTPException(404, "Playbook not found")


@router.post('/{playbook_id}/run')
async def run_playbook(request: Request, playbook_id: str, body: PlaybookRunRequest = PlaybookRunRequest()):
    """Execute a playbook."""
    engine = request.app.state.playbook_engine
    if engine is None:
        raise HTTPException(503, "Playbook engine not initialized")
    try:
        session_id = await engine.start(playbook_id, body.params, body.case_id)
        return {"session_id": session_id, "status": "running"}
    except PlaybookValidationError as e:
        raise HTTPException(400, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        raise HTTPException(500, f"Playbook execution failed: {str(e)}")

class PlaybookApprovalRequest(BaseModel):
    approved: bool
    comment: str = ""
    approved_by: str = "unknown"


@router.post('/sessions/{session_id}/approve')
async def approve_playbook_step(request: Request, session_id: str, body: PlaybookApprovalRequest):
    """Approve or reject a pending playbook approval checkpoint."""
    engine = request.app.state.playbook_engine
    if engine is None:
        raise HTTPException(503, "Playbook engine not initialized")
    try:
        result_session_id = await engine.execute_from_step(session_id, body.approved, body.approved_by)
        return {"success": True, "session_id": result_session_id}
    except ValueError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        raise HTTPException(500, f"Playbook resume failed: {str(e)}")


@router.get('/sessions/{session_id}/report')
async def get_playbook_report(request: Request, session_id: str):
    """Generate and serve an HTML report for a completed playbook session."""
    store = request.app.state.agent_store
    if store is None:
        raise HTTPException(503, "Agent store not initialized")
    session = store.get_session(session_id)
    if session is None:
        raise HTTPException(404, "Session not found")
    metadata = session.get('metadata') or {}
    if not isinstance(metadata, dict):
        metadata = {}
    investigation_result = metadata.get('ioc_investigation_result')
    ioc = metadata.get('ioc')
    if not investigation_result:
        raise HTTPException(404, "No report data available for this session")

    with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as temp_file:
        temp_path = temp_file.name

    try:
        report_path = HTMLReportGenerator().generate_ioc_report(
            investigation_result, ioc, temp_path,
        )
        if report_path is None:
            raise HTTPException(500, "Failed to generate HTML report")
        with open(temp_path, "r", encoding="utf-8") as report_file:
            html_content = report_file.read()
    finally:
        try:
            os.unlink(temp_path)
        except OSError as cleanup_exc:
            logger.warning(
                "Failed to delete temporary report file %s: %s",
                temp_path, cleanup_exc,
            )

    return HTMLResponse(content=html_content)
