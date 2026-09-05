"""
Author: Ugur Ates
Case Management API endpoints.
"""

import logging
import os
import sqlite3
import tempfile
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from ...reporting.incident_report_pdf import generate_incident_report_pdf
from ..case_store import _severity_to_4tier
from ..models import (
    CaseCreate,
    CaseNote,
    CaseStatusUpdate,
    IncidentReport,
    IncidentReportCreate,
    IncidentReportUpdate,
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post('')
async def create_case(request: Request, payload: CaseCreate):
    """Create a new case."""
    store = request.app.state.case_store
    case_id = store.create_case(
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
    )
    return {'id': case_id, 'message': f'Case created: {payload.title}'}


@router.get('')
async def list_cases(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
):
    """List all cases."""
    store = request.app.state.case_store
    cases = store.list_cases(limit=limit, offset=offset, status=status)
    return {'items': cases}


@router.get('/{case_id}')
async def get_case(request: Request, case_id: str):
    """Get case details with linked analyses and notes."""
    store = request.app.state.case_store
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(404, 'Case not found')
    return case


@router.post('/{case_id}/incident-report', response_model=IncidentReport)
async def create_incident_report(
    request: Request, case_id: str, payload: IncidentReportCreate
):
    """Create the incident report for a case."""
    store = request.app.state.case_store
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(404, 'Case not found')
    fields = payload.model_dump(exclude_none=True)
    if 'severity_4tier' not in fields:
        fields['severity_4tier'] = _severity_to_4tier(case['severity'])
    try:
        return store.create_incident_report(case_id, **fields)
    except sqlite3.IntegrityError:
        raise HTTPException(409, 'Incident report already exists')


@router.get('/{case_id}/incident-report', response_model=IncidentReport)
async def get_incident_report(request: Request, case_id: str):
    """Get a case incident report."""
    report = request.app.state.case_store.get_incident_report(case_id)
    if report is None:
        raise HTTPException(404, 'Incident report not found')
    return report


@router.get('/{case_id}/incident-report/pdf')
async def get_incident_report_pdf(
    request: Request, case_id: str, download: bool = False
):
    """Generate a PDF for a case incident report."""
    store = request.app.state.case_store
    report = store.get_incident_report(case_id)
    if report is None:
        raise HTTPException(404, 'Incident report not found')

    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
        temp_path = temp_file.name

    report_path = generate_incident_report_pdf(report, temp_path)
    if report_path is None:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise HTTPException(500, 'Failed to generate incident report PDF')

    disposition_type = 'attachment' if download else 'inline'
    return FileResponse(
        path=report_path,
        media_type='application/pdf',
        filename=f'incident-report-{case_id}.pdf',
        background=BackgroundTask(os.unlink, report_path),
        content_disposition_type=disposition_type,
    )


@router.patch('/{case_id}/incident-report', response_model=IncidentReport)
async def update_incident_report(
    request: Request, case_id: str, payload: IncidentReportUpdate
):
    """Partially update a case incident report."""
    store = request.app.state.case_store
    fields = payload.model_dump(exclude_none=True)
    if not store.update_incident_report(case_id, **fields):
        raise HTTPException(404, 'Incident report not found')
    return store.get_incident_report(case_id)


@router.patch('/{case_id}/status')
async def update_case_status(request: Request, case_id: str, payload: CaseStatusUpdate):
    """Update case status."""
    store = request.app.state.case_store
    ok = store.update_case_status(case_id, payload.status.value)
    if not ok:
        raise HTTPException(404, 'Case not found')
    return {'message': f'Status updated to {payload.status.value}'}


@router.post('/{case_id}/analyses')
async def link_analysis(request: Request, case_id: str, analysis_id: str):
    """Link an analysis to a case."""
    store = request.app.state.case_store
    ok = store.link_analysis(case_id, analysis_id)
    if not ok:
        raise HTTPException(400, 'Failed to link analysis')
    return {'message': 'Analysis linked to case'}


@router.post('/{case_id}/notes')
async def add_note(request: Request, case_id: str, payload: CaseNote):
    """Add a note to a case."""
    store = request.app.state.case_store
    note_id = store.add_note(case_id, payload.content, payload.author)
    return {'id': note_id, 'message': 'Note added'}
