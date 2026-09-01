"""
Author: Ugur Ates
Report API endpoints.
"""

import json
import logging
import os
import tempfile
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from starlette.background import BackgroundTask

from ...reporting.ioc_pdf import generate_ioc_pdf

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get('/{analysis_id}/json')
async def get_report_json(request: Request, analysis_id: str):
    """Get raw JSON report."""
    mgr = request.app.state.analysis_manager
    job = mgr.get_job(analysis_id)
    if job is None:
        raise HTTPException(404, 'Analysis not found')
    return JSONResponse(content=job.get('result') or job)


@router.get('/{analysis_id}/html')
async def get_report_html(request: Request, analysis_id: str):
    """Get HTML report."""
    mgr = request.app.state.analysis_manager
    job = mgr.get_job(analysis_id)
    if job is None:
        raise HTTPException(404, 'Analysis not found')

    templates = request.app.state.templates
    return templates.TemplateResponse('report_view.html', {
        'request': request,
        'job': job,
    })


@router.get('/{analysis_id}/mitre')
async def get_mitre_layer(request: Request, analysis_id: str):
    """Get MITRE ATT&CK Navigator layer JSON."""
    mgr = request.app.state.analysis_manager
    job = mgr.get_job(analysis_id)
    if job is None:
        raise HTTPException(404, 'Analysis not found')

    result = job.get('result') or {}
    techniques = result.get('mitre_techniques', [])

    # Build Navigator layer
    layer = {
        'name': f'BTA Analysis {analysis_id}',
        'versions': {'attack': '14', 'navigator': '4.9', 'layer': '4.5'},
        'domain': 'enterprise-attack',
        'description': f'Auto-generated from analysis {analysis_id}',
        'techniques': [
            {
                'techniqueID': t.get('technique_id', ''),
                'tactic': t.get('tactic', '').lower().replace(' ', '-'),
                'color': '#e60d0d',
                'comment': t.get('technique_name', ''),
                'enabled': True,
            }
            for t in techniques
        ],
    }
    return JSONResponse(content=layer)


@router.get('/{analysis_id}/pdf')
async def get_report_pdf(request: Request, analysis_id: str):
    """Generate and download a PDF report for an IOC analysis."""
    mgr = request.app.state.analysis_manager
    job = mgr.get_job(analysis_id)
    if job is None:
        raise HTTPException(404, 'Analysis not found')

    result = job.get('result') or {}
    if not isinstance(result, dict):
        raise HTTPException(500, 'Invalid analysis result')

    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
        temp_path = temp_file.name

    report_path = generate_ioc_pdf(result, temp_path)
    if report_path is None:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise HTTPException(500, 'Failed to generate PDF report')

    return FileResponse(
        path=report_path,
        media_type='application/pdf',
        filename=f'ioc-report-{analysis_id}.pdf',
        background=BackgroundTask(os.unlink, report_path),
    )
