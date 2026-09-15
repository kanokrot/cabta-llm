"""
Author: Ugur Ates with creamloso
Report API endpoints.
"""

import hashlib
import json
import logging
import os
import tempfile
import threading
import zipfile
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, StrictStr
from starlette.background import BackgroundTask

from ...detection.rule_validator import validate_rule
from ...reporting.ioc_pdf import generate_ioc_pdf
from ..auth import require_role

logger = logging.getLogger(__name__)
REPORT_ROLES = [
    'SOC Analyst Tier 1-2',
    'Incident Responder',
    'Threat Hunter',
    'admin',
]

router = APIRouter(
    dependencies=[Depends(require_role(REPORT_ROLES))]
)

_RULE_EXTENSIONS = {
    'kql': '.kql',
    'spl': '.spl',
    'sigma': '.yml',
    'yara': '.yar',
    'xql': '.xql',
    'dql': '.dql',
    'suricata': '.rules',
    'snort': '.rules',
    'firewall': '.conf',
}
_RULE_MEDIA_TYPES = {
    'sigma': 'application/yaml',
    'yara': 'text/plain',
}
_rule_export_states: Dict[Tuple[str, str], dict] = {}
_rule_export_lock = threading.RLock()


class RuleApprovalRequest(BaseModel):
    approved_by: str = 'unknown'


class RuleDeploymentRequest(BaseModel):
    deployed_by: str = 'unknown'


class RuleContentUpdateRequest(BaseModel):
    content: StrictStr


def _get_rule_content(
    request: Request,
    analysis_id: str,
    rule_type: str,
) -> Tuple[str, str]:
    normalized_type = str(rule_type or '').strip().lower()
    if normalized_type not in _RULE_EXTENSIONS:
        raise HTTPException(404, f'Unsupported rule type: {normalized_type}')

    job = request.app.state.analysis_manager.get_job(analysis_id)
    if job is None:
        raise HTTPException(404, 'Analysis not found')
    result = job.get('result') or {}
    if not isinstance(result, dict):
        raise HTTPException(500, 'Invalid analysis result')
    rules = result.get('detection_rules') or {}
    if not isinstance(rules, dict) or normalized_type not in rules:
        raise HTTPException(404, f'{normalized_type.upper()} rule not found')

    raw_content = rules[normalized_type]
    if isinstance(raw_content, list):
        content = '\n\n'.join(str(item) for item in raw_content)
    elif isinstance(raw_content, str):
        content = raw_content
    else:
        content = json.dumps(raw_content, indent=2, default=str)
    return normalized_type, content


def _get_rule_export_state(analysis_id: str, rule_type: str, content: str) -> dict:
    state_key = (analysis_id, rule_type)
    content_sha256 = hashlib.sha256(content.encode('utf-8')).hexdigest()
    with _rule_export_lock:
        state = _rule_export_states.get(state_key)
        if state is None or state.get('content_sha256') != content_sha256:
            state = {
                'analysis_id': analysis_id,
                'rule_type': rule_type,
                'status': 'pending_export',
                'content_sha256': content_sha256,
                'approved_by': None,
                'approved_at': None,
                'deployed_by': None,
                'deployed_at': None,
            }
            _rule_export_states[state_key] = state
        return dict(state)


def _require_rule_export_approval(
    analysis_id: str,
    rule_type: str,
    content: str,
) -> dict:
    state = _get_rule_export_state(analysis_id, rule_type, content)
    if state['status'] not in ('approved', 'deployed'):
        raise HTTPException(
            403,
            f'{rule_type.upper()} rule export requires explicit human approval',
        )
    return state


def _write_rule_temp_file(rule_type: str, content: str) -> str:
    with tempfile.NamedTemporaryFile(
        mode='w',
        encoding='utf-8',
        newline='',
        suffix=_RULE_EXTENSIONS[rule_type],
        delete=False,
    ) as temp_file:
        temp_file.write(content)
        if not content.endswith('\n'):
            temp_file.write('\n')
        return temp_file.name


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
    return templates.TemplateResponse(request, 'report_view.html', {
        'job': job,
    })


@router.get('/{analysis_id}/html/download')
async def download_report_html(request: Request, analysis_id: str):
    """Download the HTML report."""
    mgr = request.app.state.analysis_manager
    job = mgr.get_job(analysis_id)
    if job is None:
        raise HTTPException(404, 'Analysis not found')

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        'report_view.html',
        {'job': job},
        headers={
            'Content-Disposition': (
                f'attachment; filename="report-{analysis_id}.html"'
            ),
        },
    )


@router.get('/{analysis_id}/mitre')
async def get_mitre_layer(request: Request, analysis_id: str):
    """Get MITRE ATT&CK Navigator layer JSON."""
    mgr = request.app.state.analysis_manager
    job = mgr.get_job(analysis_id)
    if job is None:
        raise HTTPException(404, 'Analysis not found')

    result = job.get('result') or {}
    techniques = result.get('mitre_mapping') or result.get('mitre_techniques') or []

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
async def get_report_pdf(request: Request, analysis_id: str, download: bool = False):
    """Generate a PDF report for an IOC analysis.

    By default the PDF is served inline (Content-Disposition: inline) so
    that clicking "Print > PDF" opens the file in the browser's native PDF
    viewer/print dialog instead of silently saving it to Downloads.
    Pass ?download=1 to force a "Save As" download instead (used by the
    Export dropdown).
    """
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

    disposition_type = 'attachment' if download else 'inline'

    return FileResponse(
        path=report_path,
        media_type='application/pdf',
        filename=f'ioc-report-{analysis_id}.pdf',
        background=BackgroundTask(os.unlink, report_path),
        content_disposition_type=disposition_type,
    )


@router.get('/{analysis_id}/rules/{rule_type}/status')
async def get_rule_export_status(
    request: Request,
    analysis_id: str,
    rule_type: str,
):
    """Return the in-memory review and manual-deployment state for a rule."""
    normalized_type, content = _get_rule_content(request, analysis_id, rule_type)
    return _get_rule_export_state(analysis_id, normalized_type, content)


@router.put('/{analysis_id}/rules/{rule_type}')
async def update_rule_content(
    request: Request,
    analysis_id: str,
    rule_type: str,
    body: RuleContentUpdateRequest,
    _current_user: dict = Depends(
        require_role(['Threat Hunter', 'admin'])
    ),
):
    """Validate and persist edited detection-rule content."""
    normalized_type = str(rule_type or '').strip().lower()
    if normalized_type not in _RULE_EXTENSIONS:
        raise HTTPException(404, f'Unsupported rule type: {normalized_type}')

    validation = validate_rule(normalized_type, body.content)
    if not validation['valid']:
        raise HTTPException(
            422,
            detail={
                'message': 'Rule validation failed; content was not saved',
                'validation': validation,
            },
        )

    updated = request.app.state.analysis_manager.update_detection_rule(
        analysis_id,
        normalized_type,
        body.content,
    )
    if not updated:
        raise HTTPException(404, 'Analysis or rule not found')

    return {
        'success': True,
        'rule_type': normalized_type,
        'validation': validation,
    }


@router.post('/{analysis_id}/rules/{rule_type}/approve')
async def approve_rule_export(
    request: Request,
    analysis_id: str,
    rule_type: str,
    body: Optional[RuleApprovalRequest] = None,
    _current_user: dict = Depends(
        require_role(['Incident Responder', 'admin'])
    ),
):
    """Validate a rule and record explicit human approval for its export."""
    normalized_type, content = _get_rule_content(request, analysis_id, rule_type)
    validation = validate_rule(normalized_type, content)
    if not validation['valid']:
        raise HTTPException(
            422,
            detail={
                'message': 'Rule validation failed; export was not approved',
                'validation': validation,
            },
        )

    approved_by = (body.approved_by if body else 'unknown').strip() or 'unknown'
    state = _get_rule_export_state(analysis_id, normalized_type, content)
    with _rule_export_lock:
        stored_state = _rule_export_states[(analysis_id, normalized_type)]
        stored_state.update({
            'status': 'approved',
            'approved_by': approved_by,
            'approved_at': datetime.now(timezone.utc).isoformat(),
            'deployed_by': None,
            'deployed_at': None,
        })
        state = dict(stored_state)
    state['validation'] = validation
    return state


@router.post('/{analysis_id}/rules/{rule_type}/mark-deployed')
async def mark_rule_deployed(
    request: Request,
    analysis_id: str,
    rule_type: str,
    body: Optional[RuleDeploymentRequest] = None,
    _current_user: dict = Depends(
        require_role(['Incident Responder', 'admin'])
    ),
):
    """Record a human-reported manual deployment without calling external systems."""
    normalized_type, content = _get_rule_content(request, analysis_id, rule_type)
    _require_rule_export_approval(analysis_id, normalized_type, content)
    deployed_by = (body.deployed_by if body else 'unknown').strip() or 'unknown'
    with _rule_export_lock:
        stored_state = _rule_export_states[(analysis_id, normalized_type)]
        stored_state.update({
            'status': 'deployed',
            'deployed_by': deployed_by,
            'deployed_at': datetime.now(timezone.utc).isoformat(),
        })
        return dict(stored_state)


@router.get('/{analysis_id}/rules/{rule_type}/download')
async def download_detection_rule(
    request: Request,
    analysis_id: str,
    rule_type: str,
):
    """Serve one validated, human-approved rule as a deployable text file."""
    normalized_type, content = _get_rule_content(request, analysis_id, rule_type)
    _require_rule_export_approval(analysis_id, normalized_type, content)
    temp_path = _write_rule_temp_file(normalized_type, content)
    return FileResponse(
        path=temp_path,
        media_type=_RULE_MEDIA_TYPES.get(normalized_type, 'text/plain'),
        filename=(
            f'analysis-{analysis_id}-{normalized_type}'
            f'{_RULE_EXTENSIONS[normalized_type]}'
        ),
        background=BackgroundTask(os.unlink, temp_path),
    )


@router.get('/{analysis_id}/rules/export/zip')
async def export_detection_rules_zip(
    request: Request,
    analysis_id: str,
    rule_types: str = Query(..., description='Comma-separated rule types'),
):
    """Bundle selected, individually approved rule artifacts into a ZIP file."""
    selected_types = list(dict.fromkeys(
        item.strip().lower() for item in rule_types.split(',') if item.strip()
    ))
    if not selected_types:
        raise HTTPException(400, 'At least one rule type must be selected')

    approved_rules = []
    for selected_type in selected_types:
        normalized_type, content = _get_rule_content(
            request,
            analysis_id,
            selected_type,
        )
        _require_rule_export_approval(analysis_id, normalized_type, content)
        approved_rules.append((normalized_type, content))

    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
        temp_path = temp_file.name
    try:
        with zipfile.ZipFile(
            temp_path,
            mode='w',
            compression=zipfile.ZIP_DEFLATED,
        ) as archive:
            for normalized_type, content in approved_rules:
                archive.writestr(
                    f'{normalized_type}{_RULE_EXTENSIONS[normalized_type]}',
                    content if content.endswith('\n') else f'{content}\n',
                )
    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise

    return FileResponse(
        path=temp_path,
        media_type='application/zip',
        filename=f'analysis-{analysis_id}-detection-rules.zip',
        background=BackgroundTask(os.unlink, temp_path),
    )
