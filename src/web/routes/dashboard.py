"""
Author: Ugur Ates
Dashboard API endpoints.
"""
import logging
from fastapi import APIRouter, Depends, Request

from ..auth import TEAM_LEAD, get_current_user, get_user_ids_by_role, require_role
from ..oversight import record_cross_user_read
from ..visibility import serialize_dashboard_job, serialize_dashboard_sources, serialize_dashboard_stats

logger = logging.getLogger(__name__)
router = APIRouter(
    dependencies=[
        Depends(require_role([
            'SOC Analyst Tier 1-2',
            'Incident Responder',
            'Threat Hunter',
            TEAM_LEAD,
            'admin',
        ]))
    ]
)


def _owner_scope(current_user: dict):
    return None if current_user.get('role') == 'admin' else current_user['id']


def _flatten_job(job: dict, role: str = 'SOC Analyst Tier 1-2') -> dict:
    """Flatten a raw AnalysisManager job row into the shape the
    dashboard frontend (dashboard.js) expects: ioc/filename, ioc_type,
    type, verdict, threat_score, created_at.
    """
    return serialize_dashboard_job(job, role=role)


@router.get('/stats')
async def get_stats(request: Request, current_user: dict = Depends(get_current_user)):
    """Get dashboard statistics."""
    mgr = request.app.state.analysis_manager
    return serialize_dashboard_stats(mgr.get_stats(), current_user['role'])


@router.get('/recent')
async def get_recent(
    request: Request,
    limit: int = 10,
    current_user: dict = Depends(get_current_user),
):
    """Get recent analyses.

    Returns the same trimmed representation for SOC Analysts and Team Leads.
    """
    mgr = request.app.state.analysis_manager
    if current_user.get('role') == TEAM_LEAD:
        jobs = mgr.list_jobs(
            limit=limit,
            user_ids=get_user_ids_by_role('SOC Analyst Tier 1-2'),
        )
        for job in jobs:
            if job.get('user_id') != current_user['id']:
                record_cross_user_read(
                    request,
                    actor_user_id=current_user['id'],
                    actor_role=TEAM_LEAD,
                    target_user_id=job['user_id'],
                    resource_type='dashboard',
                    resource_id=job['id'],
                )
    else:
        jobs = mgr.list_jobs(
            limit=limit,
            user_id=_owner_scope(current_user),
        )
    analyses = [_flatten_job(j, role=current_user['role']) for j in jobs]
    return {'analyses': analyses, 'items': analyses}


@router.get('/sources')
async def get_sources(request: Request, current_user: dict = Depends(get_current_user)):
    """Get TI source health status."""
    # Placeholder - would integrate with RateLimitManager in production
    sources = [
        {'name': 'VirusTotal', 'status': 'healthy', 'avg_response_ms': 450},
        {'name': 'AbuseIPDB', 'status': 'healthy', 'avg_response_ms': 320},
        {'name': 'Shodan', 'status': 'healthy', 'avg_response_ms': 580},
        {'name': 'GreyNoise', 'status': 'healthy', 'avg_response_ms': 290},
        {'name': 'AlienVault OTX', 'status': 'healthy', 'avg_response_ms': 410},
    ]
    return {'sources': serialize_dashboard_sources(sources, current_user['role'])}
