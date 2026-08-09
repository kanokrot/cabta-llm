"""
Author: Ugur Ates
Dashboard API endpoints.
"""
import json
import logging
from fastapi import APIRouter, Request

logger = logging.getLogger(__name__)
router = APIRouter()


def _flatten_job(job: dict) -> dict:
    """Flatten a raw AnalysisManager job row into the shape the
    dashboard frontend (dashboard.js) expects: ioc/filename, ioc_type,
    type, verdict, threat_score, created_at.
    """
    params = job.get('params') or {}
    if isinstance(params, str):
        try:
            params = json.loads(params)
        except (json.JSONDecodeError, TypeError):
            params = {}

    return {
        'id': job.get('id'),
        'ioc': params.get('value'),
        'filename': params.get('filename'),
        'ioc_type': params.get('ioc_type'),
        'type': job.get('analysis_type'),
        'status': job.get('status'),
        'verdict': job.get('verdict') or 'UNKNOWN',
        'threat_score': job.get('score'),
        'created_at': job.get('created_at'),
        'completed_at': job.get('completed_at'),
    }


@router.get('/stats')
async def get_stats(request: Request):
    """Get dashboard statistics."""
    mgr = request.app.state.analysis_manager
    return mgr.get_stats()


@router.get('/recent')
async def get_recent(request: Request, limit: int = 10):
    """Get recent analyses.

    Returns both ``analyses`` (flattened, frontend-ready shape) and the
    raw ``items`` for callers that want the untouched job rows.
    """
    mgr = request.app.state.analysis_manager
    jobs = mgr.list_jobs(limit=limit)
    analyses = [_flatten_job(j) for j in jobs]
    return {'analyses': analyses, 'items': jobs}


@router.get('/sources')
async def get_sources(request: Request):
    """Get TI source health status."""
    # Placeholder - would integrate with RateLimitManager in production
    sources = [
        {'name': 'VirusTotal', 'status': 'healthy', 'avg_response_ms': 450},
        {'name': 'AbuseIPDB', 'status': 'healthy', 'avg_response_ms': 320},
        {'name': 'Shodan', 'status': 'healthy', 'avg_response_ms': 580},
        {'name': 'GreyNoise', 'status': 'healthy', 'avg_response_ms': 290},
        {'name': 'AlienVault OTX', 'status': 'healthy', 'avg_response_ms': 410},
    ]
    return {'sources': sources}