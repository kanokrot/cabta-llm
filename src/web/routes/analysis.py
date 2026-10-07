"""
Author: Ugur Ates
Analysis API endpoints.
"""

import asyncio
import csv
import hashlib
import inspect
import logging
import tempfile
import threading
from pathlib import Path
from typing import Literal, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse

from ..models import (
    AnalysisState,
    AnalysisStatus,
    FileUploadResponse,
    IOCRequest,
)
from ..auth import TEAM_LEAD, get_current_user, get_user_ids_by_role, require_role
from ..email_capabilities import get_email_capabilities
from ..oversight import record_cross_user_read
from ..visibility import serialize_analysis_job, serialize_status

logger = logging.getLogger(__name__)
MAX_FILE_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_EMAIL_UPLOAD_BYTES = 25 * 1024 * 1024
HISTORY_ADMIN_ROLE = "admin"
HISTORY_ANALYST_ROLE = "SOC Analyst Tier 1-2"
HISTORY_EXPORT_CAP = 10_000
CSV_DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
router = APIRouter(
    dependencies=[
        Depends(require_role([
            "SOC Analyst Tier 1-2", "Incident Responder", "Threat Hunter",
            TEAM_LEAD, "admin",
        ]))
    ]
)


def _load_config():
    """Load application config for analyzer initialization."""
    try:
        from src.utils.config import load_config
        return load_config()
    except Exception:
        return {}


def _get_readable_job(request: Request, analysis_id: str, current_user: dict):
    """Apply owner/admin scope and Team Lead's implicit single-team scope."""
    mgr = request.app.state.analysis_manager
    role = current_user.get("role")
    if role == "admin":
        return mgr.get_job(analysis_id)
    if role != TEAM_LEAD:
        return mgr.get_job(analysis_id, user_id=current_user["id"])

    job = mgr.get_job(analysis_id)
    if job is None or job.get("user_id") not in get_user_ids_by_role("SOC Analyst Tier 1-2"):
        return None
    if job.get("user_id") != current_user["id"]:
        record_cross_user_read(
            request,
            actor_user_id=current_user["id"],
            actor_role=TEAM_LEAD,
            target_user_id=job["user_id"],
            resource_type="analysis",
            resource_id=analysis_id,
        )
    return job


def _history_scope(current_user: dict) -> dict:
    role = current_user.get("role")
    if role == HISTORY_ADMIN_ROLE:
        return {}
    if role == TEAM_LEAD:
        return {"user_ids": get_user_ids_by_role(HISTORY_ANALYST_ROLE)}
    return {"user_id": current_user["id"]}


def _audit_team_lead_history_reads(
    request: Request,
    current_user: dict,
    jobs: list[dict],
) -> None:
    if current_user.get("role") != TEAM_LEAD:
        return
    for job in jobs:
        if job.get("user_id") != current_user["id"]:
            record_cross_user_read(
                request,
                actor_user_id=current_user["id"],
                actor_role=TEAM_LEAD,
                target_user_id=job["user_id"],
                resource_type="analysis",
                resource_id=job["id"],
            )


def sanitize_csv_text(value) -> str:
    """Preserve text while neutralizing spreadsheet formula prefixes."""
    text = "" if value is None else str(value)
    first_non_whitespace = 0
    while (
        first_non_whitespace < len(text)
        and text[first_non_whitespace].isspace()
        and text[first_non_whitespace] not in ("\t", "\r")
    ):
        first_non_whitespace += 1
    if (
        text.startswith(CSV_DANGEROUS_PREFIXES)
        or (
            first_non_whitespace < len(text)
            and text[first_non_whitespace] in CSV_DANGEROUS_PREFIXES
        )
    ):
        return "'" + text
    return text


def _history_csv_row(job: dict, role: str) -> list:
    item = serialize_analysis_job(job, role=role)
    target = item.get("ioc") or item.get("filename") or item.get("id") or ""
    score = item.get("score")
    return [
        sanitize_csv_text(item.get("id")),
        sanitize_csv_text(item.get("analysis_type")),
        sanitize_csv_text(target),
        sanitize_csv_text(item.get("verdict")),
        sanitize_csv_text(job.get("verdict_group")),
        "" if score is None else score,
        sanitize_csv_text(item.get("status")),
        sanitize_csv_text(item.get("created_at")),
        sanitize_csv_text(item.get("completed_at")),
    ]


async def _read_email_upload_with_limit(file: UploadFile) -> bytes:
    """Read an email upload incrementally and reject oversized content."""
    chunks = []
    total = 0
    chunk_size = 1024 * 1024
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_EMAIL_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail='Email file exceeds 25 MB limit')
        chunks.append(chunk)
    return b''.join(chunks)


async def _read_file_upload_with_limit(file: UploadFile) -> bytes:
    """Read a file upload incrementally and reject oversized content."""
    chunks = []
    total = 0
    chunk_size = 1024 * 1024
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_FILE_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail='File exceeds 50 MB limit')
        chunks.append(chunk)
    return b''.join(chunks)


# ------------------------------------------------------------------
# Background analysis helpers
# ------------------------------------------------------------------

def _step_manifest(step_definitions):
    return [
        {'key': key, 'label': label, 'state': 'pending'}
        for key, label in step_definitions
    ]


def _step_callback(mgr, job_id, step_definitions):
    steps = _step_manifest(step_definitions)
    by_key = {step['key']: step for step in steps}

    def on_step(step_key, state):
        step = by_key.get(step_key)
        if step is None:
            return
        step['state'] = state
        done = sum(
            item['state'] in {'completed', 'skipped'} for item in steps
        )
        progress = round(100 * done / len(steps)) if steps else 0
        update_steps = getattr(mgr, 'update_steps', None)
        if callable(update_steps):
            update_steps(
                job_id,
                steps,
                progress,
                current_step=step['label'],
            )

    return steps, on_step


async def _analyze_with_steps(analyzer, path, job_id, user_id, on_step):
    analyze = analyzer.analyze
    parameters = inspect.signature(analyze).parameters.values()
    accepts_callback = (
        'on_step' in inspect.signature(analyze).parameters
        or any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters)
    )
    kwargs = {'analysis_id': job_id, 'user_id': user_id}
    if accepts_callback:
        kwargs['on_step'] = on_step
    return await analyze(path, **kwargs)

def _run_email_analysis_bg(
    mgr,
    job_id: str,
    eml_path: str,
    user_id: int = None,
    shared_email_analyzer=None,
) -> None:
    """Run email analysis in a background thread."""
    try:
        from src.tools.email_analyzer import EmailAnalyzer, EMAIL_ANALYSIS_STEPS
        config = _load_config()
        analyzer = EmailAnalyzer(config)
        if shared_email_analyzer is not None:
            analyzer.ioc_investigator = getattr(shared_email_analyzer, 'ioc_investigator', None)
            analyzer.file_analyzer = getattr(shared_email_analyzer, 'file_analyzer', None)

        _, on_step = _step_callback(mgr, job_id, EMAIL_ANALYSIS_STEPS)

        result = asyncio.run(_analyze_with_steps(
            analyzer, eml_path, job_id, user_id, on_step,
        ))

        verdict = result.get('verdict', 'UNKNOWN')
        score = result.get('composite_score', result.get('base_phishing_score', 0))

        mgr.complete_job(job_id, result, verdict=verdict, score=score)

    except Exception as e:
        logger.error(f"[EMAIL-BG] Analysis failed for {job_id}: {e}")
        mgr.fail_job(job_id, str(e))


def _run_file_analysis_bg(
    mgr, job_id: str, file_path: str, notification_manager=None, user_id: int = None,
) -> None:
    """Run file/malware analysis in a background thread."""
    try:
        from src.tools.malware_analyzer import MalwareAnalyzer, MALWARE_ANALYSIS_STEPS
        config = _load_config()
        analyzer = MalwareAnalyzer(config)

        _, on_step = _step_callback(mgr, job_id, MALWARE_ANALYSIS_STEPS)

        result = asyncio.run(_analyze_with_steps(
            analyzer, file_path, job_id, user_id, on_step,
        ))

        verdict = result.get('verdict', 'UNKNOWN')
        score = result.get('composite_score', result.get('threat_score', 0))

        mgr.complete_job(job_id, result, verdict=verdict, score=score)

    except Exception as e:
        logger.error(f"[FILE-BG] Analysis failed for {job_id}: {e}")
        mgr.fail_job(job_id, str(e))


def _run_ioc_analysis_bg(
    mgr, job_id: str, value: str, ioc_type: str, case_store=None,
    case_id: str = None, notification_manager=None, user_id: int = None,
) -> None:
    """Run IOC investigation in a background thread."""
    try:
        mgr.update_progress(job_id, 5, 'Loading IOC investigator...')
        from src.tools.ioc_investigator import IOCInvestigator
        config = _load_config()
        investigator = IOCInvestigator(config, notification_manager=notification_manager)

        mgr.update_progress(job_id, 10, f'Investigating {value}...')

        # Register a progress callback so each source query is reported
        _source_count = [0]

        def _on_source_progress(source_name, status):
            _source_count[0] += 1
            pct = min(10 + int((_source_count[0] / 25) * 75), 85)
            mgr.update_progress(job_id, pct, f'Querying {source_name}...')

        # Set callback if investigator supports it
        if hasattr(investigator, 'set_progress_callback'):
            investigator.set_progress_callback(_on_source_progress)

        result = asyncio.run(
            investigator.investigate(
                value, analysis_id=job_id, user_id=user_id,
            )
        )

        # User-owned lookups are enrichment only and run after investigation
        # (and therefore after all scoring, coverage, source accounting, and LLM work).
        try:
            from ..user_api_keys import cross_check_ioc

            result["extra_evidence"] = asyncio.run(
                cross_check_ioc(
                    value,
                    result.get("ioc_type") or ioc_type,
                    user_id,
                )
            )
        except Exception:
            # Keep the investigation result intact and expose only generic statuses.
            result["extra_evidence"] = [
                {"source": source, "status": "unavailable"}
                for source in ("virustotal", "abuseipdb", "otx")
            ]

        verdict = result.get('verdict', 'UNKNOWN')
        score = result.get('threat_score', 0)

        mgr.update_progress(job_id, 90, 'Generating detection rules...')
        mgr.update_progress(job_id, 95, 'Saving results...')
        mgr.complete_job(job_id, result, verdict=verdict, score=score)

        if case_id and case_store:
            try:
                case_store.link_analysis(case_id, job_id)
            except Exception as link_exc:
                logger.warning(f"[IOC-BG] Failed to auto-link analysis {job_id} to case {case_id}: {link_exc}")

    except Exception as e:
        logger.error(f"[IOC-BG] Analysis failed for {job_id}: {e}")
        mgr.fail_job(job_id, str(e))


@router.post('/ioc')
async def analyze_ioc(
    request: Request,
    payload: IOCRequest,
    current_user: dict = Depends(get_current_user),
    _write_access: dict = Depends(
        require_role(["SOC Analyst Tier 1-2", "admin"])
    ),
):
    """Start IOC investigation."""
    mgr = request.app.state.analysis_manager
    case_store = request.app.state.case_store
    ioc_type = payload.ioc_type.value if payload.ioc_type else 'auto'
    job_id = mgr.create_job(
        'ioc',
        {
            'value': payload.value,
            'ioc_type': ioc_type,
        },
        user_id=current_user['id'],
    )

    # Launch background analysis
    t = threading.Thread(
        target=_run_ioc_analysis_bg,
        args=(mgr, job_id, payload.value, ioc_type, case_store, payload.case_id,
              request.app.state.notification_manager, current_user['id']),
        daemon=True,
    )
    t.start()

    return {
        'analysis_id': job_id,
        'status': 'queued',
        'message': f'IOC analysis queued for {payload.value}',
    }


@router.post('/file')
async def analyze_file(
    request: Request,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
    _write_access: dict = Depends(
        require_role(["SOC Analyst Tier 1-2", "admin"])
    ),
):
    """Upload and analyze a file."""
    from src.tools.malware_analyzer import MALWARE_ANALYSIS_STEPS
    mgr = request.app.state.analysis_manager

    # Read file content
    content = await _read_file_upload_with_limit(file)
    sha256 = hashlib.sha256(content).hexdigest()

    # Save to temp
    suffix = Path(file.filename or 'unknown').suffix
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    job_id = mgr.create_job(
        'file',
        {
            'filename': file.filename,
            'sha256': sha256,
            'size': len(content),
            'temp_path': tmp_path,
            '_analysis_steps': _step_manifest(MALWARE_ANALYSIS_STEPS),
        },
        user_id=current_user['id'],
    )

    # Launch background analysis
    t = threading.Thread(
        target=_run_file_analysis_bg,
        args=(mgr, job_id, tmp_path, request.app.state.notification_manager,
              current_user['id']),
        daemon=True,
    )
    t.start()

    return FileUploadResponse(
        analysis_id=job_id,
        filename=file.filename or 'unknown',
        sha256=sha256,
    )


@router.post('/email')
async def analyze_email(
    request: Request,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
    _write_access: dict = Depends(
        require_role(["SOC Analyst Tier 1-2", "admin"])
    ),
):
    """Upload and analyze an email (.eml)."""
    from src.tools.email_analyzer import EMAIL_ANALYSIS_STEPS
    mgr = request.app.state.analysis_manager

    content = await _read_email_upload_with_limit(file)
    sha256 = hashlib.sha256(content).hexdigest()

    with tempfile.NamedTemporaryFile(delete=False, suffix='.eml') as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    job_id = mgr.create_job(
        'email',
        {
            'filename': file.filename,
            'sha256': sha256,
            'temp_path': tmp_path,
            '_analysis_steps': _step_manifest(EMAIL_ANALYSIS_STEPS),
        },
        user_id=current_user['id'],
    )

    # Launch background email analysis
    t = threading.Thread(
        target=_run_email_analysis_bg,
        args=(
            mgr,
            job_id,
            tmp_path,
            current_user['id'],
            getattr(request.app.state, 'email_analyzer', None),
        ),
        daemon=True,
    )
    t.start()

    return {
        'analysis_id': job_id,
        'status': 'queued',
        'message': f'Email analysis queued: {file.filename}',
    }


@router.get('/email/capabilities')
async def email_capabilities(
    request: Request,
    refresh: bool = False,
    current_user: dict = Depends(get_current_user),
):
    """Return cached status for the email-analysis capabilities."""
    is_admin = current_user.get('role') == 'admin'
    if refresh and not is_admin:
        raise HTTPException(status_code=403, detail='Admin role required for refresh')
    analyzer = getattr(request.app.state, 'email_analyzer', None)
    return get_email_capabilities(
        analyzer=analyzer,
        refresh=refresh,
        include_reason=is_admin,
    )


@router.get('/file/capabilities')
async def file_capabilities(
    request: Request,
    refresh: bool = False,
    current_user: dict = Depends(get_current_user),
):
    """Return cached status for the file-analysis capabilities."""
    from ..file_capabilities import get_file_capabilities

    is_admin = current_user.get('role') == 'admin'
    if refresh and not is_admin:
        raise HTTPException(status_code=403, detail='Admin role required for refresh')
    analyzer = getattr(request.app.state, 'malware_analyzer', None)
    return get_file_capabilities(
        analyzer=analyzer,
        refresh=refresh,
        include_reason=is_admin,
    )


@router.get('/{analysis_id}')
async def get_analysis(
    request: Request,
    analysis_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get the role-scoped, sanitized analysis result."""
    job = _get_readable_job(request, analysis_id, current_user)
    if job is None:
        raise HTTPException(status_code=404, detail='Analysis not found')
    return serialize_analysis_job(job, role=current_user['role'])


@router.get('/history/summary')
async def get_history_summary(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Get role-scoped analysis history summary counts."""
    mgr = request.app.state.analysis_manager
    return mgr.get_history_summary(**_history_scope(current_user))


@router.get('/{analysis_id}/status')
async def get_analysis_status(
    request: Request,
    analysis_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get analysis progress."""
    job = _get_readable_job(request, analysis_id, current_user)
    if job is None:
        raise HTTPException(status_code=404, detail='Analysis not found')
    return serialize_status(job, role=current_user['role'])


@router.get('/history/')
async def get_history(
    request: Request,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = None,
    group: Optional[Literal[
        "malicious", "suspicious", "clean", "unknown", "failed", "in_progress",
    ]] = Query(default=None),
    analysis_type: Optional[Literal["ioc", "file", "email"]] = Query(
        default=None, alias="type"
    ),
    q: Optional[str] = Query(default=None, max_length=200),
    range_name: Literal["all", "24h", "7d"] = Query(default="all", alias="range"),
    sort: Literal["date", "score", "verdict", "type", "status"] = Query(
        default="date"
    ),
    order: Literal["asc", "desc"] = Query(default="desc"),
    current_user: dict = Depends(get_current_user),
):
    """Get analysis history."""
    mgr = request.app.state.analysis_manager
    role = current_user.get("role")
    filters = {
        "limit": limit,
        "offset": offset,
        "status": status,
        "group": group,
        "analysis_type": analysis_type,
        "q": q,
        "range_name": range_name,
        "sort": sort,
        "order": order,
    }
    page = mgr.list_history_page(**filters, **_history_scope(current_user))
    _audit_team_lead_history_reads(request, current_user, page["items"])

    items = []
    for job in page["items"]:
        item = serialize_analysis_job(job, role=role)
        item["verdict_group"] = job["verdict_group"]
        items.append(item)

    return {
        'items': items,
        'total': page["total"],
        'limit': limit,
        'offset': offset,
    }


@router.get('/history/export')
async def export_history(
    request: Request,
    status: Optional[str] = None,
    group: Optional[Literal[
        "malicious", "suspicious", "clean", "unknown", "failed", "in_progress",
    ]] = Query(default=None),
    analysis_type: Optional[Literal["ioc", "file", "email"]] = Query(
        default=None, alias="type"
    ),
    q: Optional[str] = Query(default=None, max_length=200),
    range_name: Literal["all", "24h", "7d"] = Query(default="all", alias="range"),
    sort: Literal["date", "score", "verdict", "type", "status"] = Query(
        default="date"
    ),
    order: Literal["asc", "desc"] = Query(default="desc"),
    current_user: dict = Depends(get_current_user),
):
    """Stream a role-scoped, filtered history CSV."""
    mgr = request.app.state.analysis_manager
    role = current_user.get("role")
    filters = {
        "status": status,
        "group": group,
        "analysis_type": analysis_type,
        "q": q,
        "range_name": range_name,
        "sort": sort,
        "order": order,
    }
    jobs = mgr.export_history_rows(
        cap=HISTORY_EXPORT_CAP,
        **filters,
        **_history_scope(current_user),
    )
    if len(jobs) > HISTORY_EXPORT_CAP:
        raise HTTPException(
            status_code=413,
            detail=f"History export exceeds the {HISTORY_EXPORT_CAP}-row limit",
        )

    _audit_team_lead_history_reads(request, current_user, jobs)

    columns = [
        "id", "type", "target", "verdict", "verdict_group",
        "score", "status", "created_at", "completed_at",
    ]

    class _CsvBuffer:
        def write(self, value: str) -> str:
            return value

    def generate():
        writer = csv.writer(_CsvBuffer(), lineterminator="\r\n")
        yield "\ufeff"
        yield writer.writerow(columns)
        for job in jobs:
            yield writer.writerow(_history_csv_row(job, role))

    return StreamingResponse(
        generate(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="analysis-history.csv"',
        },
    )
