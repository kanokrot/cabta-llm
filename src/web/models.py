"""
Author: Ugur Ates
Pydantic models for the Web API.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class IOCType(str, Enum):
    AUTO = 'auto'
    IP = 'ip'
    DOMAIN = 'domain'
    URL = 'url'
    HASH = 'hash'
    HASH_MD5 = 'hash_md5'
    HASH_SHA1 = 'hash_sha1'
    HASH_SHA256 = 'hash_sha256'
    EMAIL = 'email'
    CVE = 'cve'


class AnalysisType(str, Enum):
    IOC = 'ioc'
    FILE = 'file'
    EMAIL = 'email'


class AnalysisState(str, Enum):
    QUEUED = 'queued'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'


class Verdict(str, Enum):
    CLEAN = 'CLEAN'
    SUSPICIOUS = 'SUSPICIOUS'
    MALICIOUS = 'MALICIOUS'
    UNKNOWN = 'UNKNOWN'


class CaseStatus(str, Enum):
    OPEN = 'Open'
    INVESTIGATING = 'Investigating'
    RESOLVED = 'Resolved'
    CLOSED = 'Closed'


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class IOCRequest(BaseModel):
    value: str = Field(..., min_length=1, description="IOC value (IP, domain, hash, etc.)")
    ioc_type: Optional[IOCType] = Field(None, description="IOC type (auto-detected if omitted)")
    case_id: Optional[str] = Field(None, description="Case ID to auto-link this analysis to")


class FileUploadResponse(BaseModel):
    analysis_id: str
    filename: str
    sha256: str
    status: AnalysisState = AnalysisState.QUEUED
    message: str = 'File queued for analysis'


# ---------------------------------------------------------------------------
# Status / progress models
# ---------------------------------------------------------------------------

class AnalysisProgress(BaseModel):
    analysis_id: str
    status: AnalysisState
    progress: int = Field(0, ge=0, le=100)
    current_step: str = ''
    steps_completed: List[str] = Field(default_factory=list)
    elapsed_seconds: float = 0.0


class AnalysisStatus(BaseModel):
    analysis_id: str
    analysis_type: AnalysisType
    status: AnalysisState
    verdict: Optional[Verdict] = None
    score: Optional[int] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Dashboard models
# ---------------------------------------------------------------------------

class DashboardStats(BaseModel):
    total_analyses: int = 0
    malicious_count: int = 0
    suspicious_count: int = 0
    clean_count: int = 0
    average_score: float = 0.0
    analyses_today: int = 0
    top_ioc_types: Dict[str, int] = Field(default_factory=dict)


class SourceHealth(BaseModel):
    name: str
    status: str = 'unknown'  # healthy, degraded, down
    last_check: Optional[datetime] = None
    avg_response_ms: float = 0.0
    error_rate: float = 0.0


# ---------------------------------------------------------------------------
# Case management models
# ---------------------------------------------------------------------------

class CaseCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: str = ''
    severity: str = Field('medium', pattern='^(low|medium|high|critical)$')


class CaseNote(BaseModel):
    content: str = Field(..., min_length=1)
    author: str = 'analyst'


class CaseStatusUpdate(BaseModel):
    status: CaseStatus


class CaseOperationsUpdate(BaseModel):
    priority: Optional[str] = Field(
        None, pattern='^(low|medium|high|critical)$'
    )
    assignee: Optional[int] = Field(None, ge=1)


class IncidentReportCreate(BaseModel):
    threat_type: Optional[str] = None
    threat_description: Optional[str] = None
    attacker_ip: Optional[str] = None
    target_ip: Optional[str] = None
    affected_username: Optional[str] = None
    attack_outcome: Optional[str] = None
    occurrence_note: Optional[str] = None
    detected_at: Optional[str] = None
    detection_device: Optional[str] = None
    severity_4tier: Optional[str] = None
    findings: Optional[List[str]] = None
    analysis: Optional[List[str]] = None
    impact: Optional[List[str]] = None
    remediation: Optional[List[str]] = None
    reference: Optional[List[str]] = None


class IncidentReportUpdate(IncidentReportCreate):
    pass


class IncidentReport(BaseModel):
    case_id: str
    threat_type: str = ''
    threat_description: str = ''
    attacker_ip: str = ''
    target_ip: str = ''
    affected_username: str = ''
    attack_outcome: str = ''
    occurrence_note: str = ''
    detected_at: str = ''
    detection_device: str = ''
    severity_4tier: str = ''
    findings: List[str] = Field(default_factory=list)
    analysis: List[str] = Field(default_factory=list)
    impact: List[str] = Field(default_factory=list)
    remediation: List[str] = Field(default_factory=list)
    reference: List[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class CaseSummary(BaseModel):
    id: str
    title: str
    status: CaseStatus
    severity: str
    created_at: datetime
    analysis_count: int = 0
    note_count: int = 0
