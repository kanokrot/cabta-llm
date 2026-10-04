import asyncio
import io
import time
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, UploadFile

from src.tools.email_analyzer import EmailAnalyzer
from src.web import visibility
from src.web.routes import analysis as analysis_routes


def _config():
    return {
        "analysis": {"enable_rag": False, "enable_llm": False},
        "api_keys": {},
        "timeouts": {"api_timeout": 1},
    }


def _safe_message(with_attachment=True, with_url=False):
    message = EmailMessage()
    message["From"] = "analyst@example.com"
    message["To"] = "soc@example.org"
    message["Subject"] = "Safe capability test"
    message["Received-SPF"] = "pass"
    message["Authentication-Results"] = "example.org; dkim=pass; dmarc=pass"
    body = "This is a safe test."
    if with_url:
        body += " Visit https://example.com/notice"
    message.set_content(body)
    if with_attachment:
        message.add_attachment(
            b"harmless attachment",
            maintype="application",
            subtype="octet-stream",
            filename="safe.txt",
        )
    return message


def _write_eml(tmp_path, with_attachment=True, with_url=False):
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "safe.eml"
    path.write_bytes(_safe_message(with_attachment, with_url).as_bytes())
    return path


class FakeInvestigator:
    def __init__(self, result=None, delay=0):
        self.calls = []
        self.result = result or {"verdict": "CLEAN", "threat_score": 0}
        self.delay = delay

    async def investigate(self, value):
        self.calls.append(value)
        if self.delay:
            await asyncio.sleep(self.delay)
        return {"ioc": value, **self.result}


class FakeFileAnalyzer:
    def __init__(self, result=None, delay=0, error=False):
        self.paths = []
        self.result = result or {"verdict": "CLEAN", "threat_score": 0}
        self.delay = delay
        self.error = error

    async def analyze(self, path):
        self.paths.append(path)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise RuntimeError("fake analyzer failure")
        return dict(self.result)


class FakeManager:
    def __init__(self):
        self.completed = []
        self.failed = []

    def update_progress(self, *args):
        return None

    def complete_job(self, *args, **kwargs):
        self.completed.append((args, kwargs))

    def fail_job(self, *args):
        self.failed.append(args)


def _run_analyze(analyzer, path):
    return asyncio.run(analyzer.analyze(str(path)))


def test_route_worker_copies_shared_cross_tool_instances(monkeypatch, tmp_path):
    captured = {}

    class JobAnalyzer:
        def __init__(self, config):
            self.ioc_investigator = None
            self.file_analyzer = None

        async def analyze(self, path, analysis_id=None, user_id=None):
            captured["refs"] = (self.ioc_investigator, self.file_analyzer)
            return {"verdict": "CLEAN", "composite_score": 0}

    shared_ioc = object()
    shared_file = object()
    shared = SimpleNamespace(ioc_investigator=shared_ioc, file_analyzer=shared_file)
    monkeypatch.setattr("src.tools.email_analyzer.EmailAnalyzer", JobAnalyzer)

    manager = FakeManager()
    analysis_routes._run_email_analysis_bg(
        manager, "job-1", str(_write_eml(tmp_path)), 1, shared
    )

    assert captured["refs"] == (shared_ioc, shared_file)
    assert not manager.failed


def test_worker_without_shared_analyzer_keeps_disconnected_behavior(monkeypatch, tmp_path):
    captured = {}

    class JobAnalyzer:
        def __init__(self, config):
            self.ioc_investigator = None
            self.file_analyzer = None

        async def analyze(self, path, analysis_id=None, user_id=None):
            captured["refs"] = (self.ioc_investigator, self.file_analyzer)
            return {
                "verdict": "CLEAN",
                "composite_score": 0,
                "capability_errors": [
                    {"capability": "ioc_investigator", "status": "not_connected"},
                    {"capability": "file_analyzer", "status": "not_connected"},
                ],
            }

    monkeypatch.setattr("src.tools.email_analyzer.EmailAnalyzer", JobAnalyzer)
    manager = FakeManager()
    analysis_routes._run_email_analysis_bg(
        manager, "job-2", str(_write_eml(tmp_path)), 1, None
    )

    assert captured["refs"] == (None, None)
    assert not manager.failed


def test_wired_fake_tools_produce_ioc_and_attachment_results(tmp_path):
    analyzer = EmailAnalyzer(_config())
    analyzer.ioc_investigator = FakeInvestigator()
    analyzer.file_analyzer = FakeFileAnalyzer()

    result = _run_analyze(analyzer, _write_eml(tmp_path, with_url=True))

    assert result["ioc_analysis"]["total_iocs"] > 0
    assert result["attachment_analysis"]["total_attachments"] == 1
    assert not any(item["status"] == "not_connected" for item in result["capability_errors"])


def test_missing_tools_are_reported_without_changing_local_result(tmp_path):
    analyzer = EmailAnalyzer(_config())
    result = _run_analyze(analyzer, _write_eml(tmp_path))

    statuses = {item["capability"]: item["status"] for item in result["capability_errors"]}
    assert statuses["ioc_investigator"] == "not_connected"
    assert statuses["file_analyzer"] == "not_connected"
    assert result["composite_score"] == 17
    assert result["base_phishing_score"] == 25


def test_malicious_ioc_and_attachment_use_existing_formula(tmp_path):
    ioc_analyzer = EmailAnalyzer(_config())
    ioc_analyzer.ioc_investigator = FakeInvestigator({"verdict": "MALICIOUS", "threat_score": 100})
    ioc_result = _run_analyze(ioc_analyzer, _write_eml(tmp_path / "ioc", with_url=True))
    base = ioc_result["base_phishing_score"]
    assert ioc_result["composite_score"] == int(max(base * 0.70 + 20, base * 0.65))

    attachment_analyzer = EmailAnalyzer(_config())
    attachment_analyzer.file_analyzer = FakeFileAnalyzer(
        {"verdict": "MALICIOUS", "threat_score": 100}
    )
    attachment_result = _run_analyze(attachment_analyzer, _write_eml(tmp_path / "attachment"))
    base = attachment_result["base_phishing_score"]
    assert attachment_result["composite_score"] == int(max(base * 0.70 + 10, base * 0.65))


def test_attachment_temp_file_cleanup_success_and_invalid_suffix(tmp_path):
    message = _safe_message()
    fake = FakeFileAnalyzer()
    analyzer = EmailAnalyzer(_config())
    analyzer.file_analyzer = fake
    errors = []
    result = asyncio.run(analyzer._analyze_attachments(
        message,
        {"attachments": [{"filename": "a.txt:x"}]},
        errors,
    ))

    assert result == []
    assert not errors
    assert len(fake.paths) == 0

    message = EmailMessage()
    message.set_content("safe")
    message.add_attachment(b"payload", maintype="application", subtype="octet-stream", filename="a.txt:x")
    fake = FakeFileAnalyzer()
    analyzer.file_analyzer = fake
    errors = []
    result = asyncio.run(analyzer._analyze_attachments(
        message,
        {"attachments": [{"filename": "a.txt:x"}]},
        errors,
    ))
    assert len(result) == 1
    assert fake.paths
    assert all(":" not in Path(path).name for path in fake.paths)
    assert all(not Path(path).exists() for path in fake.paths)


def test_attachment_temp_file_cleanup_on_exception():
    message = EmailMessage()
    message.set_content("safe")
    message.add_attachment(b"payload", maintype="application", subtype="octet-stream", filename="a.txt")
    fake = FakeFileAnalyzer(error=True)
    analyzer = EmailAnalyzer(_config())
    analyzer.file_analyzer = fake
    errors = []

    result = asyncio.run(analyzer._analyze_attachments(
        message,
        {"attachments": [{"filename": "a.txt"}]},
        errors,
    ))

    assert result == []
    assert errors[0]["status"] == "error"
    assert all(not Path(path).exists() for path in fake.paths)


def test_ioc_deduplicates_and_keeps_caps():
    fake = FakeInvestigator()
    analyzer = EmailAnalyzer(_config())
    analyzer.ioc_investigator = fake
    email_data = {
        "urls": [f"https://example.com/{i}" for i in range(5)] + ["https://example.com/0"],
        "ips": ["192.0.2.1", "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"],
        "domains": ["one.example", "one.example", "two.example", "three.example", "four.example"],
    }
    results = asyncio.run(analyzer._investigate_iocs(email_data, []))

    assert len(results) == 11
    assert len(fake.calls) == len(set(fake.calls))
    assert fake.calls[:5] == [f"https://example.com/{i}" for i in range(5)]
    assert fake.calls[5:8] == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    assert fake.calls[8:] == ["one.example", "two.example", "three.example"]


def test_ioc_deadline_keeps_partial_results(monkeypatch):
    fake = FakeInvestigator(delay=0.2)
    analyzer = EmailAnalyzer(_config())
    analyzer.ioc_investigator = fake
    monkeypatch.setattr("src.tools.email_analyzer._IOC_STAGE_TIMEOUT_SECONDS", 0.05)
    errors = []

    results = asyncio.run(analyzer._investigate_iocs(
        {"urls": ["https://example.com/slow"], "ips": [], "domains": []},
        errors,
    ))

    assert results == []
    assert errors[0]["status"] == "timeout"


def test_three_email_jobs_do_not_deadlock():
    async def run_jobs():
        analyzers = []
        for _ in range(3):
            analyzer = EmailAnalyzer(_config())
            analyzer.ioc_investigator = FakeInvestigator()
            analyzers.append(analyzer)
        return await asyncio.wait_for(
            asyncio.gather(*[
                analyzer._investigate_iocs(
                    {"urls": ["https://example.com"], "ips": [], "domains": []},
                    [],
                )
                for analyzer in analyzers
            ]),
            timeout=3,
        )

    results = asyncio.run(run_jobs())
    assert all(len(result) == 1 for result in results)


def test_email_upload_over_25mb_is_rejected_before_temp_file(monkeypatch):
    class Manager:
        def create_job(self, *args, **kwargs):
            raise AssertionError("job must not be created")

    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(analysis_manager=Manager(), email_analyzer=None)
        )
    )
    upload = UploadFile(
        filename="too-large.eml",
        file=io.BytesIO(b"x" * (analysis_routes.MAX_EMAIL_UPLOAD_BYTES + 1)),
    )
    monkeypatch.setattr(
        analysis_routes.tempfile,
        "NamedTemporaryFile",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("temp file created")),
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            analysis_routes.analyze_email(
                request,
                upload,
                {"id": 1, "role": "admin"},
                None,
            )
        )
    assert exc_info.value.status_code == 413


def test_capability_errors_are_serialized_without_internal_names():
    job = {
        "id": "email-1",
        "analysis_type": "email",
        "status": "completed",
        "progress": 100,
        "current_step": "done",
        "created_at": "2026-01-01T00:00:00+00:00",
        "result": {
            "capability_errors": [
                {
                    "capability": "ioc_investigator",
                    "status": "not_connected",
                    "message": "IOC investigation is not connected for this email.",
                }
            ]
        },
    }
    serialized = visibility.serialize_analysis_job(job, role="admin")

    assert serialized["capability_errors"][0]["status"] == "not_connected"
    assert "config.yaml" not in str(serialized)
    assert "api_key" not in str(serialized).lower()
