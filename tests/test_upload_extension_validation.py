"""Server-side extension and email-content validation for upload endpoints."""

import asyncio
import io
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, UploadFile

from src.web.routes import analysis as analysis_routes
from src.web.upload_validation import (
    EMAIL_ALLOWED_EXTENSIONS,
    FILE_ALLOWED_EXTENSIONS,
    has_allowed_extension,
)


class _Manager:
    def __init__(self):
        self.jobs = []

    def create_job(self, *args, **kwargs):
        self.jobs.append((args, kwargs))
        return "upload-job"


def _request(manager):
    return SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                analysis_manager=manager,
                notification_manager=None,
                email_analyzer=None,
            )
        )
    )


def _track_temp_files(monkeypatch, tmp_path):
    created_paths = []
    real_named_temporary_file = analysis_routes.tempfile.NamedTemporaryFile

    def tracked_tempfile(**kwargs):
        temp_file = real_named_temporary_file(dir=tmp_path, **kwargs)
        created_paths.append(Path(temp_file.name))
        return temp_file

    monkeypatch.setattr(analysis_routes.tempfile, "NamedTemporaryFile", tracked_tempfile)
    return created_paths


def _invoke_upload(kind, filename, content, manager):
    upload = UploadFile(filename=filename, file=io.BytesIO(content))
    request = _request(manager)
    if kind == "email":
        return asyncio.run(
            analysis_routes.analyze_email(
                request, upload, {"id": 1, "role": "admin"}, None
            )
        )
    return asyncio.run(
        analysis_routes.analyze_file(
            request, upload, {"id": 1, "role": "admin"}, None
        )
    )


def _stub_background_worker(monkeypatch, kind):
    worker_name = "_run_email_analysis_bg" if kind == "email" else "_run_file_analysis_bg"
    monkeypatch.setattr(analysis_routes, worker_name, lambda *args: None)


_VALID_EMAIL = (
    b"From: sender@example.test\r\n"
    b"To: recipient@example.test\r\n"
    b"Subject: Report\r\n\r\n"
    b"Message body\r\n"
)


def test_shared_extension_helper_normalizes_last_suffix_and_trailing_characters():
    assert has_allowed_extension("report.EML", EMAIL_ALLOWED_EXTENSIONS)
    assert has_allowed_extension("report.eml...   ", EMAIL_ALLOWED_EXTENSIONS)
    assert has_allowed_extension("a.exe.txt", FILE_ALLOWED_EXTENSIONS)
    assert not has_allowed_extension(None, EMAIL_ALLOWED_EXTENSIONS)
    assert not has_allowed_extension("  ...", EMAIL_ALLOWED_EXTENSIONS)
    assert has_allowed_extension("hash", FILE_ALLOWED_EXTENSIONS, allow_no_suffix=True)


@pytest.mark.parametrize("filename", ["message.eml", "message.EML"])
def test_email_accepts_eml_case_insensitively(monkeypatch, tmp_path, filename):
    manager = _Manager()
    _stub_background_worker(monkeypatch, "email")
    created_paths = _track_temp_files(monkeypatch, tmp_path)

    response = _invoke_upload("email", filename, _VALID_EMAIL, manager)

    assert response["status"] == "queued"
    assert len(manager.jobs) == 1
    assert len(created_paths) == 1 and created_paths[0].suffix == ".eml"
    for path in created_paths:
        path.unlink(missing_ok=True)


@pytest.mark.parametrize("filename", ["message.txt", "message.exe", "message.pdf", "message"])
def test_email_rejects_disallowed_or_missing_extension_before_job_or_temp(
    monkeypatch, tmp_path, filename
):
    manager = _Manager()
    _stub_background_worker(monkeypatch, "email")
    created_paths = _track_temp_files(monkeypatch, tmp_path)

    with pytest.raises(HTTPException) as exc_info:
        _invoke_upload("email", filename, _VALID_EMAIL, manager)

    assert exc_info.value.status_code == 400
    assert ".eml" in exc_info.value.detail
    assert manager.jobs == []
    assert created_paths == []
    assert list(tmp_path.iterdir()) == []


def test_email_rejects_eml_without_email_headers_before_job_or_temp(
    monkeypatch, tmp_path
):
    manager = _Manager()
    _stub_background_worker(monkeypatch, "email")
    created_paths = _track_temp_files(monkeypatch, tmp_path)

    with pytest.raises(HTTPException) as exc_info:
        _invoke_upload("email", "message.eml", b"plain text with no headers", manager)

    assert exc_info.value.status_code == 400
    assert "email" in exc_info.value.detail.lower()
    assert manager.jobs == []
    assert created_paths == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("filename", ["sample.exe", "document.pdf", "document.docx", "script.ps1", "archive.zip"])
def test_file_accepts_extension_from_each_supported_category(
    monkeypatch, tmp_path, filename
):
    manager = _Manager()
    _stub_background_worker(monkeypatch, "file")
    created_paths = _track_temp_files(monkeypatch, tmp_path)

    response = _invoke_upload("file", filename, b"content need not match extension", manager)

    assert response.analysis_id == "upload-job"
    assert len(manager.jobs) == 1
    assert len(created_paths) == 1
    for path in created_paths:
        path.unlink(missing_ok=True)


def test_file_rejects_unknown_extension_before_job_or_temp(monkeypatch, tmp_path):
    manager = _Manager()
    _stub_background_worker(monkeypatch, "file")
    created_paths = _track_temp_files(monkeypatch, tmp_path)

    with pytest.raises(HTTPException) as exc_info:
        _invoke_upload("file", "sample.xyz123", b"sample", manager)

    assert exc_info.value.status_code == 400
    assert "extension" in exc_info.value.detail.lower()
    assert manager.jobs == []
    assert created_paths == []
    assert list(tmp_path.iterdir()) == []


def test_file_accepts_suffixless_hash_named_file(monkeypatch, tmp_path):
    manager = _Manager()
    _stub_background_worker(monkeypatch, "file")
    created_paths = _track_temp_files(monkeypatch, tmp_path)

    response = _invoke_upload("file", "a" * 64, b"sample", manager)

    assert response.analysis_id == "upload-job"
    assert len(manager.jobs) == 1
    assert len(created_paths) == 1 and created_paths[0].suffix == ""
    for path in created_paths:
        path.unlink(missing_ok=True)


def test_file_double_extension_uses_last_suffix(monkeypatch, tmp_path):
    manager = _Manager()
    _stub_background_worker(monkeypatch, "file")
    created_paths = _track_temp_files(monkeypatch, tmp_path)

    response = _invoke_upload("file", "a.exe.txt", b"text content", manager)

    assert response.analysis_id == "upload-job"
    assert len(manager.jobs) == 1
    assert len(created_paths) == 1 and created_paths[0].suffix == ".txt"
    for path in created_paths:
        path.unlink(missing_ok=True)
