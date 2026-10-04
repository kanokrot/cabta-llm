import asyncio
import io
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, UploadFile

from src.web.routes import analysis as analysis_routes


class _Manager:
    def __init__(self):
        self.jobs = []

    def create_job(self, *args, **kwargs):
        self.jobs.append((args, kwargs))
        return "file-job"


class _TempFile:
    def __init__(self):
        self.name = "temp-file.bin"
        self.data = bytearray()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def write(self, content):
        self.data.extend(content)


class _Thread:
    def __init__(self, *args, **kwargs):
        self.started = False

    def start(self):
        self.started = True


def _request(manager):
    return SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                analysis_manager=manager,
                notification_manager=None,
            )
        )
    )


def test_file_upload_at_limit_is_accepted(monkeypatch):
    manager = _Manager()
    monkeypatch.setattr(analysis_routes.tempfile, "NamedTemporaryFile", lambda **kwargs: _TempFile())
    monkeypatch.setattr(analysis_routes.threading, "Thread", _Thread)
    upload = UploadFile(
        filename="at-limit.bin",
        file=io.BytesIO(b"x" * analysis_routes.MAX_FILE_UPLOAD_BYTES),
    )

    response = asyncio.run(
        analysis_routes.analyze_file(
            _request(manager),
            upload,
            {"id": 1, "role": "admin"},
            None,
        )
    )

    assert response.analysis_id == "file-job"
    assert len(manager.jobs) == 1


def test_file_upload_over_limit_is_rejected_before_job_or_temp_file(monkeypatch):
    manager = _Manager()
    monkeypatch.setattr(
        analysis_routes.tempfile,
        "NamedTemporaryFile",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("temp file created")),
    )
    upload = UploadFile(
        filename="too-large.bin",
        file=io.BytesIO(b"x" * (analysis_routes.MAX_FILE_UPLOAD_BYTES + 1)),
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            analysis_routes.analyze_file(
                _request(manager),
                upload,
                {"id": 1, "role": "admin"},
                None,
            )
        )

    assert exc_info.value.status_code == 413
    assert exc_info.value.detail == "File exceeds 50 MB limit"
    assert manager.jobs == []
