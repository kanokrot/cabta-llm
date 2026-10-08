import re

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient

from src.web import page_auth
from src.web.app import _register_page_routes
from src.web.page_auth import PageAuthMiddleware
from src.web.security import SESSION_COOKIE_NAME
from src.web.upload_validation import FILE_ALLOWED_EXTENSIONS


def test_file_page_passes_sorted_server_allowlist_to_template(monkeypatch):
    user = {
        "id": 1,
        "email": "analyst@example.test",
        "username": "analyst",
        "role": "admin",
        "is_active": 1,
    }
    monkeypatch.setattr(page_auth, "get_current_user", lambda token, request=None: user)

    captured_contexts = []
    original_template_response = Jinja2Templates.TemplateResponse

    def capture_file_page_context(self, *args, **kwargs):
        if len(args) >= 3 and args[1] == "analysis_file.html":
            captured_contexts.append(args[2])
        return original_template_response(self, *args, **kwargs)

    monkeypatch.setattr(Jinja2Templates, "TemplateResponse", capture_file_page_context)

    app = FastAPI()
    app.add_middleware(PageAuthMiddleware)
    _register_page_routes(app)

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, "test-token")
        response = client.get("/analysis/file")

    assert response.status_code == 200
    assert len(captured_contexts) == 1
    assert captured_contexts[0]["allowed_extensions"] == sorted(FILE_ALLOWED_EXTENSIONS)

    allowlist_match = re.search(
        r'<ul id="allowedFileExtensions"[^>]*>(.*?)</ul>', response.text, re.DOTALL
    )
    assert allowlist_match is not None
    rendered_extensions = re.findall(r"<li><code>(\.[^<]+)</code></li>", allowlist_match.group(1))
    assert set(rendered_extensions) == FILE_ALLOWED_EXTENSIONS
    assert {".exe", ".pdf", ".docx", ".ps1", ".zip"}.issubset(rendered_extensions)
    assert "accept=" not in response.text
    assert "new Set(" in response.text
    assert "if (!suffix || ALLOWED_FILE_EXTENSIONS.has(suffix))" in response.text
    assert "validateUploadExtension(e.dataTransfer.files[0])" in response.text
    assert "validateUploadExtension(fileInput.files[0])" in response.text
