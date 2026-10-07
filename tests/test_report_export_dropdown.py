from pathlib import Path
import re

from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates

from src.web.analysis_manager import AnalysisManager
from src.web.routes import reports


def _render_report(tmp_path, query_string=""):
    app = FastAPI()
    from src.web.auth import get_current_user
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 1,
        "email": "admin@example.test",
        "username": "admin",
        "role": "admin",
        "is_active": 1,
    }
    app.state.analysis_manager = AnalysisManager(
        db_path=str(tmp_path / "analysis_jobs.db")
    )
    app.state.templates = Jinja2Templates(
        directory=str(Path(__file__).resolve().parents[1] / "templates")
    )
    app.include_router(reports.router, prefix="/api/reports")

    job_id = app.state.analysis_manager.create_job("ioc", {"value": "test"})
    app.state.analysis_manager.complete_job(
        job_id,
        {"verdict": "CLEAN"},
        verdict="CLEAN",
        score=0,
    )

    response = TestClient(app).get(
        f"/api/reports/{job_id}/html{query_string}"
    )
    assert response.status_code == 200
    return job_id, response.text


def test_report_actions_render_export_and_print_dropdowns(tmp_path):
    job_id, html = _render_report(tmp_path)

    assert 'id="reportToolbar"' in html
    assert 'id="btnCopyReportLink"' in html
    assert 'aria-label="Breadcrumb"' in html
    assert f'title="{job_id}"' in html
    assert f'#{job_id[:8]}' in html

    assert 'id="reportExportDropdown"' in html
    assert 'id="btnExportReportJson"' in html
    assert f'href="/api/reports/{job_id}/html/download"' in html
    assert f'href="/api/reports/{job_id}/pdf?download=1"' in html
    export_menu = re.search(
        r'<ul class="dropdown-menu rv-export-menu".*?</ul>', html, re.DOTALL
    )
    assert export_menu is not None
    export_text = re.sub(r"<[^>]+>", " ", export_menu.group(0))
    assert re.findall(r"\b(JSON|HTML|PDF)\b", export_text) == ["JSON", "HTML", "PDF"]
    assert 'id="reportExportDropdownToggle"' in html
    assert 'data-bs-toggle="dropdown"' in html
    assert 'onclick="document.getElementById(\'reportExportDropdownToggle\').click()"' in html

    assert 'id="reportPrintDropdown"' in html
    assert 'id="btnPrintReportPdf"' in html
    assert 'id="btnPrintReportHtml"' in html
    assert f'href="/api/reports/{job_id}/html?print=1"' in html
    assert 'target="_blank"' in html
    print_menu = re.search(
        r'<ul class="dropdown-menu rv-print-menu".*?</ul>', html, re.DOTALL
    )
    assert print_menu is not None
    print_text = re.sub(r"<[^>]+>", " ", print_menu.group(0))
    assert re.findall(r"\b(Print as PDF|Print as HTML)\b", print_text) == [
        "Print as PDF", "Print as HTML"
    ]


def test_print_mode_omits_report_action_bar(tmp_path):
    _, normal_html = _render_report(tmp_path)
    _, print_html = _render_report(tmp_path, "?print=1")

    assert 'id="reportToolbar"' in normal_html
    assert 'id="reportToolbar"' not in print_html
    assert 'id="btnCopyReportLink"' not in print_html
