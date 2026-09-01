from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates

from src.web.analysis_manager import AnalysisManager
from src.web.routes import reports


def _render_report(tmp_path, query_string=""):
    app = FastAPI()
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

    assert 'id="reportExportDropdown"' in html
    assert 'id="btnExportReportJson"' in html
    assert f'href="/api/reports/{job_id}/html/download"' in html
    assert f'href="/api/reports/{job_id}/pdf"' in html

    assert 'id="reportPrintDropdown"' in html
    assert 'id="btnPrintReportPdf"' in html
    assert 'id="btnPrintReportHtml"' in html
    assert f'href="/api/reports/{job_id}/html?print=1"' in html
    assert 'target="_blank"' in html


def test_print_mode_omits_report_action_bar(tmp_path):
    _, normal_html = _render_report(tmp_path)
    _, print_html = _render_report(tmp_path, "?print=1")

    assert "Back to History" in normal_html
    assert "Back to History" not in print_html
    assert 'id="reportExportDropdown"' not in print_html
    assert 'id="reportPrintDropdown"' not in print_html
