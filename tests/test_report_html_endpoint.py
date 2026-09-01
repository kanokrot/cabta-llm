from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates

from src.web.analysis_manager import AnalysisManager
from src.web.routes import reports


def _build_report_app(tmp_path):
    app = FastAPI()
    app.state.analysis_manager = AnalysisManager(
        db_path=str(tmp_path / "analysis_jobs.db")
    )
    app.state.templates = Jinja2Templates(
        directory=str(Path(__file__).resolve().parents[1] / "templates")
    )
    app.include_router(reports.router, prefix="/api/reports")
    return app


def test_report_html_returns_ok_for_existing_job(tmp_path):
    app = _build_report_app(tmp_path)

    job_id = app.state.analysis_manager.create_job("ioc", {"value": "test"})
    app.state.analysis_manager.complete_job(
        job_id,
        {"verdict": "CLEAN"},
        verdict="CLEAN",
        score=0,
    )

    response = TestClient(app).get(f"/api/reports/{job_id}/html")

    assert response.status_code == 200


def test_report_html_download_returns_attachment(tmp_path):
    app = _build_report_app(tmp_path)
    job_id = app.state.analysis_manager.create_job("ioc", {"value": "test"})
    app.state.analysis_manager.complete_job(
        job_id,
        {"verdict": "CLEAN"},
        verdict="CLEAN",
        score=0,
    )

    response = TestClient(app).get(f"/api/reports/{job_id}/html/download")

    assert response.status_code == 200
    assert response.headers["content-disposition"] == (
        f'attachment; filename="report-{job_id}.html"'
    )


def test_print_css_hides_actual_cabta_navbar():
    css_path = Path(__file__).resolve().parents[1] / "static" / "css" / "themes.css"
    css = css_path.read_text(encoding="utf-8")
    print_section = css.split("31. Print Styles", maxsplit=1)[1].split(
        "32. Dark Mode", maxsplit=1
    )[0]

    assert ".cabta-navbar" in print_section
