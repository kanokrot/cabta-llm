import re
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


def _render_report(tmp_path, result):
    app = _build_report_app(tmp_path)
    job_id = app.state.analysis_manager.create_job("file", {"filename": "sample.exe"})
    app.state.analysis_manager.complete_job(
        job_id,
        result,
        verdict="MALICIOUS",
        score=90,
    )
    return TestClient(app).get(f"/api/reports/{job_id}/html")


def test_report_renders_flat_mitre_mapping_technique_id(tmp_path):
    response = _render_report(
        tmp_path,
        {
            "verdict": "MALICIOUS",
            "mitre_mapping": [
                {
                    "technique_id": "T1059",
                    "source": "sandbox",
                    "confidence": "high",
                }
            ],
        },
    )

    assert response.status_code == 200
    assert re.search(
        r'<span class="mitre-badge">\s*T1059\s*</span>', response.text
    )


def test_report_renders_capa_attack_techniques(tmp_path):
    capabilities = {
        "success": True,
        "capabilities": [],
        "attack_techniques": [
            {
                "id": "T1055",
                "tactic": "Defense Evasion",
                "technique": "Process Injection",
                "subtechnique": "",
                "capability": "inject into process",
            }
        ],
    }
    response = _render_report(
        tmp_path,
        {
            "verdict": "MALICIOUS",
            "static_analysis": {"capabilities": capabilities},
            "capabilities": capabilities,
        },
    )

    assert response.status_code == 200
    assert re.search(
        r'<span class="mitre-badge">\s*T1055\s*</span>', response.text
    )
    assert "MITRE ATT&CK Techniques" in response.text
    assert "Defense Evasion" in response.text
    assert "Process Injection" in response.text
