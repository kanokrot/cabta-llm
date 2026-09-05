"""Template wiring tests for the editable case incident report UI."""

from pathlib import Path


TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "case_detail.html"


def test_case_detail_contains_incident_report_form_and_pdf_action():
    html = TEMPLATE.read_text(encoding="utf-8")

    assert 'id="incidentReportForm"' in html
    assert 'id="saveIncidentReportBtn"' in html
    assert 'id="downloadIncidentReportPdfBtn"' in html
    for field in (
        "threat_type",
        "threat_description",
        "attacker_ip",
        "target_ip",
        "affected_username",
        "attack_outcome",
        "occurrence_note",
        "detected_at",
        "detection_device",
        "severity_4tier",
        "findings",
        "analysis",
        "impact",
        "remediation",
        "reference",
    ):
        assert f'name="{field}"' in html


def test_case_detail_wires_incident_report_api_and_pdf_download():
    html = TEMPLATE.read_text(encoding="utf-8")

    assert "'/incident-report'" in html
    assert "incidentApiUrl + '/pdf?download=1'" in html
    assert "method: reportExists ? 'PATCH' : 'POST'" in html
    assert "response.status === 404" in html
