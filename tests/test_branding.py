from fastapi import FastAPI

from src.branding import BRAND_NAME, BRAND_TAGLINE
from src.integrations.stix_generator import STIXGenerator
from src.reporting import incident_report_pdf, ioc_pdf
from src.web.app import _register_page_routes, create_app


def test_shared_templates_expose_brand_globals():
    app = create_app()
    templates = app.state.templates

    assert templates.env.globals["BRAND_NAME"] == BRAND_NAME
    assert templates.env.globals["BRAND_TAGLINE"] == BRAND_TAGLINE

    rendered = templates.env.from_string(
        "{{ BRAND_NAME }} - {{ BRAND_TAGLINE }}"
    ).render()
    assert rendered == "SOCPOW - Every IOC gets the POW"


def test_fallback_templates_expose_brand_globals():
    app = FastAPI()
    _register_page_routes(app)

    assert app.state.templates.env.globals["BRAND_NAME"] == BRAND_NAME
    assert app.state.templates.env.globals["BRAND_TAGLINE"] == BRAND_TAGLINE


def _flowable_text(flowables):
    for flowable in flowables:
        text = getattr(flowable, "text", None)
        if isinstance(text, str):
            yield text
        for row in getattr(flowable, "_cellvalues", ()):
            yield from _flowable_text(row)
        if isinstance(flowable, (list, tuple)):
            yield from _flowable_text(flowable)


def test_pdf_generators_use_central_brand_in_builder_inputs(monkeypatch, tmp_path):
    captured_ioc_story = []
    captured_incident_story = []

    class CapturingDocument:
        def __init__(self, captured, *args, **kwargs):
            self.captured = captured

        def build(self, story):
            self.captured.extend(story)

    monkeypatch.setattr(
        ioc_pdf,
        "SimpleDocTemplate",
        lambda *args, **kwargs: CapturingDocument(captured_ioc_story),
    )
    monkeypatch.setattr(
        incident_report_pdf,
        "SimpleDocTemplate",
        lambda *args, **kwargs: CapturingDocument(captured_incident_story),
    )

    ioc_result = ioc_pdf.generate_ioc_pdf(
        {"summary": "summary"},
        str(tmp_path / "ioc.pdf"),
        {"analysis_type": "file", "version": "2.0.0"},
    )
    incident_result = incident_report_pdf.generate_incident_report_pdf(
        {}, str(tmp_path / "incident.pdf")
    )

    assert ioc_result is not None
    assert incident_result is not None
    ioc_text = " ".join(_flowable_text(captured_ioc_story))
    incident_text = " ".join(_flowable_text(captured_incident_story))
    assert BRAND_NAME in ioc_text
    assert "SOCPOW v2.0.0" in ioc_text
    assert BRAND_NAME in incident_text
    assert "Cyan Agent Blue Team Assistant" not in ioc_text
    assert "Cyan Agent Blue Team Assistant" not in incident_text


def test_stix_identity_uses_brand_name_without_deriving_id_from_name():
    identity = STIXGenerator().create_identity()

    assert identity["name"] == BRAND_NAME
    assert identity["description"] == "SOCPOW - Cyber Blue Team Assistant"
    assert identity["id"].startswith("identity--")
