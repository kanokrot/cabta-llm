"""Tests for the Thai-language incident report PDF generator."""

from pathlib import Path

import src.reporting.incident_report_pdf as incident_pdf
from src.reporting.incident_report_pdf import (
    _font_supports_glyphs,
    _render_severity_row,
    generate_incident_report_pdf,
)


FONT_PATH = Path(__file__).resolve().parents[1] / "assets" / "fonts" / "Sarabun-Regular.ttf"


def test_sarabun_supports_latin_glyph():
    assert _font_supports_glyphs(str(FONT_PATH), "A") is True


def test_severity_checkbox_rendering_matches_detected_font_support():
    supported = _font_supports_glyphs(str(FONT_PATH), "☐☑")

    assert isinstance(supported, bool)
    rendered = _render_severity_row("High", supported)
    if supported:
        assert rendered.count("☑") == 1
        assert rendered.count("☐") == 3
    else:
        assert "☐" not in rendered
        assert "☑" not in rendered
        assert "**High**" in rendered


def test_sarabun_does_not_support_emoji_glyph():
    assert _font_supports_glyphs(str(FONT_PATH), chr(0x1F600)) is False


def test_render_severity_row_with_supported_checkbox_glyphs():
    rendered = _render_severity_row("High", glyphs_supported=True)

    assert rendered.count("☑") == 1
    assert rendered.count("☐") == 3
    assert "☑ High" in rendered


def test_render_severity_row_without_checkbox_glyphs():
    rendered = _render_severity_row("High", glyphs_supported=False)

    assert "☐" not in rendered
    assert "☑" not in rendered
    assert rendered == "Critical | **High** | Medium | Low"


def test_render_severity_row_unknown_or_empty_is_unselected():
    assert _render_severity_row("", True) == "☐ Critical | ☐ High | ☐ Medium | ☐ Low"
    assert _render_severity_row("Unknown", False) == "Critical | High | Medium | Low"


def test_generate_full_thai_incident_report(tmp_path):
    output_path = str(tmp_path / "incident_report.pdf")
    data = {
        "threat_type": "การโจมตีแบบฟิชชิ่ง",
        "threat_description": "อีเมลหลอกลวงขอข้อมูลบัญชี",
        "attacker_ip": "203.0.113.5",
        "target_ip": "10.0.0.12",
        "affected_username": "jdoe",
        "attack_outcome": "บัญชีถูกขโมย",
        "occurrence_note": "3 ครั้งในสัปดาห์นี้",
        "detected_at": "2026-09-05 14:30",
        "detection_device": "Wazuh SIEM",
        "severity_4tier": "High",
        "findings": ["พบลิงก์ปลอมใน inbox"],
        "analysis": ["พบ spoofed domain"],
        "impact": ["บัญชีอีเมลถูกเข้าถึง"],
        "remediation": ["เปลี่ยนรหัสผ่านทันที", "เปิดใช้ MFA"],
        "reference": ["INC-2026-014"],
    }

    result = generate_incident_report_pdf(data, output_path)

    assert result == output_path
    assert Path(output_path).exists()
    assert Path(output_path).stat().st_size > 0


def test_generate_with_missing_optional_keys(tmp_path):
    output_path = str(tmp_path / "minimal_incident_report.pdf")

    result = generate_incident_report_pdf({}, output_path)

    assert result == output_path
    assert Path(output_path).stat().st_size > 0


def test_build_failure_returns_none(monkeypatch, tmp_path):
    class FailingDocument:
        def build(self, story):
            raise RuntimeError("simulated build failure")

    monkeypatch.setattr(incident_pdf, "SimpleDocTemplate", lambda *args, **kwargs: FailingDocument())

    assert generate_incident_report_pdf({}, str(tmp_path / "failed.pdf")) is None


def test_generation_calls_register_thai_fonts(monkeypatch, tmp_path):
    calls = []
    real_register = incident_pdf.register_thai_fonts

    def register_spy():
        calls.append(True)
        return real_register()

    monkeypatch.setattr(incident_pdf, "register_thai_fonts", register_spy)

    result = generate_incident_report_pdf({}, str(tmp_path / "registered.pdf"))

    assert result is not None
    assert calls == [True]


def test_build_letterhead_returns_flowable_when_logo_present():
    from src.reporting.incident_report_pdf import _build_letterhead, _setup_styles

    styles = _setup_styles(thai_fonts_registered=True)
    letterhead = _build_letterhead(styles)
    assert letterhead is not None


def test_build_letterhead_returns_none_when_logo_missing(monkeypatch):
    import src.reporting.incident_report_pdf as incident_pdf

    monkeypatch.setattr(
        incident_pdf, "_LOGO_PATH", incident_pdf.Path("nonexistent_logo.png")
    )
    styles = incident_pdf._setup_styles(thai_fonts_registered=True)
    letterhead = incident_pdf._build_letterhead(styles)
    assert letterhead is None


def test_generate_pdf_still_succeeds_when_logo_missing(monkeypatch, tmp_path):
    # Fail-safe: a missing logo must never break PDF generation, same philosophy as
    # missing Thai font files in thai_fonts.py — degrade gracefully, don't crash.
    import src.reporting.incident_report_pdf as incident_pdf

    monkeypatch.setattr(
        incident_pdf, "_LOGO_PATH", incident_pdf.Path("nonexistent_logo.png")
    )
    output_path = str(tmp_path / "no_logo.pdf")
    result = generate_incident_report_pdf({}, output_path)
    assert result == output_path
    assert Path(output_path).stat().st_size > 0


def test_generate_pdf_with_logo_is_larger_than_without(tmp_path):
    # Sanity check that the logo is actually embedded (file size should meaningfully increase
    # vs a run with no logo), without parsing PDF internals.
    import src.reporting.incident_report_pdf as incident_pdf

    with_logo_path = str(tmp_path / "with_logo.pdf")
    generate_incident_report_pdf({}, with_logo_path)
    with_logo_size = Path(with_logo_path).stat().st_size

    original_logo_path = incident_pdf._LOGO_PATH
    incident_pdf._LOGO_PATH = incident_pdf.Path("nonexistent_logo.png")
    try:
        without_logo_path = str(tmp_path / "without_logo.pdf")
        generate_incident_report_pdf({}, without_logo_path)
        without_logo_size = Path(without_logo_path).stat().st_size
    finally:
        incident_pdf._LOGO_PATH = original_logo_path

    assert with_logo_size > without_logo_size
