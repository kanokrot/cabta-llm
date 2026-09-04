"""
Tests for src/utils/thai_fonts.py — Thai font registration for ReportLab.

CABTA's PDF generators (executive_pdf.py, ioc_pdf.py) currently use ReportLab's
default Helvetica, which has no Thai glyphs. This module registers Sarabun
(SIL OFL licensed, Thai National Font used in the Royal Thai Government Gazette)
so any generator can request Thai-safe fonts by name.
"""

import os
import pytest
from reportlab.pdfbase import pdfmetrics
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import ParagraphStyle

from src.utils.thai_fonts import register_thai_fonts, THAI_FONT_REGULAR, THAI_FONT_BOLD


class TestFontRegistration:

    def test_register_thai_fonts_succeeds(self):
        """Registration should not raise and should return True."""
        assert register_thai_fonts() is True

    def test_registered_font_names_are_queryable(self):
        """After registration, pdfmetrics must recognize both font names."""
        register_thai_fonts()
        registered = pdfmetrics.getRegisteredFontNames()
        assert THAI_FONT_REGULAR in registered
        assert THAI_FONT_BOLD in registered

    def test_registration_is_idempotent(self):
        """Calling register_thai_fonts() multiple times must not raise
        (ReportLab raises if you re-register the same font name twice
        without guarding against it)."""
        assert register_thai_fonts() is True
        assert register_thai_fonts() is True  # second call, same process

    def test_missing_font_file_returns_false_not_exception(self, monkeypatch, tmp_path):
        """If the TTF files are missing (e.g. fresh clone before download),
        the function must fail safely — return False, never raise —
        so PDF generation can fall back to Helvetica instead of crashing."""
        import src.utils.thai_fonts as mod
        monkeypatch.setattr(mod, "_FONT_DIR", tmp_path)  # empty dir, no ttf files
        # Force re-registration attempt against the bad path
        monkeypatch.setattr(mod, "_REGISTERED", False)
        assert register_thai_fonts() is False


class TestThaiTextRendering:

    def test_pdf_with_thai_text_builds_without_error(self, tmp_path):
        """End-to-end: a real PDF with actual Thai characters (from the
        T-NET incident report template) must build without ReportLab
        throwing a glyph/encoding error."""
        register_thai_fonts()
        output_path = str(tmp_path / "thai_test.pdf")

        style = ParagraphStyle(
            name="ThaiBody",
            fontName=THAI_FONT_REGULAR,
            fontSize=14,
            leading=18,
        )
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        story = [Paragraph("ประเภทของภัยคุกคาม: การโจมตีแบบฟิชชิ่ง", style)]
        doc.build(story)  # must not raise

        assert os.path.exists(output_path)
        assert os.path.getsize(output_path) > 0
