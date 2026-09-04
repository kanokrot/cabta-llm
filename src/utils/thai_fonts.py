"""Thai font registration helpers for ReportLab PDF generation."""

import logging
from pathlib import Path

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


logger = logging.getLogger(__name__)

THAI_FONT_REGULAR = "Sarabun"
THAI_FONT_BOLD = "Sarabun-Bold"

_FONT_DIR = Path(__file__).resolve().parents[2] / "assets" / "fonts"
_REGISTERED = False


def register_thai_fonts() -> bool:
    """Register bundled Sarabun fonts, returning whether registration succeeded."""
    global _REGISTERED

    if _REGISTERED:
        return True

    try:
        pdfmetrics.registerFont(
            TTFont(THAI_FONT_REGULAR, _FONT_DIR / "Sarabun-Regular.ttf")
        )
        pdfmetrics.registerFont(
            TTFont(THAI_FONT_BOLD, _FONT_DIR / "Sarabun-Bold.ttf")
        )
    except Exception as exc:
        logger.warning("Unable to register Thai fonts: %s", exc)
        return False

    _REGISTERED = True
    return True
