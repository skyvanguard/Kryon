"""Firm identity for report branding.

The auditing FIRM is distinct from the CLIENT. The cover + footer carry the firm identity; the client
is named in the meta. Centralised here so every report renders the same firm branding by default. The
defaults below are generic placeholders — override via env (KRYON_FIRM_*) to white-label your firm.
"""

from __future__ import annotations

import base64
import os
from functools import lru_cache
from pathlib import Path

FIRM_NAME = os.getenv("KRYON_FIRM_NAME", "Your Security Firm")
FIRM_TAGLINE = os.getenv("KRYON_FIRM_TAGLINE", "CYBERSECURITY & AI RESEARCHER")
FIRM_AUDITOR = os.getenv("KRYON_FIRM_AUDITOR", "Kryon Autonomous Cybersecurity")
FIRM_ACCENT = os.getenv("KRYON_FIRM_ACCENT", "#1f74d0")  # firm accent (blue)
FIRM_ACCENT_DARK = os.getenv("KRYON_FIRM_ACCENT_DARK", "#0b2240")  # deep navy (cover background)
FIRM_NAVY_TOP = os.getenv("KRYON_FIRM_NAVY_TOP", "#0a1a33")
FIRM_NAVY_BOTTOM = os.getenv("KRYON_FIRM_NAVY_BOTTOM", "#0e2c54")

_ASSETS = Path(__file__).parent / "assets"


@lru_cache(maxsize=2)
def _logo_data_uri(filename: str, mime: str) -> str:
    """Embed a bundled logo asset as a base64 data URI (weasyprint-friendly, no file path)."""
    p = _ASSETS / filename
    try:
        return f"data:{mime};base64," + base64.b64encode(p.read_bytes()).decode("ascii")
    except OSError:
        return ""


def firm_logo_data_uri() -> str:
    """The firm emblem (transparent) for the dark cover, as a data URI."""
    override = os.getenv("KRYON_FIRM_LOGO")  # optional external path override
    if override:
        try:
            data = Path(override).read_bytes()
            suffix = Path(override).suffix.lower().lstrip(".")
            mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "svg": "image/svg+xml"}.get(
                suffix, "image/png"
            )
            return f"data:{mime};base64," + base64.b64encode(data).decode("ascii")
        except OSError:
            pass
    return _logo_data_uri("firm_emblem.png", "image/png")


def firm_logo_light_data_uri() -> str:
    """The firm logo on a light background (for light-themed surfaces)."""
    return _logo_data_uri("firm_logo.png", "image/png")


def firm_logo_dark_data_uri() -> str:
    """The firm logo on a dark background (for dark headers/footers)."""
    return _logo_data_uri("firm_logo_dark.jpg", "image/jpeg")
