"""F85.H — Cover page + signature block + branding wireup tests."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from kryon.reporting.cover import (
    _classification_color,
    _file_to_data_uri,
    _normalise_classification,
    render_cover_page,
    render_signature_block,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_normalise_classification_accepts_valid_values():
    assert _normalise_classification("PUBLIC") == "PUBLIC"
    assert _normalise_classification("internal") == "INTERNAL"
    assert _normalise_classification("Confidential") == "CONFIDENTIAL"
    assert _normalise_classification("RESTRICTED") == "RESTRICTED"


def test_normalise_classification_falls_back_for_unknown():
    assert _normalise_classification("") == "INTERNAL"
    assert _normalise_classification(None or "") == "INTERNAL"
    assert _normalise_classification("TOP_SECRET") == "INTERNAL"
    assert _normalise_classification("foo bar") == "INTERNAL"


def test_classification_color_distinct_per_level():
    """The 4 classifications each have a distinct color so a bank
    reviewer eyeballing the banner can tell them apart."""
    colors = {_classification_color(c) for c in ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED")}
    assert len(colors) == 4


def test_file_to_data_uri_passes_through_http_urls():
    assert _file_to_data_uri("https://example.com/logo.png") == "https://example.com/logo.png"
    assert _file_to_data_uri("http://example.com/logo.png") == "http://example.com/logo.png"


def test_file_to_data_uri_passes_through_data_uri():
    src = "data:image/png;base64,abc"
    assert _file_to_data_uri(src) == src


def test_file_to_data_uri_returns_empty_for_missing(tmp_path: Path):
    assert _file_to_data_uri(None) == ""
    assert _file_to_data_uri("") == ""
    assert _file_to_data_uri(tmp_path / "nope.png") == ""


def test_file_to_data_uri_encodes_local_png(tmp_path: Path):
    """Local PNGs are read and base64-encoded so weasyprint embeds
    them without a network fetch."""
    png_bytes = b"\x89PNG\r\n\x1a\nFAKEBODY"
    p = tmp_path / "logo.png"
    p.write_bytes(png_bytes)
    uri = _file_to_data_uri(p)
    assert uri.startswith("data:image/png;base64,")
    assert base64.b64decode(uri.split(",", 1)[1]) == png_bytes


# ---------------------------------------------------------------------------
# render_cover_page
# ---------------------------------------------------------------------------


def test_cover_includes_title_and_client():
    html = render_cover_page(
        title="Pentest Report",
        client_name="BritImp",
        target_scope="172.18.201.0/24",
        engagement_id="britimp-2026-05",
        classification="CONFIDENTIAL",
        date="2026-05-11",
    )
    assert "Pentest Report" in html
    assert "BritImp" in html
    assert "172.18.201.0/24" in html
    assert "britimp-2026-05" in html
    assert "CONFIDENTIAL" in html
    assert "2026-05-11" in html


def test_cover_classification_banner_color_matches_level():
    html_conf = render_cover_page(
        title="X",
        client_name="Y",
        classification="CONFIDENTIAL",
    )
    html_pub = render_cover_page(
        title="X",
        client_name="Y",
        classification="PUBLIC",
    )
    # Different banner colors should appear in the inline CSS
    assert _classification_color("CONFIDENTIAL") in html_conf
    assert _classification_color("PUBLIC") in html_pub


def test_cover_falls_back_to_client_name_when_no_logo():
    html = render_cover_page(
        title="X",
        client_name="Acme Bank",
        client_logo_path=None,
    )
    # Without a logo, the cover uses the client name as a textual placeholder
    assert "kr-cover-client-placeholder" in html
    assert "Acme Bank" in html


def test_cover_embeds_logo_when_path_given(tmp_path: Path):
    p = tmp_path / "logo.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\nABCD")
    html = render_cover_page(
        title="X",
        client_name="Acme",
        client_logo_path=str(p),
    )
    assert "data:image/png;base64," in html
    assert "kr-cover-client-logo" in html


def test_cover_invalid_classification_renders_internal():
    html = render_cover_page(
        title="X",
        client_name="Y",
        classification="LEAKED_FROM_BUG",
    )
    assert "INTERNAL" in html
    assert "LEAKED_FROM_BUG" not in html


def test_cover_default_date_is_today_iso():
    html = render_cover_page(title="X", client_name="Y")
    # We don't pin the exact day; just confirm a 4-digit year is present
    import re

    assert re.search(r"20\d\d-\d\d-\d\d", html)


def test_cover_uses_custom_accent_color():
    html = render_cover_page(
        title="X",
        client_name="Y",
        accent_color="#aabbcc",
    )
    assert "#aabbcc" in html


# ---------------------------------------------------------------------------
# render_signature_block
# ---------------------------------------------------------------------------


def test_signature_includes_auditor_and_engagement():
    html = render_signature_block(
        auditor="SkyVanguard",
        engagement_id="ENG-001",
        reproducibility_hash="abc123def456",
        date="2026-05-11",
    )
    assert "SkyVanguard" in html
    assert "ENG-001" in html
    assert "abc123def456" in html
    assert "2026-05-11" in html


def test_signature_omits_hash_row_when_not_provided():
    html = render_signature_block(
        auditor="X",
        engagement_id="Y",
        reproducibility_hash="",
    )
    # The "Hash de reproducibilidad" row only appears when a hash is provided
    assert "Hash de reproducibilidad" not in html


def test_signature_includes_kryon_version_line():
    html = render_signature_block(auditor="X", engagement_id="Y")
    assert "Kryon v2.1.0" in html


# ---------------------------------------------------------------------------
# End-to-end: generator wiring (requires intelligence.models)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generator_includes_cover_and_signature(tmp_path: Path):
    """The full generate path must produce HTML that contains both
    the cover-page block and the signature block, regardless of
    whether the operator passed branding flags."""
    from kryon.intelligence.models import Finding, Severity
    from kryon.reporting.generator import ReportGenerator
    from kryon.reporting.models import ReportConfig, ReportType

    findings = [
        Finding(
            id="f1",
            title="SQL Injection",
            description="...",
            severity=Severity.HIGH,
            affected_asset="10.0.0.1",
        )
    ]
    cfg = ReportConfig(
        report_type=ReportType.TECHNICAL,
        client_name="BritImp",
        target_scope="172.18.201.0/24",
        engagement_id="ENG-TEST",
        classification="CONFIDENTIAL",
        auditor="SkyVanguard / Kryon",
        reproducibility_hash="hashtest123",
    )
    gen = ReportGenerator()
    html = await gen.generate(findings, cfg)

    assert "kr-cover" in html
    assert "kr-signature" in html
    assert "BritImp" in html
    assert "ENG-TEST" in html
    assert "CONFIDENTIAL" in html
    assert "hashtest123" in html
