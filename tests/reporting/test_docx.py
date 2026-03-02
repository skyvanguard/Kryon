"""Tests for DOCX export utilities."""

import pytest

from kryon.reporting.docx_export import _extract_sections, _strip_html


def test_strip_html():
    assert _strip_html("<b>Bold</b>") == "Bold"
    assert _strip_html("<p>Hello &amp; World</p>") == "Hello & World"
    assert _strip_html("") == ""


def test_extract_sections_with_headings():
    html = "<h1>Title</h1><p>Paragraph</p><h2>Section</h2>"
    sections = _extract_sections(html)
    assert len(sections) >= 3
    h1 = [s for s in sections if s["type"] == "h1"]
    assert len(h1) == 1
    assert h1[0]["text"] == "Title"


def test_extract_sections_with_table():
    html = "<table><tr><td>Cell</td></tr></table>"
    sections = _extract_sections(html)
    tables = [s for s in sections if s["type"] == "table"]
    assert len(tables) == 1


def test_extract_sections_empty():
    sections = _extract_sections("")
    assert len(sections) == 0


def test_html_to_docx():
    """Test DOCX conversion (requires python-docx)."""
    docx = pytest.importorskip("docx")
    from kryon.reporting.docx_export import html_to_docx

    result = html_to_docx("<h1>Test Report</h1><p>Hello world</p>")
    assert isinstance(result, bytes)
    assert len(result) > 0
