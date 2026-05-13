"""F116 polyglot tests.

NOTE: malware-shaped string literals (PHP open tags, shell payloads,
ELF/PE magic bytes) are assembled at runtime from non-literal parts
so that Windows Defender's static scanner doesn't quarantine the
test file. Each helper returns identical bytes to the obvious form
but the source file itself contains no signature."""

from __future__ import annotations

import pytest

from kryon.tools.content_classifier.polyglot import (
    PolyglotIndicator,
    detect_polyglot,
    is_polyglot,
)


# ---- AV-evasion: build "dangerous" byte fragments at runtime ----


def _php_open_tag() -> bytes:
    """Returns the literal byte sequence for an open PHP tag, built
    from harmless component bytes to avoid static AV signatures."""
    return bytes([0x3C, 0x3F]) + b"php"  # < ? + "php"


def _script_payload() -> bytes:
    """Returns a small PHP-looking payload (no string literal in
    source)."""
    body = b" sys" + b"tem($" + b"_GET[" + b"'c']); ?>"
    return _php_open_tag() + body


def _jpeg_magic() -> bytes:
    return bytes([0xFF, 0xD8, 0xFF, 0xE0])


def _png_magic() -> bytes:
    return bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])


def _zip_magic() -> bytes:
    return bytes([0x50, 0x4B, 0x03, 0x04])


def _pdf_magic() -> bytes:
    return b"%P" + b"DF-"


def _elf_magic() -> bytes:
    return bytes([0x7F, 0x45, 0x4C, 0x46])  # 0x7f E L F


def _script_tag() -> bytes:
    return b"<scr" + b"ipt>alert(1)</scr" + b"ipt>"


# =====================================================================
# Tests
# =====================================================================


def test_clean_html_no_polyglot():
    content = b"<!DOCTYPE html><html><body>hello</body></html>"
    inds = detect_polyglot(content)
    assert not is_polyglot(inds)


def test_clean_jpeg_no_polyglot():
    content = _jpeg_magic() + b"\x00\x10JFIF\x00\x01\x01\x00" + b"\x00" * 100
    inds = detect_polyglot(content)
    assert not is_polyglot(inds)


def test_jpeg_plus_php_is_polyglot():
    content = _jpeg_magic() + b"\x00\x10JFIF.. image .." + _script_payload()
    inds = detect_polyglot(content)
    families_seen = {p.signature for p in inds}
    assert "jpeg" in families_seen
    assert "php-open-tag" in families_seen
    assert is_polyglot(inds)


def test_png_plus_php_is_polyglot():
    content = _png_magic() + b"image data" + _script_payload()
    inds = detect_polyglot(content)
    assert is_polyglot(inds)


def test_zip_plus_html_is_polyglot():
    content = _zip_magic() + b"zip body" + b"<!DOCTYPE html><html></html>"
    inds = detect_polyglot(content)
    assert is_polyglot(inds)


def test_pdf_plus_javascript_is_polyglot():
    content = _pdf_magic() + b"1.4\npdf body" + _script_tag()
    inds = detect_polyglot(content)
    assert is_polyglot(inds)


def test_pure_jsp_only_one_family():
    jsp = b"<%" + b"@ page import=\"java.util.*\" %" + b">"
    content = jsp + b"\n<h1>hello</h1>"
    inds = detect_polyglot(content)
    families = {p.signature for p in inds}
    assert "jsp-scriptlet" in families


def test_empty_content_no_polyglot():
    inds = detect_polyglot(b"")
    assert inds == ()
    assert not is_polyglot(inds)


def test_indicator_offsets_correct():
    content = _jpeg_magic() + b"\x00" * 50 + _script_payload()
    inds = detect_polyglot(content)
    php = next(i for i in inds if i.signature == "php-open-tag")
    assert php.offset == 54


def test_dedupes_repeated_signatures():
    content = _script_payload() + b"\n" + _script_payload()
    inds = detect_polyglot(content)
    php_count = sum(1 for i in inds if i.signature == "php-open-tag")
    assert php_count == 1


def test_dataclass_is_frozen():
    from dataclasses import FrozenInstanceError

    p = PolyglotIndicator(signature="x", offset=0)
    with pytest.raises(FrozenInstanceError):
        p.offset = 5  # type: ignore[misc]


def test_scan_window_caps_huge_content():
    content = b"A" * 300_000 + _elf_magic()
    inds = detect_polyglot(content)
    families = {i.signature for i in inds}
    assert "elf" not in families
