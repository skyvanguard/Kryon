"""F116 main classifier tests.

NOTE: as in test_polyglot.py, malware-shaped bytes are assembled at
runtime from harmless fragments so Windows Defender doesn't quarantine
the test source file."""

from __future__ import annotations

import hashlib

import pytest

from kryon.tools.content_classifier.classifier import (
    ALL_CC_RULES,
    ContentClassifier,
    ContentInput,
    classify_content,
    is_magika_available,
)


# ---- AV-evasion fragments -------------------------------------------------


def _php_open_tag() -> bytes:
    return bytes([0x3C, 0x3F]) + b"php"


def _php_payload() -> bytes:
    return _php_open_tag() + b" echo $" + b"_GET[" + b"'cmd']; ?>"


def _png_magic() -> bytes:
    return bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])


def _elf_magic() -> bytes:
    return bytes([0x7F, 0x45, 0x4C, 0x46])


def _jpeg_magic() -> bytes:
    return bytes([0xFF, 0xD8, 0xFF, 0xE0])


def _pdf_magic() -> bytes:
    return b"%P" + b"DF-"


def _zip_magic() -> bytes:
    return bytes([0x50, 0x4B, 0x03, 0x04])


def _aws_key() -> bytes:
    # Build the AWS access key literal "AKIAIOSFODNN7EXAMPLE" piecewise
    return b"AK" + b"IA" + b"IOS" + b"FODNN7" + b"EXAMPLE"


# =====================================================================
# Pinning
# =====================================================================


def test_all_cc_rules_pinned():
    expected = {f"CC-{n:03d}" for n in range(1, 9)}
    assert expected == ALL_CC_RULES


# =====================================================================
# Heuristic fallback
# =====================================================================


def test_heuristic_classifies_png():
    content = _png_magic() + b"\x00" * 100
    r = classify_content(content, source_url="https://x/img.png", content_type_header="image/png")
    label = r.magika_label or r.heuristic_label
    assert label == "png"


def test_heuristic_classifies_phpsource():
    content = _php_payload()
    r = classify_content(content)
    label = r.magika_label or r.heuristic_label
    assert label in ("phpsource", "php")


def test_heuristic_classifies_html():
    content = b"<!DOCTYPE html><html><body>x</body></html>"
    r = classify_content(content)
    label = r.magika_label or r.heuristic_label
    assert label == "html"


def test_heuristic_classifies_json():
    content = b'{"key": "value", "nested": {"a": 1}}'
    r = classify_content(content)
    label = r.magika_label or r.heuristic_label
    assert label == "json"


def test_heuristic_classifies_pdf():
    content = _pdf_magic() + b"1.4\nBody"
    r = classify_content(content)
    label = r.magika_label or r.heuristic_label
    assert label == "pdf"


def test_heuristic_classifies_zip():
    content = _zip_magic() + b"..."
    r = classify_content(content)
    label = r.magika_label or r.heuristic_label
    assert label == "zip"


def test_heuristic_classifies_elf():
    content = _elf_magic() + b"\x02\x01\x01"
    r = classify_content(content)
    label = r.magika_label or r.heuristic_label
    assert label == "elf"


# =====================================================================
# Findings emission
# =====================================================================


def test_phpsource_in_html_emits_cc_001_and_cc_005():
    content = _php_payload()
    r = classify_content(
        content,
        source_url="https://target.com/index.php",
        content_type_header="text/html",
    )
    rule_ids = {f.rule_id for f in r.findings}
    assert "CC-001" in rule_ids
    assert "CC-005" in rule_ids


def test_executable_in_uploads_emits_cc_004():
    content = _elf_magic() + b"\x02\x01\x01" + b"\x00" * 200
    r = classify_content(
        content,
        source_url="https://target.com/uploads/avatar.png",
        content_type_header="image/png",
    )
    rule_ids = {f.rule_id for f in r.findings}
    assert "CC-004" in rule_ids


def test_polyglot_jpg_plus_php_emits_cc_003():
    content = (
        _jpeg_magic() + b"\x00\x10JFIF\x00\x01\x01\x00"
        + b"\x00" * 50
        + _php_payload()
    )
    r = classify_content(
        content,
        source_url="https://target.com/uploads/profile.jpg",
        content_type_header="image/jpeg",
    )
    rule_ids = {f.rule_id for f in r.findings}
    assert "CC-003" in rule_ids


def test_secret_in_response_emits_cc_006():
    content = b"<html>config = {api_key: '" + _aws_key() + b"'}</html>"
    r = classify_content(content, source_url="https://target.com/api/config")
    rule_ids = {f.rule_id for f in r.findings}
    assert "CC-006" in rule_ids
    secret_finding = next(f for f in r.findings if f.rule_id == "CC-006")
    extras = dict(secret_finding.extra)
    assert "secret_kind" in extras
    # Full secret value MUST NOT appear in detail (banca-safety)
    assert "IOSFODNN7" not in secret_finding.detail


def test_clean_html_no_findings():
    content = b"<!DOCTYPE html><html><body>Welcome!</body></html>"
    r = classify_content(
        content,
        source_url="https://target.com/about",
        content_type_header="text/html",
    )
    assert r.findings == ()


def test_polyglot_in_uploads_combo_findings():
    content = (
        _jpeg_magic() + b"\x00" * 30 + _php_payload() + b"\x00" * 30
    )
    r = classify_content(
        content,
        source_url="https://target.com/uploads/x.jpg",
        content_type_header="image/jpeg",
    )
    rule_ids = {f.rule_id for f in r.findings}
    assert "CC-003" in rule_ids


# =====================================================================
# SHA-256 + entropy + length
# =====================================================================


def test_content_sha256_computed():
    content = b"hello world"
    r = classify_content(content)
    expected = hashlib.sha256(content).hexdigest()
    assert r.content_sha256 == expected


def test_empty_content_no_hash():
    r = classify_content(b"")
    assert r.content_sha256 == ""


def test_content_length_recorded():
    content = b"x" * 1234
    r = classify_content(content)
    assert r.content_length == 1234


def test_entropy_positive_for_text():
    r = classify_content(b"hello world hello world")
    assert r.content_entropy > 0


# =====================================================================
# Magika availability
# =====================================================================


def test_is_magika_available_is_bool():
    assert isinstance(is_magika_available(), bool)


def test_classifier_soft_fails_without_magika(monkeypatch):
    import kryon.tools.content_classifier.classifier as mod

    monkeypatch.setattr(mod, "is_magika_available", lambda: False)
    classifier = ContentClassifier()
    r = classifier.classify(
        ContentInput(content=_png_magic(), content_length=8)
    )
    assert r.magika_available is False
    assert r.heuristic_label == "png"


# =====================================================================
# Banca-safety
# =====================================================================


def test_secret_value_never_in_classification_output():
    secret = _aws_key()
    content = b"const k = '" + secret + b"';"
    r = classify_content(content, source_url="https://x/")
    blob = repr(r)
    # The MIDDLE of the secret must NOT appear in any field
    assert "IOSFODNN7" not in blob


def test_classification_dataclasses_frozen():
    from dataclasses import FrozenInstanceError
    from kryon.tools.content_classifier.classifier import ContentClassification

    c = ContentClassification()
    with pytest.raises(FrozenInstanceError):
        c.magika_label = "x"  # type: ignore[misc]
