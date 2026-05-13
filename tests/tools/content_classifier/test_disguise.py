"""F116 — TDD contract for MIME / extension disguise detection."""

from __future__ import annotations

import pytest

from kryon.tools.content_classifier.disguise import (
    DisguiseAssessment,
    detect_disguise,
    label_implies_extension,
    label_implies_mime,
)


# =====================================================================
# label_implies_mime
# =====================================================================


@pytest.mark.parametrize(
    "label,ct,expected",
    [
        ("html", "text/html", True),
        ("html", "text/html; charset=utf-8", True),
        ("javascript", "application/javascript", True),
        ("javascript", "text/javascript", True),
        ("png", "image/png", True),
        # Mismatches
        ("javascript", "image/png", False),
        ("phpsource", "text/html", False),  # PHP source in HTML body = leak
        ("elf", "text/html", False),  # binary as HTML
        # Empty inputs: lenient (no flag)
        ("", "text/html", True),
        ("html", "", True),
        # Unknown label: lenient
        ("nonexistent-label", "text/html", True),
    ],
)
def test_label_implies_mime(label, ct, expected):
    assert label_implies_mime(label, ct) is expected


# =====================================================================
# label_implies_extension
# =====================================================================


@pytest.mark.parametrize(
    "label,url,expected",
    [
        ("html", "https://x/page.html", True),
        ("javascript", "https://x/app.js", True),
        ("css", "https://x/styles.css", True),
        ("phpsource", "https://x/index.php", True),
        # Mismatches
        ("phpsource", "https://x/avatar.jpg", False),
        ("elf", "https://x/upload.png", False),
        ("javascript", "https://x/banner.png", False),
        # No extension
        ("html", "https://x/page", True),  # no ext → lenient
    ],
)
def test_label_implies_extension(label, url, expected):
    assert label_implies_extension(label, url) is expected


# =====================================================================
# detect_disguise — full assessment
# =====================================================================


def test_no_disguise_when_everything_matches():
    assess = detect_disguise("html", "text/html", "https://x/index.html")
    assert assess.mime_disguise is False
    assert assess.extension_disguise is False
    assert assess.severity == ""


def test_mime_disguise_phpsource_as_html():
    """Classic: PHP source returned with Content-Type: text/html →
    interpreter not running, source leaked."""
    assess = detect_disguise(
        "phpsource", "text/html", "https://x/index.php"
    )
    assert assess.mime_disguise is True
    assert assess.severity == "CRITICAL"


def test_mime_disguise_executable_as_html():
    assess = detect_disguise("elf", "text/html", "https://x/page")
    assert assess.mime_disguise is True
    assert assess.severity == "HIGH"


def test_extension_disguise_php_as_jpg():
    """Upload-bypass classic: file uploaded as profile.jpg but
    content is PHP."""
    assess = detect_disguise(
        "phpsource", "image/jpeg", "https://x/uploads/profile.jpg"
    )
    assert assess.extension_disguise is True
    # Both mismatch AND PHP is severe
    assert assess.severity == "CRITICAL"


def test_extension_only_disguise():
    """Same content type declared correctly but URL extension misleads."""
    assess = detect_disguise(
        "javascript", "application/javascript", "https://x/banner.png"
    )
    assert assess.mime_disguise is False
    assert assess.extension_disguise is True


def test_empty_label_returns_empty_assessment():
    assess = detect_disguise("", "text/html", "https://x/page")
    assert assess.mime_disguise is False
    assert assess.extension_disguise is False


def test_dataclass_is_frozen():
    from dataclasses import FrozenInstanceError

    a = DisguiseAssessment()
    with pytest.raises(FrozenInstanceError):
        a.mime_disguise = True  # type: ignore[misc]
