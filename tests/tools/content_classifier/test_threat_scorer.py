"""F116 — TDD contract for the contextual threat scorer."""

from __future__ import annotations

import pytest

from kryon.tools.content_classifier.threat_scorer import (
    ThreatScoreResult,
    score_threat,
)


# =====================================================================
# Source code in production endpoints
# =====================================================================


def test_phpsource_in_production_path_high_score():
    r = score_threat("phpsource", "https://target.com/index.php")
    assert r.score >= 70
    assert r.primary_rule == "CC-005"


def test_phpsource_in_docs_lower_score():
    r = score_threat("phpsource", "https://target.com/docs/examples/index.php")
    assert r.score < 70  # docs are less critical
    assert r.primary_rule == "CC-005"


# =====================================================================
# Executables
# =====================================================================


def test_elf_in_uploads_critical():
    r = score_threat("elf", "https://target.com/uploads/avatar.png")
    assert r.score >= 80
    assert r.primary_rule == "CC-004"
    assert any("upload" in f.lower() for f in r.factors)


def test_pe_in_static_lower_score():
    r = score_threat("pe", "https://target.com/static/icon.exe")
    assert r.score < 60  # /static legit context
    assert r.primary_rule == "CC-004"


def test_elf_in_random_path():
    r = score_threat("elf", "https://target.com/files/data")
    assert r.score >= 60
    assert r.primary_rule == "CC-004"


# =====================================================================
# Polyglot
# =====================================================================


def test_polyglot_in_uploads_critical():
    r = score_threat(
        detected_label="jpeg",
        source_url="https://target.com/uploads/profile.jpg",
        polyglot_present=True,
    )
    assert r.score >= 70


def test_polyglot_elsewhere_medium():
    r = score_threat(
        detected_label="png",
        source_url="https://target.com/static/logo.png",
        polyglot_present=True,
    )
    assert 30 <= r.score <= 70


# =====================================================================
# MIME disguise
# =====================================================================


def test_mime_disguise_in_uploads_bumps_score():
    r = score_threat(
        detected_label="javascript",
        source_url="https://target.com/uploads/avatar.png",
        mime_disguise=True,
    )
    assert any("upload" in f.lower() for f in r.factors)
    assert r.score >= 40


def test_mime_disguise_in_admin():
    r = score_threat(
        detected_label="javascript",
        source_url="https://target.com/admin/dashboard",
        mime_disguise=True,
    )
    assert any("admin" in f.lower() for f in r.factors)


# =====================================================================
# Embedded secrets
# =====================================================================


def test_secrets_in_api_response():
    r = score_threat(
        detected_label="json",
        source_url="https://target.com/api/users",
        secret_count=2,
    )
    assert r.primary_rule == "CC-006"
    assert r.score > 0


def test_secrets_in_html_response():
    r = score_threat(
        detected_label="html",
        source_url="https://target.com/login",
        secret_count=1,
    )
    assert r.primary_rule == "CC-006"


def test_no_secrets_no_score_from_secrets():
    r = score_threat(detected_label="html", source_url="https://target.com/", secret_count=0)
    # html on /, no secrets → score should be 0
    assert r.score == 0


# =====================================================================
# Archives in sensitive paths
# =====================================================================


def test_zip_in_api_path():
    r = score_threat(
        detected_label="zip", source_url="https://target.com/api/export"
    )
    assert r.primary_rule == "CC-008"
    assert r.score >= 20


def test_zip_in_static_path_low_score():
    r = score_threat(
        detected_label="zip", source_url="https://target.com/static/data.zip"
    )
    # No factor bonus from /api or /admin
    assert r.score == 0  # zip in /static is fine


# =====================================================================
# Backup path bonuses
# =====================================================================


def test_backup_path_adds_to_score():
    r = score_threat(
        detected_label="txt", source_url="https://target.com/config.bak"
    )
    assert r.score > 0
    assert any("backup" in f.lower() for f in r.factors)


# =====================================================================
# Sanity
# =====================================================================


def test_score_bounded_0_to_100():
    r = score_threat(
        detected_label="phpsource",
        source_url="https://target.com/uploads/.git/config.bak",
        polyglot_present=True,
        mime_disguise=True,
        secret_count=10,
    )
    assert 0 <= r.score <= 100  # bounded


def test_clean_html_no_score():
    r = score_threat(detected_label="html", source_url="https://target.com/about")
    assert r.score == 0
    assert r.factors == ()


def test_dataclass_is_frozen():
    from dataclasses import FrozenInstanceError

    r = ThreatScoreResult(score=50, factors=())
    with pytest.raises(FrozenInstanceError):
        r.score = 60  # type: ignore[misc]
