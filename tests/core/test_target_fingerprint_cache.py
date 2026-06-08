"""F192 — Persisted target fingerprint cache tests.

F180.B uses ``_KNOWN_TARGET_TECH`` (hardcoded map of juice_shop, dvwa,
webgoat) to inject authoritative tech_stack for known lab hosts. For
real-world targets (banking webapps, custom URLs) the map misses and
the gate falls back to narration extraction — fragile.

F192 fills the gap by persisting WhatWeb-derived tech_stack to
``.kryon/target_fingerprints/<host>.json``. Subsequent engagements
against the same host read the cached fingerprint immediately.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kryon.validation.target_fingerprint_cache import (
    fingerprint_path,
    load_target_fingerprint,
    save_target_fingerprint,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch, tmp_path):
    """Each test gets a fresh tmp directory for the fingerprint cache."""
    monkeypatch.setenv("KRYON_FINGERPRINT_DIR", str(tmp_path))
    return tmp_path


# ---------------------------------------------------------------------------
# save_target_fingerprint
# ---------------------------------------------------------------------------


def test_save_creates_file(_isolated_cache):
    ok = save_target_fingerprint("http://example.com", {"nginx", "php"})
    assert ok is True
    files = list(_isolated_cache.iterdir())
    assert len(files) == 1


def test_save_with_empty_stack_noop(_isolated_cache):
    ok = save_target_fingerprint("http://example.com", set())
    assert ok is False
    assert list(_isolated_cache.iterdir()) == []


def test_save_with_empty_host_noop(_isolated_cache):
    ok = save_target_fingerprint("", {"nginx"})
    assert ok is False


def test_save_with_none_host_noop(_isolated_cache):
    ok = save_target_fingerprint(None, {"nginx"})  # type: ignore[arg-type]
    assert ok is False


def test_save_handles_url_with_special_chars(_isolated_cache):
    """URLs have slashes, colons, dots — must produce safe filename."""
    ok = save_target_fingerprint("http://app.bank.com:8443/path", {"java"})
    assert ok is True
    files = list(_isolated_cache.iterdir())
    assert len(files) == 1
    # No raw slashes or colons in the filename.
    assert "/" not in files[0].name
    assert ":" not in files[0].name


# ---------------------------------------------------------------------------
# load_target_fingerprint
# ---------------------------------------------------------------------------


def test_load_returns_saved_stack(_isolated_cache):
    save_target_fingerprint("http://x.example", {"nginx", "php", "mysql"})
    loaded = load_target_fingerprint("http://x.example")
    assert loaded == {"nginx", "php", "mysql"}


def test_load_missing_returns_empty(_isolated_cache):
    assert load_target_fingerprint("http://never-saved.example") == set()


def test_load_empty_host_returns_empty(_isolated_cache):
    assert load_target_fingerprint("") == set()
    assert load_target_fingerprint(None) == set()  # type: ignore[arg-type]


def test_load_malformed_json_returns_empty(_isolated_cache):
    """A corrupted cache file shouldn't crash the caller."""
    path = fingerprint_path("http://bad.example")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not valid json", encoding="utf-8")
    assert load_target_fingerprint("http://bad.example") == set()


def test_save_overwrites_existing(_isolated_cache):
    """Re-saving the same host updates the fingerprint."""
    save_target_fingerprint("http://x.example", {"old"})
    save_target_fingerprint("http://x.example", {"new", "tokens"})
    loaded = load_target_fingerprint("http://x.example")
    assert loaded == {"new", "tokens"}


# ---------------------------------------------------------------------------
# Round-trip with realistic tech_stack tokens
# ---------------------------------------------------------------------------


def test_round_trip_with_versioned_tokens(_isolated_cache):
    """Tokens like ``nginx/1.20.0`` (versions) survive the round trip."""
    stack = {"nginx/1.20.0", "express", "node.js", "owasp juice shop"}
    save_target_fingerprint("http://juice_shop:3000", stack)
    assert load_target_fingerprint("http://juice_shop:3000") == stack


def test_persisted_data_has_metadata(_isolated_cache):
    """The JSON includes host + timestamp for debugging."""
    save_target_fingerprint("http://x.example", {"nginx"})
    path = fingerprint_path("http://x.example")
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["host"] == "http://x.example"
    assert "tech_stack" in doc
    assert "saved_at" in doc
    # Timestamp should look like ISO-8601
    assert "T" in doc["saved_at"]


# ---------------------------------------------------------------------------
# Default cache path (no env override)
# ---------------------------------------------------------------------------


def test_default_path_under_kryon_dir(monkeypatch):
    monkeypatch.delenv("KRYON_FINGERPRINT_DIR", raising=False)
    path = fingerprint_path("http://x.example")
    assert ".kryon" in str(path)
    assert "target_fingerprints" in str(path)
