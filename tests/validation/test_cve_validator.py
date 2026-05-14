"""F151 — CVE ID validator tests."""

from __future__ import annotations

from kryon.validation.cve_validator import (
    cve_in_local_cache,
    is_valid_cve_format,
    is_valid_cve_id,
    validate_finding_cve,
)

# ---------------------------------------------------------------------------
# is_valid_cve_format
# ---------------------------------------------------------------------------


def test_valid_classic_cve():
    assert is_valid_cve_format("CVE-2021-44228") is True


def test_valid_lowercase_prefix():
    assert is_valid_cve_format("cve-2024-12345") is True


def test_valid_long_sequence():
    assert is_valid_cve_format("CVE-2023-1234567") is True


def test_valid_pre_1999_rejected():
    assert is_valid_cve_format("CVE-1990-0001") is False


def test_valid_year_1999_accepted():
    assert is_valid_cve_format("CVE-1999-0001") is True


def test_valid_far_future_year_rejected():
    assert is_valid_cve_format("CVE-2099-1234") is False


def test_invalid_short_sequence():
    assert is_valid_cve_format("CVE-2024-1") is False


def test_invalid_no_dash():
    assert is_valid_cve_format("CVE 2024 1234") is False


def test_invalid_non_string():
    assert is_valid_cve_format(None) is False  # type: ignore[arg-type]
    assert is_valid_cve_format(123) is False  # type: ignore[arg-type]


def test_invalid_empty():
    assert is_valid_cve_format("") is False


def test_invalid_random_text():
    assert is_valid_cve_format("not-a-cve") is False


def test_whitespace_tolerated():
    assert is_valid_cve_format("  CVE-2021-44228  ") is True


# ---------------------------------------------------------------------------
# Local cache
# ---------------------------------------------------------------------------


def test_cache_missing_returns_false(tmp_path):
    assert cve_in_local_cache("CVE-2021-44228", cache_path=tmp_path / "no.txt") is False


def test_cache_populated_membership(tmp_path):
    cache_path = tmp_path / "cves.txt"
    cache_path.write_text("CVE-2021-44228\nCVE-2024-12345\n# comment\n\n", encoding="utf-8")
    # Drop lru_cache so we re-read this fresh tmp file.
    from kryon.validation import cve_validator

    cve_validator._load_cache.cache_clear()

    assert cve_in_local_cache("CVE-2021-44228", cache_path=cache_path) is True
    assert cve_in_local_cache("CVE-2024-12345", cache_path=cache_path) is True
    assert cve_in_local_cache("CVE-9999-9999", cache_path=cache_path) is False


def test_cache_case_insensitive(tmp_path):
    cache_path = tmp_path / "c.txt"
    cache_path.write_text("CVE-2021-44228\n", encoding="utf-8")
    from kryon.validation import cve_validator

    cve_validator._load_cache.cache_clear()

    assert cve_in_local_cache("cve-2021-44228", cache_path=cache_path) is True


# ---------------------------------------------------------------------------
# is_valid_cve_id (format + optional cache)
# ---------------------------------------------------------------------------


def test_valid_id_passes_format_only_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("KRYON_CVE_CACHE_REQUIRED", raising=False)
    monkeypatch.setenv("KRYON_CVE_CACHE_PATH", str(tmp_path / "no.txt"))
    # Format-valid CVE with no cache file → still valid (default soft).
    assert is_valid_cve_id("CVE-2021-44228") is True


def test_strict_cache_rejects_when_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_CVE_CACHE_REQUIRED", "true")
    monkeypatch.setenv("KRYON_CVE_CACHE_PATH", str(tmp_path / "empty.txt"))
    from kryon.validation import cve_validator

    cve_validator._load_cache.cache_clear()

    assert is_valid_cve_id("CVE-2021-44228") is False


def test_strict_cache_accepts_when_present(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_CVE_CACHE_REQUIRED", "true")
    cache = tmp_path / "c.txt"
    cache.write_text("CVE-2021-44228\n", encoding="utf-8")
    monkeypatch.setenv("KRYON_CVE_CACHE_PATH", str(cache))
    from kryon.validation import cve_validator

    cve_validator._load_cache.cache_clear()

    assert is_valid_cve_id("CVE-2021-44228") is True


# ---------------------------------------------------------------------------
# validate_finding_cve — the gate the parser calls
# ---------------------------------------------------------------------------


def test_finding_with_valid_cve_passes(monkeypatch):
    monkeypatch.delenv("KRYON_CVE_CACHE_REQUIRED", raising=False)
    ok, reason = validate_finding_cve({"rule_id": "CVE-2021-44228", "severity": "HIGH"})
    assert ok is True


def test_finding_with_invalid_year_dropped(monkeypatch):
    monkeypatch.delenv("KRYON_CVE_CACHE_REQUIRED", raising=False)
    ok, reason = validate_finding_cve({"rule_id": "CVE-1990-0001", "severity": "HIGH"})
    assert ok is False
    assert "year" in reason or "invalid" in reason


def test_finding_with_malformed_cve_dropped(monkeypatch):
    monkeypatch.delenv("KRYON_CVE_CACHE_REQUIRED", raising=False)
    ok, reason = validate_finding_cve({"rule_id": "CVE-X-Y", "severity": "HIGH"})
    assert ok is False


def test_finding_without_cve_shape_passes_unconditionally(monkeypatch):
    monkeypatch.delenv("KRYON_CVE_CACHE_REQUIRED", raising=False)
    ok, _ = validate_finding_cve({"rule_id": "http-plaintext", "severity": "HIGH"})
    assert ok is True


def test_finding_with_no_rule_id_passes(monkeypatch):
    monkeypatch.delenv("KRYON_CVE_CACHE_REQUIRED", raising=False)
    ok, _ = validate_finding_cve({"severity": "HIGH", "message": "x"})
    assert ok is True


def test_finding_validator_can_be_disabled_via_env(monkeypatch):
    monkeypatch.setenv("KRYON_CVE_VALIDATE", "false")
    # Even an obviously bogus CVE passes when validation is off.
    ok, reason = validate_finding_cve({"rule_id": "CVE-9999-9999", "severity": "HIGH"})
    assert ok is True
    assert "disabled" in reason


def test_finding_validator_default_is_enabled(monkeypatch):
    monkeypatch.delenv("KRYON_CVE_VALIDATE", raising=False)
    ok, _ = validate_finding_cve({"rule_id": "CVE-2099-9999", "severity": "HIGH"})
    # Year 2099 outside plausible window → dropped.
    assert ok is False


def test_finding_dataclass_compatible(monkeypatch):
    """validate_finding_cve must also accept dataclass-like objects."""
    monkeypatch.delenv("KRYON_CVE_CACHE_REQUIRED", raising=False)

    class _F:
        rule_id = "CVE-2021-44228"
        severity = "HIGH"

    ok, _ = validate_finding_cve(_F())
    assert ok is True


# F151 regression — the two R1-invented CVEs from the Juice Shop bench
# should be filterable. CVE-2020-10445 has a plausible year + format,
# so without cache it passes; CVE-2021-44228 is Log4Shell (real). The
# validator does NOT claim to detect every invented CVE without a real
# NVD cache — its job is to kill SHAPE-broken IDs and out-of-range years.


def test_juice_shop_r1_invented_cve_format_passes_without_cache(monkeypatch):
    """The CVE R1 invented was format-valid, so without a cache it
    passes; that's WHY the cache option exists (operator can wire it)."""
    monkeypatch.delenv("KRYON_CVE_CACHE_REQUIRED", raising=False)
    ok, _ = validate_finding_cve({"rule_id": "CVE-2020-10445", "severity": "CRITICAL"})
    assert ok is True


def test_juice_shop_r1_invented_cve_dropped_with_cache(monkeypatch, tmp_path):
    """With strict cache enabled and the invented CVE NOT in the cache,
    F151 drops it — the killer-feature for banca-safe mode."""
    cache = tmp_path / "real_cves.txt"
    cache.write_text("CVE-2021-44228\nCVE-2024-12345\n", encoding="utf-8")
    monkeypatch.setenv("KRYON_CVE_CACHE_REQUIRED", "true")
    monkeypatch.setenv("KRYON_CVE_CACHE_PATH", str(cache))
    from kryon.validation import cve_validator

    cve_validator._load_cache.cache_clear()

    ok, reason = validate_finding_cve({"rule_id": "CVE-2020-10445", "severity": "CRITICAL"})
    assert ok is False
    assert "cache" in reason
