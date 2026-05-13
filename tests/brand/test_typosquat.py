"""F90.1 — TDD contract for the typosquat generator + DNS checker.

Coverage:
  - Domain split helper (label + suffix)
  - Per-strategy generation: produces expected mutations, never
    returns the original.
  - Generate honors max_variants cap + strategy subset.
  - Deduplication across strategies.
  - IDN homoglyph round-trips to a Punycode A-label (xn--...).
  - DNS resolver fire-gate: dry-run default, fire+env required,
    NXDOMAIN → not_resolving, other OSError → error.
  - Tool wrapper: generate mode (no I/O), scan mode summary.
  - Banca-safety: invalid DNS labels rejected, original never in
    output.
"""

from __future__ import annotations

import json
import socket
from typing import Any
from unittest.mock import patch

import pytest

from kryon.brand.typosquat import (
    ALL_STRATEGIES,
    DEFAULT_DNS_TIMEOUT,
    DEFAULT_MAX_VARIANTS,
    TyposquatCandidate,
    TyposquatScanResult,
    _generate_additions,
    _generate_homoglyphs,
    _generate_idn_homoglyphs,
    _generate_omissions,
    _generate_replacements,
    _generate_tld_swaps,
    _generate_transpositions,
    _is_valid_dns_label,
    _split_domain,
    generate_typosquats,
    resolve_candidate,
)


# =====================================================================
# Domain split + label validation
# =====================================================================


def test_split_domain_with_compound_tld():
    assert _split_domain("bcp.com.py") == ("bcp", ".com.py")


def test_split_domain_with_single_tld():
    assert _split_domain("example.com") == ("example", ".com")


def test_split_domain_with_no_tld():
    """A bare label is still mutateable; suffix is empty."""
    assert _split_domain("internal") == ("internal", "")


def test_split_domain_normalizes_case_and_whitespace():
    assert _split_domain("  BCP.COM.PY  ") == ("bcp", ".com.py")


def test_valid_dns_label_accepts_alphanumeric():
    assert _is_valid_dns_label("bcp") is True
    assert _is_valid_dns_label("bcp-bank") is True
    assert _is_valid_dns_label("xn--mxa") is True  # punycode


def test_valid_dns_label_rejects_empty_and_too_long():
    assert _is_valid_dns_label("") is False
    assert _is_valid_dns_label("a" * 64) is False  # > 63 chars


def test_valid_dns_label_rejects_leading_or_trailing_hyphen():
    assert _is_valid_dns_label("-bcp") is False
    assert _is_valid_dns_label("bcp-") is False


def test_valid_dns_label_rejects_special_chars():
    assert _is_valid_dns_label("bc!p") is False
    assert _is_valid_dns_label("bc/p") is False


# =====================================================================
# Per-strategy generators
# =====================================================================


def test_transposition_swaps_adjacent_chars():
    variants = _generate_transpositions("bcp")
    # Two adjacent swaps possible: bc→cb (cbp) and cp→pc (bpc).
    assert "cbp" in variants
    assert "bpc" in variants
    assert len(variants) == 2


def test_transposition_skips_identity_swaps():
    """Swapping two identical letters yields the original — must be
    skipped to avoid the generator returning the input."""
    variants = _generate_transpositions("aab")
    # aab → aab (skip), aab → aba.
    assert "aab" not in variants
    assert "aba" in variants


def test_omission_drops_each_char_once():
    variants = _generate_omissions("bcp")
    assert variants == {"cp", "bp", "bc"}


def test_omission_skips_too_short_label():
    """A 2-letter label dropping a char becomes 1 letter — useless
    for typosquatting. Skip to keep the candidate space sane."""
    assert _generate_omissions("ab") == set()


def test_addition_inserts_at_every_position():
    """For label of length N, expect close to (N+1) * 26 variants —
    minor set dedupe when inserting the same letter at adjacent
    positions of identical chars (e.g. inserting 'b' before 'b' →
    same string)."""
    variants = _generate_additions("bcp")
    # (3 + 1) * 26 = 104 max, minus dedupe from inserting 'b' / 'c' /
    # 'p' next to themselves (3 collisions). Lower bound 100.
    assert 100 <= len(variants) <= 104
    assert "abcp" in variants  # insert 'a' at front
    assert "bcpz" in variants  # insert 'z' at back
    assert "bcap" in variants  # insert 'a' in middle


def test_replacement_uses_keyboard_neighbours():
    """'b' has QWERTY neighbours v/g/h/n — replacements at position 0
    of 'bcp' produce 4 variants."""
    variants = _generate_replacements("bcp")
    expected_b_replacements = {"vcp", "gcp", "hcp", "ncp"}
    assert expected_b_replacements <= variants


def test_homoglyph_swaps_visually_similar():
    variants = _generate_homoglyphs("bcp")
    # 'b' → '8' or '6' — both should be in the set.
    assert any("8cp" == v or "6cp" == v for v in variants)


def test_idn_homoglyph_produces_punycode_a_label():
    """The Cyrillic 'с' (U+0441) substitution must round-trip through
    `idna.encode` to an xn--... ASCII label DNS can resolve."""
    pairs = _generate_idn_homoglyphs("bcp")
    if not pairs:
        pytest.skip("no IDN homoglyphs for this label")
    for display, ascii_label in pairs:
        assert ascii_label.startswith("xn--"), (
            f"IDN ascii form must be punycode: got {ascii_label!r}"
        )
        # Display form must contain at least one non-ASCII character.
        assert any(ord(ch) > 127 for ch in display)


def test_idn_homoglyph_skips_pure_ascii_roundtrip():
    """If the homoglyph table happens to include a Latin-only
    substitution (shouldn't, but defensive), the result would
    round-trip to the same ASCII — must be filtered out.

    Label uses chars NOT in the IDN homoglyph table (b/d/f) so
    the result is naturally empty."""
    pairs = _generate_idn_homoglyphs("bdf")
    assert pairs == set()


def test_tld_swap_replaces_suffix():
    variants = _generate_tld_swaps("bcp", ".com.py")
    assert "bcp.com.ar" in variants
    assert "bcp.com.uy" in variants
    # Original suffix must NOT be in the swap set.
    assert "bcp.com.py" not in variants


# =====================================================================
# generate_typosquats — public API
# =====================================================================


def test_generate_returns_typosquat_candidates():
    candidates = generate_typosquats("bcp.com.py", max_variants=20)
    assert candidates
    assert all(isinstance(c, TyposquatCandidate) for c in candidates)
    assert all(c.original_domain == "bcp.com.py" for c in candidates)


def test_generate_excludes_original():
    candidates = generate_typosquats("bcp.com.py")
    variants = {c.variant for c in candidates}
    assert "bcp.com.py" not in variants


def test_generate_deduplicates_across_strategies():
    """Same variant produced by two strategies should appear once."""
    candidates = generate_typosquats("bcp.com.py")
    variants = [c.variant for c in candidates]
    assert len(variants) == len(set(variants))


def test_generate_honors_max_variants_cap():
    candidates = generate_typosquats("bcp.com.py", max_variants=10)
    assert len(candidates) <= 10


def test_generate_strategy_subset():
    """Restricting to one strategy → only that strategy in output."""
    candidates = generate_typosquats(
        "bcp.com.py",
        strategies=("omission",),
        max_variants=100,
    )
    assert candidates
    assert {c.strategy for c in candidates} == {"omission"}


def test_generate_empty_domain_returns_empty():
    assert generate_typosquats("") == []
    assert generate_typosquats("   ") == []


def test_generate_marks_strategy_correctly():
    """Pin the strategy labels — downstream reports group on them."""
    candidates = generate_typosquats("bcp.com.py", max_variants=200)
    strategies_seen = {c.strategy for c in candidates}
    # Every requested strategy should produce at least one candidate
    # on a 3-letter label (mostly fertile for all 7 strategies).
    assert strategies_seen.issubset(set(ALL_STRATEGIES))
    # transposition + omission + replacement + addition all produce
    # candidates on "bcp".
    assert {"transposition", "omission", "addition", "replacement"} <= strategies_seen


def test_generate_idn_candidate_has_display_form():
    """IDN candidates must carry the human-readable display form so
    a report can show "bcр.com.py" instead of just xn--bp-zlc.com.py."""
    candidates = generate_typosquats("bcp.com.py", strategies=("idn_homoglyph",))
    idn = [c for c in candidates if c.strategy == "idn_homoglyph"]
    if not idn:
        pytest.skip("no IDN candidates for this label")
    for c in idn:
        assert c.variant.startswith("xn--") or "xn--" in c.variant
        # Display form contains a non-ASCII char.
        assert any(ord(ch) > 127 for ch in c.display_variant)


# =====================================================================
# DNS resolver — fire gate
# =====================================================================


def _candidate(variant: str = "bcp1.com.py", strategy: str = "addition") -> TyposquatCandidate:
    return TyposquatCandidate(
        original_domain="bcp.com.py",
        variant=variant,
        display_variant=variant,
        strategy=strategy,
    )


def test_resolve_dry_run_default_returns_dry_run_no_network():
    with patch("kryon.brand.typosquat.socket.getaddrinfo") as mock_resolve:
        result = resolve_candidate(_candidate(), fire=False)
    assert result.verdict == "dry_run"
    mock_resolve.assert_not_called()


def test_resolve_fire_without_env_stays_dry_run(monkeypatch):
    monkeypatch.delenv("KRYON_BRAND_FIRE", raising=False)
    with patch("kryon.brand.typosquat.socket.getaddrinfo") as mock_resolve:
        result = resolve_candidate(_candidate(), fire=True)
    assert result.verdict == "dry_run"
    mock_resolve.assert_not_called()


def test_resolve_live_returns_registered_with_ips(monkeypatch):
    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")
    fake_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.1", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.2", 0)),
    ]
    with patch("kryon.brand.typosquat.socket.getaddrinfo", return_value=fake_addrinfo):
        result = resolve_candidate(_candidate(), fire=True)
    assert result.verdict == "registered"
    assert "203.0.113.1" in result.ip_addresses
    assert "203.0.113.2" in result.ip_addresses


def test_resolve_nxdomain_returns_not_resolving(monkeypatch):
    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")
    with patch(
        "kryon.brand.typosquat.socket.getaddrinfo",
        side_effect=socket.gaierror("Name or service not known"),
    ):
        result = resolve_candidate(_candidate(), fire=True)
    assert result.verdict == "not_resolving"
    assert result.ip_addresses == ()


def test_resolve_oserror_returns_error_verdict(monkeypatch):
    """Network-level failure (timeout, no route) classifies as error,
    not not_resolving — the operator can distinguish 'definitely
    NXDOMAIN' from 'we couldn't tell'."""
    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")
    with patch(
        "kryon.brand.typosquat.socket.getaddrinfo",
        side_effect=OSError("connection refused"),
    ):
        result = resolve_candidate(_candidate(), fire=True)
    assert result.verdict == "error"
    assert result.error and "OSError" in result.error


def test_resolve_empty_addrinfo_returns_not_resolving(monkeypatch):
    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")
    with patch("kryon.brand.typosquat.socket.getaddrinfo", return_value=[]):
        result = resolve_candidate(_candidate(), fire=True)
    assert result.verdict == "not_resolving"


def test_resolve_restores_socket_timeout_on_error(monkeypatch):
    """Banca-safety: the resolver mutates the global socket timeout.
    If a query raises, the timeout MUST be restored or other code
    in the same interpreter session inherits the wrong value."""
    monkeypatch.setenv("KRYON_BRAND_FIRE", "true")
    original = socket.getdefaulttimeout()
    with patch(
        "kryon.brand.typosquat.socket.getaddrinfo",
        side_effect=OSError("boom"),
    ):
        resolve_candidate(_candidate(), fire=True)
    assert socket.getdefaulttimeout() == original


# =====================================================================
# Tool wrapper
# =====================================================================


def test_tool_generate_mode_returns_candidates():
    """Helper functions used by the tool wrapper — exercise them
    directly since @function_tool wraps the callable."""
    from kryon.brand.typosquat_tool import _scan_summary

    candidates = generate_typosquats("bcp.com.py", max_variants=10)
    assert candidates
    # _scan_summary on an empty results list must not crash.
    summary = _scan_summary([])
    assert summary["total_candidates"] == 0
    assert summary["registered_count"] == 0


def test_tool_scan_summary_buckets_by_verdict_and_strategy():
    from kryon.brand.typosquat_tool import _scan_summary

    results = [
        TyposquatScanResult(
            candidate=_candidate(strategy="transposition"),
            verdict="registered",
            ip_addresses=("1.2.3.4",),
        ),
        TyposquatScanResult(
            candidate=_candidate(variant="bp.com.py", strategy="omission"),
            verdict="not_resolving",
        ),
        TyposquatScanResult(
            candidate=_candidate(variant="bxp.com.py", strategy="replacement"),
            verdict="registered",
            ip_addresses=("5.6.7.8",),
        ),
    ]
    summary = _scan_summary(results)
    assert summary["total_candidates"] == 3
    assert summary["by_verdict"] == {"registered": 2, "not_resolving": 1}
    assert summary["registered_count"] == 2
    # Only registered variants surfaced explicitly.
    assert len(summary["registered"]) == 2
    assert all("ips" in entry for entry in summary["registered"])


# =====================================================================
# Frozen contracts
# =====================================================================


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    c = _candidate()
    with pytest.raises(FrozenInstanceError):
        c.variant = "mutated"  # type: ignore[misc]

    r = TyposquatScanResult(candidate=c, verdict="dry_run")
    with pytest.raises(FrozenInstanceError):
        r.verdict = "registered"  # type: ignore[misc]
