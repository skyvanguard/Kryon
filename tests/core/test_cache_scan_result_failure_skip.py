"""F164 — ``cache_scan_result`` must NOT cache failed scan results.

The decorator's original implementation cached every return value of the
wrapped scan tool, including failures like ``/bin/sh: 1: nuclei: not
found`` or ``[KRYON_TOOL_ERROR] ...`` envelopes emitted by tool wrappers
when the underlying binary is missing.

Because the TTL is 12 hours for vuln scans, a single failed run (e.g.
right after a Docker rebuild where the binary install silently failed)
would keep poisoning subsequent scans for the rest of the day — even
after the operator fixes the install. This was the root cause of the
F163 bench reporting 0 findings: the F163e run cached the
``nuclei: not found`` error, and F163f/F163g all hit the cache instead
of re-running the freshly-installed binary.

The fix: detect failure markers in the return value and skip the
``cache.cache_scan(...)`` call so future invocations get to retry.
"""

from __future__ import annotations

import pytest

from kryon.cache.scan_cache import cache_scan_result


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_cache(monkeypatch):
    """Use an in-memory cache per test so the global on-disk cache
    doesn't leak between tests."""
    from kryon.cache import scan_cache as sc_module
    from kryon.cache.cache_manager import CacheManager

    fresh = CacheManager(enable_persistence=False)

    class _FreshScanCache(sc_module.ScanCache):
        def __init__(self):
            super().__init__(cache_manager=fresh)

    monkeypatch.setattr(sc_module, "_global_scan_cache", None)
    monkeypatch.setattr(sc_module, "ScanCache", _FreshScanCache)
    yield


# ---------------------------------------------------------------------------
# Happy path — successful scans still cache (no regression)
# ---------------------------------------------------------------------------


def test_successful_scan_is_cached():
    call_count = {"n": 0}

    @cache_scan_result(scan_type="vuln_scan", ttl=300)
    def my_scan(args: str, target: str, ctf=None) -> str:
        call_count["n"] += 1
        return f"OK: 3 findings on {target}"

    r1 = my_scan("args", target="http://x.example")
    r2 = my_scan("args", target="http://x.example")
    assert r1 == r2 == "OK: 3 findings on http://x.example"
    # Second call served from cache → wrapped function ran only once.
    assert call_count["n"] == 1


# ---------------------------------------------------------------------------
# Failure markers — these must NOT be cached
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure_output",
    [
        "/bin/sh: 1: nuclei: not found",
        "/bin/bash: nuclei: command not found",
        "[KRYON_TOOL_ERROR] nuclei_scan did NOT execute successfully.\nReason: empty_output",
        "sh: nuclei: not found",
        "[FTL] could not find template",
        "Command 'nuclei' not found, but can be installed with:",
    ],
)
def test_failure_output_not_cached(failure_output):
    """Each of these markers indicates the scan never actually ran. The
    cache MUST skip them so the operator can fix the install and retry."""
    call_count = {"n": 0}

    @cache_scan_result(scan_type="vuln_scan", ttl=300)
    def broken_scan(args: str, target: str, ctf=None) -> str:
        call_count["n"] += 1
        return failure_output

    r1 = broken_scan("args", target="http://x.example")
    r2 = broken_scan("args", target="http://x.example")
    # Same failure both times — but the function was called twice
    # because the first failure was NOT cached.
    assert r1 == r2 == failure_output
    assert call_count["n"] == 2, (
        f"Expected 2 calls (failure not cached) for marker: {failure_output!r}"
    )


# ---------------------------------------------------------------------------
# Mixed: failure first, success second → second one wins
# ---------------------------------------------------------------------------


def test_recovery_after_failure():
    """The killer scenario from F163e→F163f: failure first (binary
    missing), then success after install. The success must be cached."""
    state = {"installed": False, "calls": 0}

    @cache_scan_result(scan_type="vuln_scan", ttl=300)
    def my_scan(args: str, target: str, ctf=None) -> str:
        state["calls"] += 1
        if not state["installed"]:
            return "/bin/sh: 1: nuclei: not found"
        return "OK: 5 findings on " + target

    r1 = my_scan("args", target="http://x.example")
    assert "not found" in r1
    state["installed"] = True
    r2 = my_scan("args", target="http://x.example")
    assert "5 findings" in r2
    r3 = my_scan("args", target="http://x.example")
    assert r3 == r2  # Third call served from cache.
    assert state["calls"] == 2  # First failure + first success.


# ---------------------------------------------------------------------------
# Non-string returns shouldn't crash
# ---------------------------------------------------------------------------


def test_non_string_return_is_cached_normally():
    """Some tools return dicts. Failure detection only applies to strings —
    don't crash on other shapes."""
    call_count = {"n": 0}

    @cache_scan_result(scan_type="vuln_scan", ttl=300)
    def dict_scan(args: str, target: str, ctf=None) -> dict:
        call_count["n"] += 1
        return {"findings": 2, "target": target}

    r1 = dict_scan("args", target="http://x.example")
    r2 = dict_scan("args", target="http://x.example")
    assert r1 == r2
    assert call_count["n"] == 1


def test_empty_output_treated_as_failure():
    """Empty string from a scan tool means the binary produced nothing —
    almost always a missing-binary or fatal-config error, never a real
    'no findings' result. Don't cache it."""
    call_count = {"n": 0}

    @cache_scan_result(scan_type="vuln_scan", ttl=300)
    def empty_scan(args: str, target: str, ctf=None) -> str:
        call_count["n"] += 1
        return ""

    empty_scan("args", target="http://x.example")
    empty_scan("args", target="http://x.example")
    assert call_count["n"] == 2  # Both calls ran (empty not cached).


# ---------------------------------------------------------------------------
# Legitimate "no findings" results MUST still cache
# ---------------------------------------------------------------------------


def test_legitimate_no_findings_is_cached():
    """A real scan that ran and returned 0 findings (legitimate clean
    target) MUST still cache — otherwise we'd re-scan every time."""
    call_count = {"n": 0}

    @cache_scan_result(scan_type="vuln_scan", ttl=300)
    def clean_scan(args: str, target: str, ctf=None) -> str:
        call_count["n"] += 1
        return "[INF] Templates loaded: 4523\nNo results found for the target."

    clean_scan("args", target="http://clean.example")
    clean_scan("args", target="http://clean.example")
    assert call_count["n"] == 1  # Second call hit cache.
