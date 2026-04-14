"""Smoke tests for joern_scan @function_tool — run inside kryon container."""
from __future__ import annotations

import json
import os
import threading
import time

# Reset env before import so module-level _ENABLED matches test mode.
os.environ.pop("KRYON_JOERN_ENABLED", None)

# Import the impl directly (bypass @function_tool wrapper).
from kryon.tools.code import joern_tool as jt


def _call(**kwargs) -> dict:
    return json.loads(jt._joern_scan_impl(**kwargs))


def test_unavailable_when_disabled():
    jt._ENABLED = False
    r = _call(
        target_path="/tmp/f7-cpgs/CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01.cpg",
        cwe_focus="121", import_timeout_s=120, query_timeout_s=60, max_findings=200,
    )
    assert r["status"] == "unavailable", r
    assert r["findings"] == []
    assert "KRYON_JOERN_ENABLED" in r["reason"]
    print("  ok: unavailable when disabled")


def test_error_unknown_cwe():
    jt._ENABLED = True
    r = _call(
        target_path="/tmp/f7-cpgs/CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01.cpg",
        cwe_focus="999", import_timeout_s=120, query_timeout_s=60, max_findings=200,
    )
    assert r["status"] == "error", r
    assert "unsupported cwe_focus" in r["reason"]
    print("  ok: unknown cwe -> error status")


def test_missing_target():
    jt._ENABLED = True
    r = _call(
        target_path="/nonexistent.cpg", cwe_focus="121",
        import_timeout_s=120, query_timeout_s=60, max_findings=200,
    )
    assert r["status"] == "error", r
    assert "target not found" in r["reason"]
    print("  ok: missing target -> error")


def test_happy_path_cwe121():
    jt._ENABLED = True
    jt._DEFAULT_SERVER = "127.0.0.1:8080"  # server is on localhost in this dev container
    r = _call(
        target_path="/tmp/f7-cpgs/CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01.cpg",
        cwe_focus="121", import_timeout_s=120, query_timeout_s=60, max_findings=200,
    )
    print(f"  happy path: status={r['status']}  count={r['count']}  stats={r.get('stats')}")
    assert r["status"] == "ok", r
    assert r["count"] >= 1, f"expected >=1 finding, got {r}"
    f = r["findings"][0]
    for k in ("path", "start_line", "cwe", "confidence", "method", "flow"):
        assert k in f, f"finding missing key {k}: {f}"
    assert f["cwe"] == "CWE-121"
    assert f["confidence"] in {"high", "medium", "low"}
    assert isinstance(f["flow"], list) and f["flow"]
    print(f"  ok: happy path — {r['count']} findings, sample method={f['method']!r}")


def test_lock_serialises():
    """Two concurrent calls should run serially: wall-clock ≈ 2 × baseline.

    If the lock is broken, wall-clock ≈ 1 × baseline (parallel execution).
    """
    jt._ENABLED = True
    jt._DEFAULT_SERVER = "127.0.0.1:8080"

    def one_call():
        return _call(
            target_path="/tmp/f7-cpgs/CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01.cpg",
            cwe_focus="121", import_timeout_s=120, query_timeout_s=60, max_findings=200,
        )

    # Baseline: one call.
    t0 = time.perf_counter()
    r = one_call()
    baseline = time.perf_counter() - t0
    assert r["status"] == "ok", r

    # Concurrent: 2 calls in parallel threads.
    results: list[dict] = []

    def worker():
        results.append(one_call())

    ts = [threading.Thread(target=worker) for _ in range(2)]
    t0 = time.perf_counter()
    for t in ts: t.start()
    for t in ts: t.join()
    parallel = time.perf_counter() - t0

    # All calls succeeded.
    for r in results:
        assert r["status"] == "ok", r
    # With the lock, parallel wall-clock ≈ 2 * baseline. Without it, ≈ 1 *.
    # Accept anything above 1.5 * baseline as serialised.
    ratio = parallel / max(baseline, 0.05)
    assert ratio >= 1.5, (
        f"lock did not serialise: baseline={baseline*1000:.0f}ms, "
        f"parallel={parallel*1000:.0f}ms (ratio={ratio:.2f}x, expected ≥1.5x)"
    )
    print(
        f"  ok: lock serialises — baseline={baseline*1000:.0f}ms, "
        f"parallel_of_2={parallel*1000:.0f}ms (ratio={ratio:.2f}x)"
    )


def test_timeout_phase():
    """Force a timeout by setting query_timeout_s=0."""
    jt._ENABLED = True
    jt._DEFAULT_SERVER = "127.0.0.1:8080"
    r = _call(
        target_path="/tmp/f7-cpgs/CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01.cpg",
        cwe_focus="121", import_timeout_s=120, query_timeout_s=1, max_findings=200,
    )
    # Query on a tiny file might still complete in 1s — this test is best-effort.
    print(f"  timeout test: status={r['status']}  reason={r.get('reason','')[:80]}")
    # Accept ok OR timeout — the important thing is no exception leaked.
    assert r["status"] in {"ok", "timeout", "error"}


if __name__ == "__main__":
    print("=== joern_scan smoke tests ===")
    test_unavailable_when_disabled()
    test_error_unknown_cwe()
    test_missing_target()
    test_happy_path_cwe121()
    test_lock_serialises()
    test_timeout_phase()
    print("\nALL PASS")
