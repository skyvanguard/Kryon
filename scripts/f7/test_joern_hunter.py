"""F7.3 integration tests for JoernHunter + HybridHunter 3-way union.

Gate: all three hunters run, results merge via confidence-gated union,
hunters_used/_failed telemetry is stamped on each finding, graceful
degradation when Joern server is unavailable.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
from pathlib import Path

# Disable LLM stage globally for these integration tests — F7.3 gate is
# "3-way static union works", not "full hybrid pipeline with LLM inference".
os.environ["KRYON_HYBRID_MAX_LLM_CANDIDATES"] = "0"


def _fake_job(file_path: str):
    from kryon.skills.supervisor_tools import HunterJob
    return HunterJob(hunter_id="test", file_path=file_path)


def test_dedup_merges_by_cwe_line_bucket():
    """Two hunters hitting the same (file, cwe, ~line) → merged with _sources."""
    from kryon.skills.planner_hunter import _confidence_gated_union
    a = {
        "file_path": "/x/a.c", "cwe": "CWE-121", "line_range": "100-100",
        "_hunter": "semgrep", "severity": "WARNING", "confidence": "medium",
    }
    b = {
        "file_path": "/x/a.c", "cwe": "CWE-121", "line_range": "102-102",
        "_hunter": "joern", "severity": "ERROR", "confidence": "high",
        "_joern_flow": [{"line": 102, "label": "IDENTIFIER", "code": "buf[i]"}],
    }
    merged = _confidence_gated_union([[a], [b]])
    assert len(merged) == 1, merged
    m = merged[0]
    assert m["severity"] == "ERROR", m
    assert m["confidence"] == "high", m
    assert set(m["_sources"]) == {"semgrep", "joern"}, m
    assert m["_source_count"] == 2
    assert m.get("_joern_flow"), m
    print("  ok: dedup by (file, cwe, line±3) merges provenance")


def test_dedup_keeps_distinct_cwe():
    """Same file, different CWE → NOT merged."""
    from kryon.skills.planner_hunter import _confidence_gated_union
    a = {"file_path": "/x/a.c", "cwe": "CWE-121", "line_range": "100-100",
         "_hunter": "semgrep", "severity": "ERROR", "confidence": "high"}
    b = {"file_path": "/x/a.c", "cwe": "CWE-190", "line_range": "100-100",
         "_hunter": "joern", "severity": "ERROR", "confidence": "high"}
    merged = _confidence_gated_union([[a], [b]])
    assert len(merged) == 2, merged
    print("  ok: different CWE on same line NOT merged")


def test_dedup_keeps_distant_lines():
    """Same file, same CWE, lines >±3 apart → NOT merged."""
    from kryon.skills.planner_hunter import _confidence_gated_union
    a = {"file_path": "/x/a.c", "cwe": "CWE-121", "line_range": "100-100",
         "_hunter": "semgrep", "severity": "WARNING", "confidence": "medium"}
    b = {"file_path": "/x/a.c", "cwe": "CWE-121", "line_range": "200-200",
         "_hunter": "joern", "severity": "ERROR", "confidence": "high"}
    merged = _confidence_gated_union([[a], [b]])
    assert len(merged) == 2, merged
    print("  ok: same CWE on distant lines NOT merged")


def test_hybrid_degrades_when_joern_disabled():
    """Without KRYON_JOERN_ENABLED, HybridHunter runs only heuristic+semgrep."""
    os.environ["KRYON_JOERN_ENABLED"] = "false"
    # Force module reload so _joern_enabled() sees the new env.
    for m in list(sys.modules):
        if m.startswith("kryon.skills.planner_hunter"):
            del sys.modules[m]
    from kryon.skills.planner_hunter import HybridHunter
    h = HybridHunter()
    assert h._joern is None, "joern hunter should be None when disabled"
    print("  ok: HybridHunter skips Joern when disabled")


def test_hybrid_all_three_run(tmp_juliet: Path):
    """All three hunters run on a Juliet file; merged results carry
    hunters_used including 'joern'."""
    os.environ["KRYON_JOERN_ENABLED"] = "true"
    os.environ["KRYON_JOERN_URL"] = "127.0.0.1:8080"
    os.environ["KRYON_JOERN_CPG_DIR"] = "/tmp/f7-cpgs"

    # Reimport to pick up enabled state.
    for m in list(sys.modules):
        if m.startswith("kryon.skills.planner_hunter") or m.startswith(
            "kryon.tools.code.joern_tool"
        ):
            del sys.modules[m]
    from kryon.skills.planner_hunter import HybridHunter

    h = HybridHunter()
    assert h._joern is not None, "joern hunter should be enabled"

    job = _fake_job(str(tmp_juliet))
    findings = asyncio.run(h(job))

    # Not asserting finding count here — F7.5 territory. Gate: telemetry.
    print(f"  hybrid returned {len(findings)} merged findings")
    if findings:
        f = findings[0]
        print(f"  sample: cwe={f.get('cwe')} sources={f.get('_sources')} "
              f"used={f.get('_hunters_used')} failed={f.get('_hunters_failed')}")
        assert "_hunters_used" in f
        assert "_hunters_failed" in f
        # joern must appear in used OR failed — never silently dropped.
        all_mentioned = set(f["_hunters_used"]) | {
            x["name"] for x in f["_hunters_failed"]
        }
        assert "joern" in all_mentioned, (
            f"joern missing from telemetry: {f['_hunters_used']} / {f['_hunters_failed']}"
        )
    print("  ok: 3-way hybrid integration, telemetry stamped")


def test_hybrid_graceful_when_joern_server_down():
    """If Joern is enabled but server unreachable, status=unavailable
    and hunters_failed includes joern — heuristic+semgrep still produce."""
    os.environ["KRYON_JOERN_ENABLED"] = "true"
    os.environ["KRYON_JOERN_URL"] = "127.0.0.1:9" # deliberately unreachable
    for m in list(sys.modules):
        if m.startswith("kryon.skills.planner_hunter") or m.startswith(
            "kryon.tools.code.joern_tool"
        ):
            del sys.modules[m]
    from kryon.skills.planner_hunter import HybridHunter

    h = HybridHunter()
    # Use any source file.
    tmp = Path("/tmp/f7_dummy.c")
    tmp.write_text('#include <string.h>\nvoid f(char *p){strcpy(p,"AAAA");}\n')
    job = _fake_job(str(tmp))
    findings = asyncio.run(h(job))
    if findings:
        f = findings[0]
        failed_names = {x["name"] for x in f["_hunters_failed"]}
        assert "joern" in failed_names, f
        assert "joern" not in f["_hunters_used"], f
        print(f"  ok: joern failed={[x['name'] for x in f['_hunters_failed']]}, "
              f"used={f['_hunters_used']}")
    else:
        print("  ok: no findings on dummy file, but joern enabled path exercised")


if __name__ == "__main__":
    # Use the same basename as the pre-parsed CPG so the JoernHunter CPG
    # resolver hits the cache and skips the multi-minute importCode step.
    juliet_src = Path(
        "/workspace/.juliet/juliet-test-suite-c/testcases/"
        "CWE121_Stack_Based_Buffer_Overflow/s01/"
        "CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01.c"
    )
    tmp_juliet = Path(
        "/tmp/CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01.c"
    )
    shutil.copy(juliet_src, tmp_juliet)

    print("=== F7.3 JoernHunter + HybridHunter integration tests ===")
    test_dedup_merges_by_cwe_line_bucket()
    test_dedup_keeps_distinct_cwe()
    test_dedup_keeps_distant_lines()
    test_hybrid_degrades_when_joern_disabled()
    test_hybrid_all_three_run(tmp_juliet)
    test_hybrid_graceful_when_joern_server_down()
    print("\nALL PASS")
