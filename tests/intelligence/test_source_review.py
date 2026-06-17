"""Tests for the Mythos-style source-review harness.

Every test runs offline — the LLM is replaced by a fake ``Reviewer`` so
the orchestration + parsing logic is exercised without a live model.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kryon.intelligence.source_review import (
    OllamaReviewer,
    SourceFinding,
    SourceReviewResult,
    build_review_prompt,
    collect_variant_targets,
    dedup_findings,
    enumerate_source_files,
    format_report_markdown,
    parse_findings_json,
    rank_findings,
    review_tree,
    score_file_risk,
    strip_think,
    triage_files,
)

# ---------------------------------------------------------------------------
# enumeration
# ---------------------------------------------------------------------------


def _write(p: Path, content: str = "x = 1\n") -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_enumerate_skips_vendor_and_non_source(tmp_path: Path):
    _write(tmp_path / "app.py")
    _write(tmp_path / "node_modules" / "dep.js")
    _write(tmp_path / "vendor" / "lib.go")
    _write(tmp_path / "README.md")
    _write(tmp_path / "src" / "core.c")
    # Build-time codegen / assembly generators + test trees are build tooling,
    # not product attack surface — they swamped the sink-density triage with
    # CWE-78 noise (OpenSSL's crypto/*/asm/*.pl) and crowded out real source.
    _write(tmp_path / "crypto" / "sha" / "asm" / "sha1-x86_64.pl")
    _write(tmp_path / "perlasm" / "gen.pl")
    _write(tmp_path / "test" / "harness.c")
    _write(tmp_path / "tests" / "fuzz.c")

    files = enumerate_source_files(tmp_path)
    names = {p.name for p in files}

    assert names == {"app.py", "core.c"}


def test_enumerate_respects_size_cap(tmp_path: Path):
    _write(tmp_path / "small.py", "a = 1\n")
    _write(tmp_path / "big.py", "x" * 1000)

    files = enumerate_source_files(tmp_path, max_file_bytes=100)

    assert [p.name for p in files] == ["small.py"]


def test_enumerate_single_file(tmp_path: Path):
    f = _write(tmp_path / "only.py")
    assert enumerate_source_files(f) == [f]


# ---------------------------------------------------------------------------
# triage
# ---------------------------------------------------------------------------


def test_score_file_risk_counts_sinks():
    safe = "def add(a, b):\n    return a + b\n"
    risky = "os.system(user_input)\neval(payload)\nstrcpy(dst, src)\n"

    assert score_file_risk(safe) == 0
    assert score_file_risk(risky) >= 3


def test_triage_ranks_risky_first(tmp_path: Path):
    safe = _write(tmp_path / "safe.py", "return 1 + 1\n")
    risky = _write(tmp_path / "risky.py", "os.system(x)\neval(y)\n")

    ranked = triage_files([safe, risky])

    assert ranked[0][0] == risky
    assert ranked[0][1] > ranked[1][1]


# ---------------------------------------------------------------------------
# think-stripping + JSON extraction + parsing
# ---------------------------------------------------------------------------


def test_strip_think_removes_block():
    raw = '<think>let me reason about this</think>\n[{"x": 1}]'
    assert strip_think(raw) == '[{"x": 1}]'


def test_strip_think_drops_unterminated_trailing():
    raw = "[]\n<think>truncated reasoning that never closed"
    assert strip_think(raw) == "[]"


def test_parse_findings_from_plain_array():
    raw = (
        '[{"line": 42, "cwe": "CWE-89", "severity": "HIGH", '
        '"title": "SQLi", "evidence": "query(x+y)", "sink": "query(", '
        '"confidence": 0.9}]'
    )
    findings = parse_findings_json(raw, file="a.py")

    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == "CWE-89"
    assert f.line == 42
    assert f.severity == "HIGH"
    assert f.confidence == pytest.approx(0.9)
    assert f.sink == "query("


def test_parse_findings_strips_think_and_fences():
    raw = '<think>reasoning here</think>\n```json\n[{"line": 7, "cwe": "79", "severity": "low"}]\n```'
    findings = parse_findings_json(raw, file="x.js")

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-79"  # bare number coerced
    assert findings[0].severity == "LOW"  # case-normalized


def test_parse_findings_tolerates_garbage_and_clamps():
    raw = (
        '[{"line": "not-a-number", "cwe": "CWE-22", "severity": "WEIRD", "confidence": 5.0}, "junk", {"no_cwe": true}]'
    )
    findings = parse_findings_json(raw, file="p.c")

    # only the first dict is salvageable (has a CWE); junk + cwe-less dropped
    assert len(findings) == 1
    f = findings[0]
    assert f.line == 0  # bad int -> 0
    assert f.severity == "MEDIUM"  # unknown sev -> default
    assert f.confidence == 1.0  # clamped from 5.0


def test_parse_findings_empty_and_nonjson():
    assert parse_findings_json("[]", file="a.py") == []
    assert parse_findings_json("no json here", file="a.py") == []
    assert parse_findings_json("<think>only reasoning</think>", file="a.py") == []


def test_build_review_prompt_numbers_lines_and_truncates():
    code = "line1\nline2\nline3\n"
    prompt = build_review_prompt("f.py", code)
    assert "f.py" in prompt
    assert "    1  line1" in prompt
    big = "a\n" * 50_000
    pr = build_review_prompt("big.py", big, max_code_chars=100)
    assert "truncated" in pr


# ---------------------------------------------------------------------------
# dedup + rank
# ---------------------------------------------------------------------------


def test_dedup_keeps_highest_confidence():
    a = SourceFinding(file="x.py", line=1, cwe="CWE-89", severity="HIGH", title="t", confidence=0.4)
    b = SourceFinding(file="x.py", line=1, cwe="CWE-89", severity="HIGH", title="t", confidence=0.8)
    out = dedup_findings([a, b])
    assert len(out) == 1
    assert out[0].confidence == pytest.approx(0.8)


def test_rank_orders_by_severity_then_confidence():
    low = SourceFinding(file="a", line=1, cwe="CWE-1", severity="LOW", title="t", confidence=0.9)
    crit = SourceFinding(file="b", line=2, cwe="CWE-2", severity="CRITICAL", title="t", confidence=0.5)
    high = SourceFinding(file="c", line=3, cwe="CWE-3", severity="HIGH", title="t", confidence=0.6)
    ranked = rank_findings([low, crit, high])
    assert [f.severity for f in ranked] == ["CRITICAL", "HIGH", "LOW"]


# ---------------------------------------------------------------------------
# variant analysis
# ---------------------------------------------------------------------------


def test_collect_variant_targets_finds_sink_elsewhere(tmp_path: Path):
    _write(tmp_path / "seed.py", "os.system(cmd)\n")
    other = _write(tmp_path / "other.py", "value = os.system(again)\n")
    _write(tmp_path / "clean.py", "return 1\n")

    seed_finding = SourceFinding(
        file="seed.py",
        line=1,
        cwe="CWE-78",
        severity="HIGH",
        title="cmd injection",
        sink="os.system(",
        confidence=0.9,
    )
    reviewed = {tmp_path / "seed.py"}

    targets = collect_variant_targets(tmp_path, [seed_finding], reviewed)

    assert other in targets
    assert (tmp_path / "clean.py") not in targets


def test_collect_variant_targets_ignores_low_confidence():
    seed = SourceFinding(
        file="seed.py",
        line=1,
        cwe="CWE-78",
        severity="HIGH",
        title="t",
        sink="os.system(",
        confidence=0.3,
    )
    assert collect_variant_targets(Path("."), [seed], set()) == []


# ---------------------------------------------------------------------------
# end-to-end review_tree with a fake reviewer
# ---------------------------------------------------------------------------


def test_review_tree_end_to_end(tmp_path: Path):
    _write(tmp_path / "vuln.py", "os.system(user)\n")
    _write(tmp_path / "also.py", "x = os.system(other)\n")
    _write(tmp_path / "safe.py", "return 2 + 2\n")

    def fake_reviewer(rel_path: str, code: str) -> list[SourceFinding]:
        if "os.system(" in code:
            return [
                SourceFinding(
                    file=rel_path,
                    line=1,
                    cwe="CWE-78",
                    severity="HIGH",
                    title="OS command injection",
                    sink="os.system(",
                    confidence=0.9,
                )
            ]
        return []

    result = review_tree(tmp_path, reviewer=fake_reviewer, clock=lambda: 0.0)

    assert isinstance(result, SourceReviewResult)
    assert result.files_total == 3
    # both vuln files flagged (one in primary pass, the other reachable via
    # variant analysis on the os.system( sink)
    files = {f.file for f in result.findings}
    assert "vuln.py" in files
    assert "also.py" in files
    assert all(f.cwe == "CWE-78" for f in result.findings)


def test_review_tree_empty_tree(tmp_path: Path):
    result = review_tree(tmp_path, reviewer=lambda r, c: [], clock=lambda: 0.0)
    assert result.files_total == 0
    assert result.findings == []


def test_review_tree_reviewer_exception_is_contained(tmp_path: Path):
    _write(tmp_path / "a.py", "os.system(x)\n")

    def boom(rel_path: str, code: str) -> list[SourceFinding]:
        raise RuntimeError("model exploded")

    result = review_tree(tmp_path, reviewer=boom, variant_analysis=False, clock=lambda: 0.0)
    assert result.findings == []
    assert any("model exploded" in e for e in result.errors)


def test_review_tree_respects_max_files(tmp_path: Path):
    for i in range(5):
        _write(tmp_path / f"f{i}.py", "os.system(x)\n")
    seen: list[str] = []

    def rec(rel_path: str, code: str) -> list[SourceFinding]:
        seen.append(rel_path)
        return []

    review_tree(tmp_path, reviewer=rec, max_files=2, variant_analysis=False, clock=lambda: 0.0)
    assert len(seen) == 2


# ---------------------------------------------------------------------------
# conversion + report
# ---------------------------------------------------------------------------


def test_to_engage_finding_maps_fields():
    f = SourceFinding(
        file="src/x.py",
        line=10,
        cwe="CWE-89",
        severity="high",
        title="SQLi",
        description="concat in query",
        evidence="q(x+y)",
        confidence=0.7,
    )
    ef = f.to_engage_finding()
    assert ef.cwe == "CWE-89"
    assert ef.severity == "HIGH"
    assert ef.host == "src/x.py"
    assert ef.rule_id == "SAST-CWE-89"
    assert ef.needs_verification is True
    assert ef.confidence == pytest.approx(0.7)
    assert "SQLi" in ef.message


def test_format_report_markdown():
    result = SourceReviewResult(
        findings=[
            SourceFinding(
                file="a.py",
                line=5,
                cwe="CWE-78",
                severity="CRITICAL",
                title="cmd inj",
                evidence="os.system(x)",
                confidence=0.95,
            )
        ],
        files_total=10,
        files_reviewed=8,
        variant_files_reviewed=2,
        elapsed_seconds=1.5,
    )
    md = format_report_markdown(result, root_label="/tmp/proj")
    assert "CWE-78" in md
    assert "a.py:5" in md
    assert "/tmp/proj" in md
    assert "os.system(x)" in md


def test_format_report_no_findings():
    md = format_report_markdown(SourceReviewResult(files_total=3, files_reviewed=3))
    assert "No vulnerabilities" in md


def test_local_reviewer_defaults(monkeypatch):
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("KRYON_SOURCE_REVIEW_BASE_URL", raising=False)
    r = OllamaReviewer()  # alias of LocalReviewer (OpenAI-compatible / llama.cpp)
    assert r.model == "kryon-devstral-24b"
    assert "8080" in r.host and r.host.endswith("/v1")
