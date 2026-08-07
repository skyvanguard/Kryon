"""Tests for verify_finding — agentic single-finding verification (gap #3).

build_default_loop is monkeypatched, so no model/compiler/network is needed.
"""

from __future__ import annotations

import dataclasses

import pytest

from kryon.intelligence.source_review import SourceFinding
from kryon.tools.code import verify as verify_mod
from kryon.tools.code.verify import _verify_impl


def _confirmed(**kw) -> SourceFinding:
    base = dict(
        file="a.c", line=42, cwe="CWE-787", severity="HIGH", title="oob", evidence="buf[i]=0;", sink="buf[i]",
        verified=True, verification_verdict="confirmed", crash_type="heap-buffer-overflow", novelty_verdict="likely-novel",
    )
    base.update(kw)
    return SourceFinding(**base)


def _patch_loop(monkeypatch, result_finding):
    import kryon.intelligence.zeroday_verify as zv

    monkeypatch.setattr(zv, "build_default_loop", lambda root: (lambda fs: [result_finding]))


# --- gate -------------------------------------------------------------------


def test_gate_off_returns_note(monkeypatch):
    monkeypatch.delenv("KRYON_ZERODAY_VERIFY", raising=False)
    out = _verify_impl("a.c", 1, "CWE-787")
    assert "OFF" in out
    assert "KRYON_ZERODAY_VERIFY" in out


# --- verdicts ---------------------------------------------------------------


def test_confirmed_novel(monkeypatch):
    monkeypatch.setenv("KRYON_ZERODAY_VERIFY", "true")
    _patch_loop(monkeypatch, _confirmed())
    out = _verify_impl("a.c", 42, "CWE-787", evidence="buf[i]=0;")
    assert "✅ CONFIRMED" in out
    assert "heap-buffer-overflow" in out
    assert "NOVEL" in out


def test_not_reproduced(monkeypatch):
    monkeypatch.setenv("KRYON_ZERODAY_VERIFY", "true")
    _patch_loop(monkeypatch, _confirmed(verified=False, verification_verdict="not-reproduced", crash_type="", novelty_verdict="likely-known", nearest_cve="CVE-2020-1"))
    out = _verify_impl("a.c", 42, "CWE-787")
    assert "not-reproduced" in out
    assert "CVE-2020-1" in out


def test_unsupported(monkeypatch):
    monkeypatch.setenv("KRYON_ZERODAY_VERIFY", "true")
    _patch_loop(monkeypatch, _confirmed(verified=False, verification_verdict="unsupported", crash_type=""))
    out = _verify_impl("a.py", 1, "CWE-999")
    assert "no oracle" in out


def test_loop_exception_surfaced(monkeypatch):
    monkeypatch.setenv("KRYON_ZERODAY_VERIFY", "true")
    import kryon.intelligence.zeroday_verify as zv

    def boom(root):
        raise RuntimeError("compiler missing")

    monkeypatch.setattr(zv, "build_default_loop", boom)
    out = _verify_impl("a.c", 1, "CWE-787")
    assert out.startswith("ERROR during verification")
    assert "compiler missing" in out


def test_bad_line_coerced(monkeypatch):
    monkeypatch.setenv("KRYON_ZERODAY_VERIFY", "true")
    _patch_loop(monkeypatch, _confirmed())
    # line="abc" must not crash
    out = _verify_impl("a.c", "abc", "CWE-787")  # type: ignore[arg-type]
    assert "CONFIRMED" in out


# --- wiring -----------------------------------------------------------------


def test_tool_registered_and_offered():
    from pathlib import Path

    import yaml

    from kryon.skills.tool_budget import build_tool_registry

    assert "verify_finding" in build_tool_registry()
    assert verify_mod.verify_finding.name == "verify_finding"
    md = Path(__file__).resolve().parents[3] / "src/kryon/skills/playbooks/zero-day/zero-day-hunter.md"
    fm = yaml.safe_load(md.read_text(encoding="utf-8").split("---")[1])
    assert "verify_finding" in fm["required_tools"]
