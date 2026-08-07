"""Tests for the deterministic SAST triage tool."""

from __future__ import annotations

from pathlib import Path

from kryon.tools.code.sast_triage import sast_triage

_fn = sast_triage._raw_fn  # the undecorated callable


def test_triage_ranks_tainted_file_above_noise(tmp_path: Path):
    # noise.c: dense in a common low-weight sink; vuln.c: one sink an input source reaches.
    (tmp_path / "noise.c").write_text("int a = malloc(1);\n" * 20, encoding="utf-8")
    (tmp_path / "vuln.c").write_text("n = recv(sock, buf);\nmemcpy(dst, buf, n);\n", encoding="utf-8")

    out = _fn(code_path=str(tmp_path))

    assert "vuln.c" in out
    # the tainted file must be listed before the noise-dense one
    assert out.index("vuln.c") < out.index("noise.c")


def test_triage_reports_sink_lines_with_cwe(tmp_path: Path):
    (tmp_path / "d.java").write_text("Object o = ctx.lookup(name);\n", encoding="utf-8")
    out = _fn(code_path=str(tmp_path))
    assert "CWE-502" in out and "d.java" in out


def test_triage_notes_when_no_sinks(tmp_path: Path):
    (tmp_path / "plain.py").write_text("x = 1 + 1\n", encoding="utf-8")
    out = _fn(code_path=str(tmp_path))
    assert "0 archivos con sinks" in out


def test_triage_missing_path():
    assert "no existe" in _fn(code_path="/nonexistent/path/xyz")
