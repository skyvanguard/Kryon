"""Lynis client — lynis_cmd + run_audit (injected transport runner)."""

from __future__ import annotations

import subprocess

import pytest

from kryon.integrations.lynis.client import LynisError, lynis_cmd, run_audit

_REPORT = "lynis_version=3.0.9\nhardening_index=70\nwarning[]=SSH-7408|Weak SSH|-|\n"


def test_lynis_cmd_audits_and_cats_report():
    cmd = lynis_cmd("/tmp/r.dat")
    assert "lynis audit system" in cmd
    assert "--report-file /tmp/r.dat" in cmd
    assert "cat /tmp/r.dat" in cmd


def test_run_audit_returns_report():
    out = run_audit(runner=lambda _cmd: _REPORT)
    assert "lynis_version" in out


def test_run_audit_no_report_raises():
    with pytest.raises(LynisError, match="no Lynis report"):
        run_audit(runner=lambda _cmd: "bash: lynis: command not found\n")


def test_run_audit_transport_error_raises():
    def runner(_cmd):
        raise OSError("ssh connection refused")

    with pytest.raises(LynisError, match="run failed"):
        run_audit(runner=runner)


def test_run_audit_timeout_raises():
    def runner(_cmd):
        raise subprocess.TimeoutExpired(cmd="lynis", timeout=1)

    with pytest.raises(LynisError, match="timed out"):
        run_audit(runner=runner)
