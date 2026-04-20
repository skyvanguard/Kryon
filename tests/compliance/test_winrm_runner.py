"""Tests for the WinRM runner (F36).

These tests exercise error-handling paths and arg formatting without
requiring a live Windows host. Actual live-host integration is covered
by a manual smoke test documented in the runner module.
"""

from __future__ import annotations

import importlib
import sys

import pytest


try:
    _runner = importlib.import_module("kryon.compliance.runners.winrm_runner")
    _base = importlib.import_module("kryon.compliance.checks.base")
except (ImportError, ModuleNotFoundError):
    pytest.skip("compliance runners not importable", allow_module_level=True)

CheckContext = _base.CheckContext
run_winrm_cmd = _runner.run_winrm_cmd


def test_localhost_rejected_for_winrm():
    """WinRM is a remote transport; localhost must be flagged."""
    ctx = CheckContext(host="localhost", transport="winrm")
    out, err, rc = run_winrm_cmd(ctx, "whoami")
    assert rc != 0
    assert "localhost" in err.lower() or "winrm" in err.lower()


def test_missing_credentials_rejected():
    ctx = CheckContext(host="10.0.0.1", transport="winrm")
    out, err, rc = run_winrm_cmd(ctx, "whoami")
    assert rc == 2
    assert "user" in err.lower() or "password" in err.lower()


def test_missing_pywinrm_gives_clear_error(monkeypatch):
    """Simulate pywinrm absence to cover the import-error branch."""
    # Snapshot winrm module state
    saved = sys.modules.pop("winrm", None)
    monkeypatch.setitem(sys.modules, "winrm", None)  # forces ImportError

    ctx = CheckContext(
        host="10.0.0.1",
        transport="winrm",
        winrm_user="audit",
        winrm_password="x",
    )
    out, err, rc = run_winrm_cmd(ctx, "whoami")
    assert rc == 127
    assert "pywinrm" in err.lower()

    # Restore
    sys.modules.pop("winrm", None)
    if saved is not None:
        sys.modules["winrm"] = saved


def test_auth_classifier_defaults_to_ntlm():
    assert _runner._classify_auth("") == "ntlm"
    assert _runner._classify_auth(None) == "ntlm"  # type: ignore[arg-type]
    assert _runner._classify_auth("Ntlm") == "ntlm"
    assert _runner._classify_auth("kerberos") == "kerberos"
    assert _runner._classify_auth("KRB5") == "kerberos"
    assert _runner._classify_auth("basic") == "basic"
    assert _runner._classify_auth("credssp") == "credssp"


def test_format_cmd_list_joins_with_space():
    assert _runner._format_cmd(["sc", "query", "Spooler"]) == "sc query Spooler"
    assert _runner._format_cmd("sc query Spooler") == "sc query Spooler"


def test_context_exposes_winrm_fields():
    """CheckContext must carry the new WinRM fields with safe defaults."""
    ctx = CheckContext()
    # Defaults keep SSH behaviour
    assert ctx.transport == "ssh"
    assert ctx.winrm_port == 5985
    assert ctx.winrm_scheme == "http"
    assert ctx.winrm_auth == "ntlm"
    # Explicit winrm context
    ctx2 = CheckContext(
        host="srv01",
        transport="winrm",
        winrm_user="audit",
        winrm_password="s3cret",
        winrm_port=5986,
        winrm_scheme="https",
        winrm_auth="kerberos",
    )
    assert ctx2.transport == "winrm"
    assert ctx2.winrm_port == 5986
    assert ctx2.winrm_scheme == "https"


def test_run_cmd_dispatches_to_winrm(monkeypatch):
    """runner.run_cmd must route to the winrm runner when transport='winrm'."""
    from kryon.compliance import runner as compliance_runner

    captured: dict = {}

    def fake_winrm(ctx, cmd, *, timeout_s=15):
        captured["called"] = True
        captured["host"] = ctx.host
        captured["cmd"] = cmd
        return "ok", "", 0

    monkeypatch.setattr(
        "kryon.compliance.runners.winrm_runner.run_winrm_cmd",
        fake_winrm,
    )

    ctx = CheckContext(
        host="srv01",
        transport="winrm",
        winrm_user="audit",
        winrm_password="x",
    )
    out, err, rc = compliance_runner.run_cmd(ctx, "whoami")
    assert captured.get("called") is True
    assert captured["host"] == "srv01"
    assert rc == 0
    assert out == "ok"
