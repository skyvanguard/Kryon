"""Microsoft Hyper-V hardening batch 2 — HV-1.3 admins, 2.3/2.4 checkpoints, 3.2 nested.
run_cmd monkeypatched — no WinRM/host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C13 = importlib.import_module("kryon.compliance.checks.hyperv.c_hv_1_3_admins_group")
C23 = importlib.import_module("kryon.compliance.checks.hyperv.c_hv_2_3_production_checkpoints")
C24 = importlib.import_module("kryon.compliance.checks.hyperv.c_hv_2_4_automatic_checkpoints")
C32 = importlib.import_module("kryon.compliance.checks.hyperv.c_hv_3_2_nested_virt")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 1.3 Hyper-V Administrators group ---


def test_13_fail_broad_everyone(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("BUILTIN\\Administrators;Everyone\n"))
    r = C13.CHECK.run(CheckContext(host="hv"))
    assert r.verdict == "FAIL"
    assert "Everyone" in r.evidence_parsed["broad_principals"]


def test_13_fail_domain_users(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("CORP\\Domain Users\n"))
    assert C13.CHECK.run(CheckContext(host="hv")).verdict == "FAIL"


def test_13_pass_named(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("CORP\\alice;CORP\\bob\n"))
    assert C13.CHECK.run(CheckContext(host="hv")).verdict == "PASS"


def test_13_error(monkeypatch):
    monkeypatch.setattr(C13, "run_cmd", _out("", 1))
    assert C13.CHECK.run(CheckContext(host="hv")).verdict == "ERROR"


# --- 2.3 Production checkpoints ---


def test_23_fail_standard(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out("legacy-vm\n"))
    assert C23.CHECK.run(CheckContext(host="hv")).verdict == "FAIL"


def test_23_pass_production(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out("\n"))
    assert C23.CHECK.run(CheckContext(host="hv")).verdict == "PASS"


# --- 2.4 Automatic checkpoints ---


def test_24_fail_enabled(monkeypatch):
    monkeypatch.setattr(C24, "run_cmd", _out("dev-vm\n"))
    assert C24.CHECK.run(CheckContext(host="hv")).verdict == "FAIL"


def test_24_pass_disabled(monkeypatch):
    monkeypatch.setattr(C24, "run_cmd", _out("\n"))
    assert C24.CHECK.run(CheckContext(host="hv")).verdict == "PASS"


# --- 3.2 Nested virtualization ---


def test_32_fail_nested(monkeypatch):
    monkeypatch.setattr(C32, "run_cmd", _out("ci-runner\n"))
    assert C32.CHECK.run(CheckContext(host="hv")).verdict == "FAIL"


def test_32_pass_none(monkeypatch):
    monkeypatch.setattr(C32, "run_cmd", _out("\n"))
    assert C32.CHECK.run(CheckContext(host="hv")).verdict == "PASS"


# --- registration ---


def test_batch2_registered():
    from kryon.compliance.runner import registered_checks

    ids = {c.control_id for c in registered_checks()}
    assert {"HV-1.3", "HV-2.3", "HV-2.4", "HV-3.2"} <= ids
