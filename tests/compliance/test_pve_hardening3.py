"""Proxmox VE hardening batch 3 — PVE-3.3 (named users), 2.4 (sysctl), 5.3 (auto-upgrades).
run_cmd monkeypatched — no node access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C33 = importlib.import_module("kryon.compliance.checks.proxmox.c_pve_3_3_named_users")
C24 = importlib.import_module("kryon.compliance.checks.proxmox.c_pve_2_4_kernel_sysctl")
C53 = importlib.import_module("kryon.compliance.checks.proxmox.c_pve_5_3_unattended_upgrades")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 3.3 named users ---

_USERS_NAMED = "user:root@pam:1:0::::::\nuser:alice@pve:1:0:Alice::alice@corp:::\n"
_USERS_ONLY_ROOT = "user:root@pam:1:0::::::\n"


def test_33_pass_named_user(monkeypatch):
    monkeypatch.setattr(C33, "run_cmd", _out(_USERS_NAMED))
    r = C33.CHECK.run(CheckContext(host="pve"))
    assert r.verdict == "PASS"
    assert "alice@pve" in r.evidence_parsed["named_non_root_users"]


def test_33_fail_only_root(monkeypatch):
    monkeypatch.setattr(C33, "run_cmd", _out(_USERS_ONLY_ROOT))
    assert C33.CHECK.run(CheckContext(host="pve")).verdict == "FAIL"


def test_33_error_no_cfg(monkeypatch):
    monkeypatch.setattr(C33, "run_cmd", _out("", 1))
    assert C33.CHECK.run(CheckContext(host="pve")).verdict == "ERROR"


# --- 2.4 kernel sysctl ---

_SYSCTL_OK = (
    "kernel.kptr_restrict = 2\nkernel.dmesg_restrict = 1\nfs.protected_hardlinks = 1\nfs.protected_symlinks = 1\n"
)
_SYSCTL_WEAK = (
    "kernel.kptr_restrict = 0\nkernel.dmesg_restrict = 1\nfs.protected_hardlinks = 1\nfs.protected_symlinks = 1\n"
)


def test_24_pass_hardened(monkeypatch):
    monkeypatch.setattr(C24, "run_cmd", _out(_SYSCTL_OK))
    assert C24.CHECK.run(CheckContext(host="pve")).verdict == "PASS"


def test_24_fail_kptr_open(monkeypatch):
    monkeypatch.setattr(C24, "run_cmd", _out(_SYSCTL_WEAK))
    r = C24.CHECK.run(CheckContext(host="pve"))
    assert r.verdict == "FAIL"
    assert any("kptr_restrict" in i for i in r.evidence_parsed["issues"])


def test_24_error_no_sysctl(monkeypatch):
    monkeypatch.setattr(C24, "run_cmd", _out("", 1))
    assert C24.CHECK.run(CheckContext(host="pve")).verdict == "ERROR"


# --- 5.3 unattended-upgrades ---

_UU_OK = '1\nAPT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
_UU_MISSING = "0\n"


def test_53_pass_enabled(monkeypatch):
    monkeypatch.setattr(C53, "run_cmd", _out(_UU_OK))
    assert C53.CHECK.run(CheckContext(host="pve")).verdict == "PASS"


def test_53_fail_not_installed(monkeypatch):
    monkeypatch.setattr(C53, "run_cmd", _out(_UU_MISSING))
    assert C53.CHECK.run(CheckContext(host="pve")).verdict == "FAIL"


# --- registration ---


def test_batch3_registered():
    from kryon.compliance.runner import registered_checks

    ids = {c.control_id for c in registered_checks()}
    assert {"PVE-2.4", "PVE-3.3", "PVE-5.3"} <= ids
