"""Proxmox VE hardening — PVE-5.2 (repo hygiene), 7.1 (time sync), 2.2 (fail2ban).
run_cmd monkeypatched — no node access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C52 = importlib.import_module("kryon.compliance.checks.proxmox.c_pve_5_2_repo_hygiene")
C71 = importlib.import_module("kryon.compliance.checks.proxmox.c_pve_7_1_time_sync")
C22 = importlib.import_module("kryon.compliance.checks.proxmox.c_pve_2_2_fail2ban")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 5.2 repo hygiene ---

_SOURCES_OK = "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription\n"
_SOURCES_PVETEST = (
    "deb http://ftp.debian.org/debian bookworm main\ndeb http://download.proxmox.com/debian/pve bookworm pvetest\n"
)
_SOURCES_COMMENTED = "# deb http://download.proxmox.com/debian/pve bookworm pvetest\n"


def test_52_fail_pvetest_active(monkeypatch):
    monkeypatch.setattr(C52, "run_cmd", _out(_SOURCES_PVETEST))
    r = C52.CHECK.run(CheckContext(host="pve"))
    assert r.verdict == "FAIL"
    assert r.evidence_parsed["pvetest_active"] is True


def test_52_pass_no_pvetest(monkeypatch):
    monkeypatch.setattr(C52, "run_cmd", _out(_SOURCES_OK))
    assert C52.CHECK.run(CheckContext(host="pve")).verdict == "PASS"


def test_52_pass_pvetest_commented(monkeypatch):
    monkeypatch.setattr(C52, "run_cmd", _out(_SOURCES_COMMENTED))
    assert C52.CHECK.run(CheckContext(host="pve")).verdict == "PASS"


def test_52_error_no_sources(monkeypatch):
    monkeypatch.setattr(C52, "run_cmd", _out("", 1))
    assert C52.CHECK.run(CheckContext(host="pve")).verdict == "ERROR"


# --- 7.1 time sync ---


def test_71_pass_synced(monkeypatch):
    monkeypatch.setattr(C71, "run_cmd", _out("NTP=yes\nNTPSynchronized=yes\n"))
    assert C71.CHECK.run(CheckContext(host="pve")).verdict == "PASS"


def test_71_fail_not_synced(monkeypatch):
    monkeypatch.setattr(C71, "run_cmd", _out("NTP=yes\nNTPSynchronized=no\n"))
    assert C71.CHECK.run(CheckContext(host="pve")).verdict == "FAIL"


def test_71_error_no_timedatectl(monkeypatch):
    monkeypatch.setattr(C71, "run_cmd", _out("", 1))
    assert C71.CHECK.run(CheckContext(host="pve")).verdict == "ERROR"


# --- 2.2 fail2ban ---


def test_22_pass_active(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("active\n"))
    assert C22.CHECK.run(CheckContext(host="pve")).verdict == "PASS"


def test_22_fail_not_installed(monkeypatch):
    monkeypatch.setattr(C22, "run_cmd", _out("\n"))
    assert C22.CHECK.run(CheckContext(host="pve")).verdict == "FAIL"


# --- registration ---


def test_pve_hardening_registered():
    from kryon.compliance.runner import registered_checks

    ids = {c.control_id for c in registered_checks()}
    assert {"PVE-2.2", "PVE-5.2", "PVE-7.1"} <= ids
