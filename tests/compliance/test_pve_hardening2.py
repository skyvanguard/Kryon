"""Proxmox VE hardening batch 2 — PVE-8.1 (backups), 4.2 (fw logging), 2.3 (ssh ciphers).
run_cmd monkeypatched — no node access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C81 = importlib.import_module("kryon.compliance.checks.proxmox.c_pve_8_1_backup_jobs")
C42 = importlib.import_module("kryon.compliance.checks.proxmox.c_pve_4_2_firewall_logging")
C23 = importlib.import_module("kryon.compliance.checks.proxmox.c_pve_2_3_ssh_ciphers")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 8.1 backup jobs ---

_JOBS_OK = "vzdump: backup-daily\n\tschedule 02:00\n\tstorage pbs\n\tall 1\n"
_JOBS_NONE = "# no scheduled jobs defined\n"


def test_81_pass_with_job(monkeypatch):
    monkeypatch.setattr(C81, "run_cmd", _out(_JOBS_OK))
    r = C81.CHECK.run(CheckContext(host="pve"))
    assert r.verdict == "PASS"
    assert "backup-daily" in r.evidence_parsed["vzdump_job_ids"]


def test_81_fail_no_job(monkeypatch):
    monkeypatch.setattr(C81, "run_cmd", _out(_JOBS_NONE))
    assert C81.CHECK.run(CheckContext(host="pve")).verdict == "FAIL"


def test_81_error_no_config(monkeypatch):
    monkeypatch.setattr(C81, "run_cmd", _out("", 1))
    assert C81.CHECK.run(CheckContext(host="pve")).verdict == "ERROR"


# --- 4.2 firewall logging ---

_FW_LOGGING = "[OPTIONS]\nenable: 1\nlog_level_in: info\nlog_level_out: info\n"
_FW_NOLOG = "[OPTIONS]\nenable: 1\nlog_level_in: nolog\n"


def test_42_pass_logging_on(monkeypatch):
    monkeypatch.setattr(C42, "run_cmd", _out(_FW_LOGGING))
    assert C42.CHECK.run(CheckContext(host="pve")).verdict == "PASS"


def test_42_fail_nolog(monkeypatch):
    monkeypatch.setattr(C42, "run_cmd", _out(_FW_NOLOG))
    assert C42.CHECK.run(CheckContext(host="pve")).verdict == "FAIL"


def test_42_na_no_firewall(monkeypatch):
    monkeypatch.setattr(C42, "run_cmd", _out("", 0))
    assert C42.CHECK.run(CheckContext(host="pve")).verdict == "N/A"


# --- 2.3 ssh ciphers ---

_SSH_WEAK = "ciphers aes256-ctr,aes128-cbc\nkexalgorithms curve25519-sha256\nmacs hmac-sha2-256\n"
_SSH_STRONG = (
    "ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n"
    "kexalgorithms curve25519-sha256\n"
    "macs hmac-sha2-512-etm@openssh.com\n"
)


def test_23_fail_weak_cbc(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out(_SSH_WEAK))
    r = C23.CHECK.run(CheckContext(host="pve"))
    assert r.verdict == "FAIL"
    assert "-cbc" in r.evidence_parsed["weak_algorithms"]


def test_23_pass_strong(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out(_SSH_STRONG))
    assert C23.CHECK.run(CheckContext(host="pve")).verdict == "PASS"


def test_23_error_no_config(monkeypatch):
    monkeypatch.setattr(C23, "run_cmd", _out("", 1))
    assert C23.CHECK.run(CheckContext(host="pve")).verdict == "ERROR"


# --- registration ---


def test_batch2_registered():
    from kryon.compliance.runner import registered_checks

    ids = {c.control_id for c in registered_checks()}
    assert {"PVE-2.3", "PVE-4.2", "PVE-8.1"} <= ids
