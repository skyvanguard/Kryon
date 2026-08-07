"""PCI-DSS v4 checks: 8.2.1 (unique user IDs) and 10.3.1 (audit log protection).
run_cmd monkeypatched — no host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C821 = importlib.import_module("kryon.compliance.checks.section_8.c_8_2_1_unique_ids")
C1031 = importlib.import_module("kryon.compliance.checks.section_10.c_10_3_1_audit_log_protection")


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 8.2.1: unique user IDs ---

_NORMAL_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "user1:x:1000:1000::/home/user1:/bin/bash\n"
)


def test_821_pass_unique(monkeypatch):
    monkeypatch.setattr(C821, "run_cmd", _out(_NORMAL_PASSWD))
    assert C821.CHECK.run(CheckContext(host="x")).verdict == "PASS"


def test_821_fail_duplicate_uid(monkeypatch):
    passwd = (
        "root:x:0:0::/root:/bin/bash\nuser1:x:1000:1000::/home/u1:/bin/bash\nuser2:x:1000:1000::/home/u2:/bin/bash\n"
    )
    monkeypatch.setattr(C821, "run_cmd", _out(passwd))
    r = C821.CHECK.run(CheckContext(host="x"))
    assert r.verdict == "FAIL"
    assert "1000" in r.evidence_parsed["duplicate_uids"]


def test_821_fail_backdoor_uid0(monkeypatch):
    passwd = "root:x:0:0::/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/bash\n"
    monkeypatch.setattr(C821, "run_cmd", _out(passwd))
    r = C821.CHECK.run(CheckContext(host="x"))
    assert r.verdict == "FAIL"
    assert "backdoor" in r.evidence_parsed["non_root_uid0"]


def test_821_error_when_unreadable(monkeypatch):
    monkeypatch.setattr(C821, "run_cmd", _out("", 1))
    assert C821.CHECK.run(CheckContext(host="x")).verdict == "ERROR"


# --- 10.3.1: audit log protection ---


def test_1031_pass_restrictive(monkeypatch):
    monkeypatch.setattr(C1031, "run_cmd", _out("600 root root\n"))
    assert C1031.CHECK.run(CheckContext(host="x")).verdict == "PASS"


def test_1031_fail_world_readable(monkeypatch):
    monkeypatch.setattr(C1031, "run_cmd", _out("644 root root\n"))
    r = C1031.CHECK.run(CheckContext(host="x"))
    assert r.verdict == "FAIL"
    assert r.evidence_parsed["world_readable"] is True


def test_1031_fail_wrong_owner(monkeypatch):
    monkeypatch.setattr(C1031, "run_cmd", _out("640 syslog adm\n"))
    assert C1031.CHECK.run(CheckContext(host="x")).verdict == "FAIL"


def test_1031_na_when_no_audit_log(monkeypatch):
    monkeypatch.setattr(C1031, "run_cmd", _out("", 1))
    assert C1031.CHECK.run(CheckContext(host="x")).verdict == "N/A"


# --- registration ---


def test_new_checks_registered():
    from kryon.compliance.runner import registered_checks

    ids = {c.control_id for c in registered_checks()}
    assert "8.2.1" in ids
    assert "10.3.1" in ids
