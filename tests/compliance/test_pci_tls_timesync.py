"""PCI-DSS v4 checks: 4.2.1 (strong TLS) and 10.6.1 (time sync).
run_cmd monkeypatched — no host access, no network."""

from __future__ import annotations

import importlib
import re

from kryon.compliance.checks.base import CheckContext

C421 = importlib.import_module("kryon.compliance.checks.section_4.c_4_2_1_strong_tls")
C1061 = importlib.import_module("kryon.compliance.checks.section_10.c_10_6_1_time_sync")


# --- 4.2.1: strong cryptography in transit ---


def _tls(port_line: str, weak_accepted: set):
    """ss returns port_line; openssl succeeds only for flags in weak_accepted."""
    proto = {"-ssl3": "SSLv3", "-tls1": "TLSv1", "-tls1_1": "TLSv1.1"}

    def fake(_ctx, cmd, **_kw):
        if isinstance(cmd, list) and cmd and cmd[0] == "ss":
            return (port_line, "", 0)
        s = cmd if isinstance(cmd, str) else " ".join(cmd)
        m = re.search(r"s_client (\S+) -connect", s)
        flag = m.group(1) if m else ""
        if flag in weak_accepted:
            return (f"CONNECTED\nNew, {proto[flag]}, Cipher is AES256-SHA\n", "", 0)
        return ("CONNECTED\nNew, (NONE), Cipher is (NONE)\n", "", 1)

    return fake


def test_421_na_when_no_tls_port(monkeypatch):
    monkeypatch.setattr(C421, "run_cmd", _tls("tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\n", set()))
    assert C421.CHECK.run(CheckContext(host="x")).verdict == "N/A"


def test_421_fail_tls11_accepted(monkeypatch):
    monkeypatch.setattr(C421, "run_cmd", _tls("tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n", {"-tls1_1"}))
    r = C421.CHECK.run(CheckContext(host="x"))
    assert r.verdict == "FAIL"
    assert "TLS1.1" in r.evidence_parsed["per_port"]["443"]["weak_protocols_accepted"]


def test_421_pass_only_strong(monkeypatch):
    monkeypatch.setattr(C421, "run_cmd", _tls("tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n", set()))
    assert C421.CHECK.run(CheckContext(host="x")).verdict == "PASS"


def test_421_error_on_unsafe_host(monkeypatch):
    monkeypatch.setattr(C421, "run_cmd", _tls("", set()))
    assert C421.CHECK.run(CheckContext(host="bad;rm -rf /")).verdict == "ERROR"


# --- 10.6.1: time synchronization ---


def _td(output: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (output, "", rc)

    return fake


def test_1061_pass_synced(monkeypatch):
    monkeypatch.setattr(C1061, "run_cmd", _td("NTP=yes\nNTPSynchronized=yes\n"))
    assert C1061.CHECK.run(CheckContext(host="x")).verdict == "PASS"


def test_1061_fail_not_synchronized(monkeypatch):
    monkeypatch.setattr(C1061, "run_cmd", _td("NTP=yes\nNTPSynchronized=no\n"))
    assert C1061.CHECK.run(CheckContext(host="x")).verdict == "FAIL"


def test_1061_fail_ntp_off(monkeypatch):
    monkeypatch.setattr(C1061, "run_cmd", _td("NTP=no\nNTPSynchronized=no\n"))
    assert C1061.CHECK.run(CheckContext(host="x")).verdict == "FAIL"


def test_1061_error_when_unavailable(monkeypatch):
    monkeypatch.setattr(C1061, "run_cmd", _td("", 1))
    assert C1061.CHECK.run(CheckContext(host="x")).verdict == "ERROR"


# --- registration ---


def test_new_checks_registered():
    from kryon.compliance.runner import registered_checks

    ids = {c.control_id for c in registered_checks()}
    assert "4.2.1" in ids
    assert "10.6.1" in ids
