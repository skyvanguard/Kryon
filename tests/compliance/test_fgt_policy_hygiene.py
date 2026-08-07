"""FortiGate section 6 — firewall policy hygiene (FGT-6.1/6.2/6.3).
run_cmd monkeypatched — no device access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C61 = importlib.import_module("kryon.compliance.checks.fortigate.c_fgt_6_1_allow_all_policies")
C62 = importlib.import_module("kryon.compliance.checks.fortigate.c_fgt_6_2_policy_logging")
C63 = importlib.import_module("kryon.compliance.checks.fortigate.c_fgt_6_3_policy_utm_profiles")

_ALLOW_ALL = """config firewall policy
    edit 1
        set name "allow-all"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""

_RESTRICTIVE = """config firewall policy
    edit 2
        set name "lan-to-dns"
        set srcaddr "lan-net"
        set dstaddr "dns-server"
        set action accept
        set service "DNS"
        set logtraffic all
        set av-profile "default"
        set ips-sensor "protect_client"
    next
end
"""

_ACCEPT_NO_LOG = """config firewall policy
    edit 3
        set name "web"
        set srcaddr "lan"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set logtraffic disable
        set av-profile "default"
    next
end
"""

_ACCEPT_NO_UTM = """config firewall policy
    edit 4
        set name "passthrough"
        set srcaddr "lan"
        set dstaddr "wan"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
end
"""


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 6.1 allow-all ---


def test_61_fail_any_any_all(monkeypatch):
    monkeypatch.setattr(C61, "run_cmd", _out(_ALLOW_ALL))
    r = C61.CHECK.run(CheckContext(host="fw"))
    assert r.verdict == "FAIL"
    assert "1" in r.evidence_parsed["allow_all_policies"]


def test_61_pass_restrictive(monkeypatch):
    monkeypatch.setattr(C61, "run_cmd", _out(_RESTRICTIVE))
    assert C61.CHECK.run(CheckContext(host="fw")).verdict == "PASS"


def test_61_error_when_unreadable(monkeypatch):
    monkeypatch.setattr(C61, "run_cmd", _out("", 1))
    assert C61.CHECK.run(CheckContext(host="fw")).verdict == "ERROR"


# --- 6.2 logging ---


def test_62_fail_logtraffic_disable(monkeypatch):
    monkeypatch.setattr(C62, "run_cmd", _out(_ACCEPT_NO_LOG))
    r = C62.CHECK.run(CheckContext(host="fw"))
    assert r.verdict == "FAIL"
    assert "3" in r.evidence_parsed["policies_without_logging"]


def test_62_pass_logging_enabled(monkeypatch):
    monkeypatch.setattr(C62, "run_cmd", _out(_RESTRICTIVE))
    assert C62.CHECK.run(CheckContext(host="fw")).verdict == "PASS"


# --- 6.3 UTM profiles ---


def test_63_fail_no_utm(monkeypatch):
    monkeypatch.setattr(C63, "run_cmd", _out(_ACCEPT_NO_UTM))
    r = C63.CHECK.run(CheckContext(host="fw"))
    assert r.verdict == "FAIL"
    assert "4" in r.evidence_parsed["policies_without_utm"]


def test_63_pass_with_utm(monkeypatch):
    monkeypatch.setattr(C63, "run_cmd", _out(_RESTRICTIVE))
    assert C63.CHECK.run(CheckContext(host="fw")).verdict == "PASS"


# --- registration ---


def test_section6_registered():
    from kryon.compliance.runner import registered_checks

    ids = {c.control_id for c in registered_checks()}
    assert {"FGT-6.1", "FGT-6.2", "FGT-6.3"} <= ids
