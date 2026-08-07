"""PCI-DSS v4 checks: 1.4.1 (host firewall) and 2.2.5 (insecure services).
run_cmd monkeypatched — no host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C141 = importlib.import_module("kryon.compliance.checks.section_1.c_1_4_1_host_firewall")
C225 = importlib.import_module("kryon.compliance.checks.section_2.c_2_2_5_insecure_services")


# --- 1.4.1: host-based firewall ---


def _fw(responses: dict):
    """responses maps cmd[0] -> (stdout, returncode); missing tools return 127."""

    def fake(_ctx, cmd, **_kw):
        r = responses.get(cmd[0])
        if r is None:
            return ("", "command not found", 127)
        return (r[0], "", r[1])

    return fake


def test_141_pass_ufw_active(monkeypatch):
    monkeypatch.setattr(C141, "run_cmd", _fw({"ufw": ("Status: active\n", 0)}))
    r = C141.CHECK.run(CheckContext(host="x"))
    assert r.verdict == "PASS"
    assert "ufw" in r.evidence_parsed["active_firewalls"]


def test_141_pass_nftables_ruleset(monkeypatch):
    ruleset = "table inet filter {\n  chain input {\n    type filter hook input priority 0; policy drop;\n  }\n}\n"
    monkeypatch.setattr(C141, "run_cmd", _fw({"nft": (ruleset, 0)}))
    assert C141.CHECK.run(CheckContext(host="x")).verdict == "PASS"


def test_141_fail_all_inactive(monkeypatch):
    monkeypatch.setattr(
        C141,
        "run_cmd",
        _fw(
            {
                "ufw": ("Status: inactive\n", 0),
                "iptables": ("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n", 0),
            }
        ),
    )
    assert C141.CHECK.run(CheckContext(host="x")).verdict == "FAIL"


def test_141_error_when_unreachable(monkeypatch):
    monkeypatch.setattr(C141, "run_cmd", lambda _c, cmd, **_k: ("", "connection refused", 255))
    assert C141.CHECK.run(CheckContext(host="x")).verdict == "ERROR"


# --- 2.2.5: insecure services ---


def test_225_fail_telnet_listening(monkeypatch):
    monkeypatch.setattr(C225, "run_cmd", lambda _c, cmd, **_k: ("tcp LISTEN 0 128 0.0.0.0:23 0.0.0.0:*\n", "", 0))
    r = C225.CHECK.run(CheckContext(host="x"))
    assert r.verdict == "FAIL"
    assert any("telnet" in s for s in r.evidence_parsed["insecure_services_listening"])


def test_225_fail_ftp_listening(monkeypatch):
    monkeypatch.setattr(C225, "run_cmd", lambda _c, cmd, **_k: ("tcp LISTEN 0 5 0.0.0.0:21 0.0.0.0:*\n", "", 0))
    assert C225.CHECK.run(CheckContext(host="x")).verdict == "FAIL"


def test_225_pass_only_secure_services(monkeypatch):
    out = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
    monkeypatch.setattr(C225, "run_cmd", lambda _c, cmd, **_k: (out, "", 0))
    assert C225.CHECK.run(CheckContext(host="x")).verdict == "PASS"


def test_225_error_when_ss_unavailable(monkeypatch):
    monkeypatch.setattr(C225, "run_cmd", lambda _c, cmd, **_k: ("", "command not found", 127))
    assert C225.CHECK.run(CheckContext(host="x")).verdict == "ERROR"


# --- registration ---


def test_new_checks_registered():
    from kryon.compliance.runner import registered_checks

    ids = {c.control_id for c in registered_checks()}
    assert "1.4.1" in ids
    assert "2.2.5" in ids
