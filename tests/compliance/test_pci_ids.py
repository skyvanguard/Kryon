"""PCI-DSS v4 check 11.5.1 — intrusion detection / prevention.
run_cmd monkeypatched — no host access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C1151 = importlib.import_module("kryon.compliance.checks.section_11.c_11_5_1_ids_ips")


def _svc(active_svcs: set):
    lines = "\n".join("active" if s in active_svcs else "inactive" for s in C1151._SERVICES)

    def fake(_ctx, _cmd, **_kw):
        rc = 0 if len(active_svcs) == len(C1151._SERVICES) else 3
        return (lines + "\n", "", rc)

    return fake


def test_1151_pass_suricata(monkeypatch):
    monkeypatch.setattr(C1151, "run_cmd", _svc({"suricata"}))
    r = C1151.CHECK.run(CheckContext(host="x"))
    assert r.verdict == "PASS"
    assert "suricata" in r.evidence_parsed["active_ids_ips"]


def test_1151_pass_fail2ban(monkeypatch):
    monkeypatch.setattr(C1151, "run_cmd", _svc({"fail2ban"}))
    assert C1151.CHECK.run(CheckContext(host="x")).verdict == "PASS"


def test_1151_fail_none_active(monkeypatch):
    monkeypatch.setattr(C1151, "run_cmd", _svc(set()))
    assert C1151.CHECK.run(CheckContext(host="x")).verdict == "FAIL"


def test_1151_error_no_systemctl(monkeypatch):
    monkeypatch.setattr(C1151, "run_cmd", lambda _c, _cmd, **_k: ("", "not found", 127))
    assert C1151.CHECK.run(CheckContext(host="x")).verdict == "ERROR"


def test_1151_registered():
    from kryon.compliance.runner import registered_checks

    assert "11.5.1" in {c.control_id for c in registered_checks()}
