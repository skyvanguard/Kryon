"""FortiGate device hardening — FGT-1.7/1.8/1.9 + 2.5.
run_cmd monkeypatched — no device access."""

from __future__ import annotations

import importlib

from kryon.compliance.checks.base import CheckContext

C17 = importlib.import_module("kryon.compliance.checks.fortigate.c_fgt_1_7_admin_gui_tls")
C18 = importlib.import_module("kryon.compliance.checks.fortigate.c_fgt_1_8_password_policy")
C19 = importlib.import_module("kryon.compliance.checks.fortigate.c_fgt_1_9_maintainer")
C25 = importlib.import_module("kryon.compliance.checks.fortigate.c_fgt_2_5_strong_crypto")

_GLOBAL_WEAK = (
    "hostname           : fw01\n"
    "admin-https-ssl-versions: tlsv1-1 tlsv1-2 tlsv1-3\n"
    "admin-maintainer   : enable\n"
    "strong-crypto      : disable\n"
)
_GLOBAL_HARDENED = (
    "hostname           : fw01\n"
    "admin-https-ssl-versions: tlsv1-2 tlsv1-3\n"
    "admin-maintainer   : disable\n"
    "strong-crypto      : enable\n"
)
_PWPOL_GOOD = "status             : enable\nminimum-length     : 12\n"
_PWPOL_DISABLED = "status             : disable\nminimum-length     : 8\n"
_PWPOL_SHORT = "status             : enable\nminimum-length     : 4\n"


def _out(text: str, rc: int = 0):
    def fake(_ctx, _cmd, **_kw):
        return (text, "", rc)

    return fake


# --- 1.7 admin GUI TLS ---


def test_17_fail_weak_tls(monkeypatch):
    monkeypatch.setattr(C17, "run_cmd", _out(_GLOBAL_WEAK))
    r = C17.CHECK.run(CheckContext(host="fw"))
    assert r.verdict == "FAIL"
    assert "tlsv1-1" in r.evidence_parsed["weak_versions_enabled"]


def test_17_pass_strong_tls(monkeypatch):
    monkeypatch.setattr(C17, "run_cmd", _out(_GLOBAL_HARDENED))
    assert C17.CHECK.run(CheckContext(host="fw")).verdict == "PASS"


# --- 1.8 password policy ---


def test_18_pass_enforced(monkeypatch):
    monkeypatch.setattr(C18, "run_cmd", _out(_PWPOL_GOOD))
    assert C18.CHECK.run(CheckContext(host="fw")).verdict == "PASS"


def test_18_fail_disabled(monkeypatch):
    monkeypatch.setattr(C18, "run_cmd", _out(_PWPOL_DISABLED))
    assert C18.CHECK.run(CheckContext(host="fw")).verdict == "FAIL"


def test_18_fail_too_short(monkeypatch):
    monkeypatch.setattr(C18, "run_cmd", _out(_PWPOL_SHORT))
    assert C18.CHECK.run(CheckContext(host="fw")).verdict == "FAIL"


# --- 1.9 maintainer ---


def test_19_fail_maintainer_enabled(monkeypatch):
    monkeypatch.setattr(C19, "run_cmd", _out(_GLOBAL_WEAK))
    assert C19.CHECK.run(CheckContext(host="fw")).verdict == "FAIL"


def test_19_pass_maintainer_disabled(monkeypatch):
    monkeypatch.setattr(C19, "run_cmd", _out(_GLOBAL_HARDENED))
    assert C19.CHECK.run(CheckContext(host="fw")).verdict == "PASS"


# --- 2.5 strong-crypto ---


def test_25_fail_disabled(monkeypatch):
    monkeypatch.setattr(C25, "run_cmd", _out(_GLOBAL_WEAK))
    assert C25.CHECK.run(CheckContext(host="fw")).verdict == "FAIL"


def test_25_pass_enabled(monkeypatch):
    monkeypatch.setattr(C25, "run_cmd", _out(_GLOBAL_HARDENED))
    assert C25.CHECK.run(CheckContext(host="fw")).verdict == "PASS"


# --- registration ---


def test_hardening_checks_registered():
    from kryon.compliance.runner import registered_checks

    ids = {c.control_id for c in registered_checks()}
    assert {"FGT-1.7", "FGT-1.8", "FGT-1.9", "FGT-2.5"} <= ids
