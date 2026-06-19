"""Batch R — IMAP/POP3 cleartext-auth posture. The capability exchange is mocked."""

from __future__ import annotations

import kryon.cli.mail_probes as mp
from kryon.cli.engage import DiscoveredService


def _svc(port: int) -> DiscoveredService:
    return DiscoveredService(host="127.0.0.1", port=port, state="open", service="")


def test_imap_cleartext_detected(monkeypatch):
    monkeypatch.setattr(mp, "_banner_and_caps", lambda *a, **k: "* CAPABILITY IMAP4rev1 AUTH=PLAIN")
    f = mp._check_imap(_svc(143))
    assert f is not None and f.rule_id == "imap-cleartext-auth"


def test_imap_with_starttls_clean(monkeypatch):
    monkeypatch.setattr(mp, "_banner_and_caps", lambda *a, **k: "* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED")
    assert mp._check_imap(_svc(143)) is None


def test_imap_logindisabled_clean(monkeypatch):
    monkeypatch.setattr(mp, "_banner_and_caps", lambda *a, **k: "* CAPABILITY IMAP4rev1 LOGINDISABLED")
    assert mp._check_imap(_svc(143)) is None


def test_pop3_cleartext_detected(monkeypatch):
    monkeypatch.setattr(mp, "_banner_and_caps", lambda *a, **k: "+OK\r\nUSER\r\nSASL PLAIN\r\n.")
    assert mp._check_pop3(_svc(110)).rule_id == "pop3-cleartext-auth"


def test_pop3_with_stls_clean(monkeypatch):
    monkeypatch.setattr(mp, "_banner_and_caps", lambda *a, **k: "+OK\r\nSTLS\r\nUSER\r\n.")
    assert mp._check_pop3(_svc(110)) is None


def test_run_mail_probes_gates_on_port(monkeypatch):
    monkeypatch.setattr(mp, "_banner_and_caps", lambda *a, **k: "* CAPABILITY IMAP4rev1 AUTH=PLAIN")
    assert mp.run_mail_probes(_svc(143))  # IMAP fires
    assert mp.run_mail_probes(_svc(8080)) == []  # unrelated port → nothing


def test_unreachable_returns_none(monkeypatch):
    monkeypatch.setattr(mp, "_banner_and_caps", lambda *a, **k: None)
    assert mp._check_imap(_svc(143)) is None and mp._check_pop3(_svc(110)) is None
