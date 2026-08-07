"""Fase 3 — Cinc wired into engage + investigate (phase helpers + --cinc flags)."""

from __future__ import annotations

import argparse
import types

from kryon.cli.engage import _parse_ssh_user_port, _run_cinc_engage_phase, add_engage_subparser
from kryon.cli.investigate import _run_cinc_phase, add_investigate_subparser

_JSON = (
    '{"profiles":[{"name":"ssh-baseline","controls":['
    '{"id":"sshd-01","title":"Set protocol 2","impact":1.0,'
    '"results":[{"status":"failed","code_desc":"Protocol should eq 2"}]}]}]}'
)


def _runner(*_a, **_k):
    return types.SimpleNamespace(returncode=100, stdout=_JSON, stderr="")


class _StubConsole:
    def print(self, *_a, **_k):
        pass


# --- engage ---


def test_engage_cinc_phase_maps(monkeypatch):
    monkeypatch.setenv("KRYON_CINC_PROFILES", "https://x/ssh-baseline")  # single profile → deterministic
    findings = _run_cinc_engage_phase(_StubConsole(), target="10.0.0.5", ssh_user="root", runner=_runner)
    assert any(f.rule_id == "CINC-sshd-01" for f in findings)
    assert all(f.confidence == 1.0 for f in findings)


def test_parse_ssh_user_port():
    assert _parse_ssh_user_port("root@10.0.0.5:2222") == ("root", 2222)
    assert _parse_ssh_user_port("admin@host") == ("admin", 22)
    assert _parse_ssh_user_port("10.0.0.5") == ("", 22)
    assert _parse_ssh_user_port("") == ("", 22)


def test_engage_cinc_flag(monkeypatch):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    add_engage_subparser(sub)
    assert parser.parse_args(["engage", "10.0.0.5", "--cinc"]).cinc is True
    assert parser.parse_args(["engage", "10.0.0.5"]).cinc is False


# --- investigate ---


def test_investigate_cinc_phase_maps(monkeypatch):
    monkeypatch.setenv("KRYON_CINC_PROFILES", "https://x/ssh-baseline")
    findings = _run_cinc_phase("10.0.0.5", ssh_user="root", runner=_runner)
    assert any(f.rule_id == "CINC-sshd-01" for f in findings)


def test_investigate_cinc_flag():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    add_investigate_subparser(sub)
    args = parser.parse_args(["investigate", "--url", "http://x", "--active", "--cinc"])
    assert args.cinc is True
    assert parser.parse_args(["investigate", "--url", "http://x"]).cinc is False
