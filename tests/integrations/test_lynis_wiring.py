"""Fase 3 — Lynis wired into engage + investigate (phase helpers + --lynis flags)."""

from __future__ import annotations

import argparse

from kryon.cli.engage import _run_lynis_engage_phase, add_engage_subparser
from kryon.cli.investigate import _run_lynis_phase, add_investigate_subparser

_REPORT = "lynis_version=3.0.9\nwarning[]=SSH-7408|Weak SSH|-|\nsuggestion[]=BOOT-5122|Set GRUB pw|-|\n"


def _runner(_cmd: str) -> str:
    return _REPORT


class _StubConsole:
    def print(self, *_a, **_k):
        pass


# --- engage ---


def test_engage_lynis_phase_maps():
    findings = _run_lynis_engage_phase(_StubConsole(), target="10.0.0.5", ssh_user="root", runner=_runner)
    assert any(f.rule_id == "LYNIS-SSH-7408" for f in findings)
    warn = next(f for f in findings if f.rule_id == "LYNIS-SSH-7408")
    assert warn.severity == "MEDIUM"
    assert warn.host == "10.0.0.5"


def test_engage_lynis_flag():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    add_engage_subparser(sub)
    assert parser.parse_args(["engage", "10.0.0.5", "--lynis"]).lynis is True
    assert parser.parse_args(["engage", "10.0.0.5"]).lynis is False


# --- investigate ---


def test_investigate_lynis_phase_maps():
    findings = _run_lynis_phase("10.0.0.5", ssh_user="root", runner=_runner)
    assert any(f.rule_id == "LYNIS-SSH-7408" for f in findings)


def test_investigate_lynis_flag():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    add_investigate_subparser(sub)
    args = parser.parse_args(["investigate", "--url", "http://x", "--active", "--lynis"])
    assert args.lynis is True
    assert parser.parse_args(["investigate", "--url", "http://x"]).lynis is False
