"""Mejora 3 — OpenVAS wired into engage (_run_openvas_engage_phase + --openvas)."""

from __future__ import annotations

import argparse

from kryon.cli.engage import _run_openvas_engage_phase, add_engage_subparser

_XML = (
    '<get_results_response status="200"><result id="r1">'
    "<name>OpenSSL</name><host>10.0.0.5</host><port>443/tcp</port>"
    '<nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>OpenSSL vuln</name>'
    '<cvss_base>7.5</cvss_base><refs><ref type="cve" id="CVE-2021-3711"/></refs>'
    "<solution>Upgrade</solution></nvt>"
    "<severity>7.5</severity><qod><value>80</value></qod>"
    "<description>x</description></result></get_results_response>"
)


class _StubConsole:
    def print(self, *_a, **_k):
        pass


class _FakeClient:
    def __init__(self, xml: str):
        self._xml = xml

    def run_scan(self, _target: str, **_kw) -> str:
        return self._xml


class _RaisingClient:
    def run_scan(self, _target: str, **_kw) -> str:
        raise RuntimeError("gvmd unreachable")


def test_engage_phase_maps_findings():
    findings = _run_openvas_engage_phase(_StubConsole(), target="10.0.0.5", client=_FakeClient(_XML))
    assert any(f.rule_id == "CVE-2021-3711" for f in findings)
    assert all(f.needs_verification for f in findings)


def test_engage_phase_swallows_errors():
    # Scan failure must never break the engagement — returns [] silently.
    findings = _run_openvas_engage_phase(_StubConsole(), target="10.0.0.5", client=_RaisingClient())
    assert findings == []


def test_engage_openvas_flag_registered():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    add_engage_subparser(sub)
    args = parser.parse_args(["engage", "10.0.0.5", "--openvas"])
    assert args.openvas is True


def test_engage_openvas_flag_default_off():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    add_engage_subparser(sub)
    args = parser.parse_args(["engage", "10.0.0.5"])
    assert args.openvas is False
