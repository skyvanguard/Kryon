"""Fase 3 wiring — _run_openvas_phase + the --openvas CLI flag."""

from __future__ import annotations

import argparse

from kryon.cli.investigate import _run_openvas_phase, add_investigate_subparser

_XML = (
    '<get_results_response status="200"><result id="r1">'
    "<name>OpenSSL</name><host>10.0.0.5</host><port>443/tcp</port>"
    '<nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>OpenSSL vuln</name>'
    '<cvss_base>7.5</cvss_base><refs><ref type="cve" id="CVE-2021-3711"/></refs>'
    "<solution>Upgrade OpenSSL</solution></nvt>"
    "<severity>7.5</severity><qod><value>80</value></qod>"
    "<description>Installed 1.1.1f</description></result></get_results_response>"
)


class _FakeClient:
    def __init__(self, xml: str):
        self._xml = xml
        self.scanned: str | None = None

    def run_scan(self, target: str, **_kw) -> str:
        self.scanned = target
        return self._xml


def test_phase_maps_findings_via_injected_client():
    c = _FakeClient(_XML)
    findings = _run_openvas_phase("10.0.0.5", client=c)
    assert c.scanned == "10.0.0.5"
    assert any(f.rule_id == "CVE-2021-3711" for f in findings)
    assert all(f.needs_verification for f in findings)
    assert all(f.confidence == 0.8 for f in findings)  # QoD 80


def test_phase_empty_results_returns_empty():
    c = _FakeClient('<get_results_response status="200"></get_results_response>')
    assert _run_openvas_phase("10.0.0.5", client=c) == []


def test_openvas_flag_registered_and_parses():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    add_investigate_subparser(sub)
    args = parser.parse_args(["investigate", "--url", "http://x", "--active", "--openvas"])
    assert args.openvas is True


def test_openvas_flag_defaults_off():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    add_investigate_subparser(sub)
    args = parser.parse_args(["investigate", "--url", "http://x"])
    assert args.openvas is False
