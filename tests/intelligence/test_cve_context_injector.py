"""Tests for the one-day CVE exploitation-context injector.

The injector is the "87% recipe" (Fang & Kang 2404.08144): hand the model the
CVE description so it can chain the exploit. Here we assert the pure extract /
format logic and the async build path with a stubbed enricher (no network).
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from kryon.intelligence.cve_context_injector import (
    build_cve_exploitation_context,
    extract_inferred_cves,
    format_exploitation_context,
    is_cve_exploit_context_enabled,
)


def _finding(**kw):
    base = {"verification_level": "inferred", "rule_id": "", "message": ""}
    base.update(kw)
    return SimpleNamespace(**base)


def _detail(cve_id, **kw):
    base = {
        "cve_id": cve_id,
        "description": "",
        "cvss_score": None,
        "cvss_vector": None,
        "epss_score": None,
        "epss_percentile": None,
        "exploit_available": False,
        "exploit_refs": [],
        "cisa_kev": False,
        "references": [],
    }
    base.update(kw)
    return SimpleNamespace(**base)


# --------------------------------------------------------------------------- #
# extract_inferred_cves
# --------------------------------------------------------------------------- #


def test_extracts_cve_from_inferred_rule_id():
    findings = [_finding(rule_id="cve-2024-6387")]
    assert extract_inferred_cves(findings) == ["CVE-2024-6387"]


def test_skips_confirmed_findings():
    # A confirmed finding already has ground truth — no scaffolding needed.
    findings = [_finding(verification_level="confirmed", rule_id="cve-2024-6387")]
    assert extract_inferred_cves(findings) == []


def test_skips_non_cve_rule_ids():
    findings = [_finding(rule_id="cookie-missing-httponly")]
    assert extract_inferred_cves(findings) == []


def test_falls_back_to_message_when_rule_not_cve():
    findings = [_finding(rule_id="version-outdated", message="CVE-2021-41773 aplicable en host:80")]
    assert extract_inferred_cves(findings) == ["CVE-2021-41773"]


def test_dedupes_preserving_order():
    findings = [
        _finding(rule_id="cve-2024-6387"),
        _finding(rule_id="cve-2021-41773"),
        _finding(rule_id="cve-2024-6387"),
    ]
    assert extract_inferred_cves(findings) == ["CVE-2024-6387", "CVE-2021-41773"]


def test_respects_limit():
    findings = [_finding(rule_id=f"cve-2020-{1000 + i}") for i in range(20)]
    assert len(extract_inferred_cves(findings, limit=3)) == 3


def test_empty_findings():
    assert extract_inferred_cves([]) == []
    assert extract_inferred_cves(None) == []


# --------------------------------------------------------------------------- #
# format_exploitation_context
# --------------------------------------------------------------------------- #


def test_format_empty_when_no_description():
    # No description == the 7% condition; nothing worth injecting.
    assert format_exploitation_context([_detail("CVE-2024-6387")]) == ""
    assert format_exploitation_context([]) == ""


def test_format_includes_description_and_metadata():
    d = _detail(
        "CVE-2021-41773",
        description="Path traversal in Apache HTTP Server 2.4.49 allows RCE.",
        cvss_score=9.8,
        cvss_vector="AV:N/AC:L",
        epss_score=0.9721,
        epss_percentile=0.99,
        exploit_available=True,
        exploit_refs=["https://exploit-db.com/exploits/50383"],
        cisa_kev=True,
        references=["https://httpd.apache.org/security/vulnerabilities_24.html"],
    )
    out = format_exploitation_context([d])
    assert "CVE-2021-41773" in out
    assert "Path traversal in Apache HTTP Server" in out  # the 87% payload
    assert "CVSS 9.8" in out
    assert "CISA KEV" in out
    assert "EPSS 0.9721" in out
    assert "exploit-db.com/exploits/50383" in out
    assert "vulnerabilities_24.html" in out


def test_format_truncates_long_description():
    d = _detail("CVE-2021-41773", description="A" * 5000)
    out = format_exploitation_context([d])
    # Cap keeps the injected block from blowing the turn budget.
    assert out.count("A") <= 900


# --------------------------------------------------------------------------- #
# build_cve_exploitation_context (async, stubbed enricher)
# --------------------------------------------------------------------------- #


class _StubEnricher:
    def __init__(self, mapping):
        self.mapping = mapping
        self.calls: list[str] = []

    async def enrich(self, cve_id):
        self.calls.append(cve_id)
        return self.mapping[cve_id]


async def test_build_bridges_inferred_finding_to_description():
    findings = [_finding(rule_id="cve-2021-41773")]
    enricher = _StubEnricher({"CVE-2021-41773": _detail("CVE-2021-41773", description="Path traversal → RCE.")})
    out = await build_cve_exploitation_context(findings, enricher=enricher)
    assert enricher.calls == ["CVE-2021-41773"]
    assert "Path traversal → RCE." in out


async def test_build_empty_when_no_inferred_cves():
    enricher = _StubEnricher({})
    out = await build_cve_exploitation_context([_finding(rule_id="cookie-x")], enricher=enricher)
    assert out == ""
    assert enricher.calls == []


async def test_build_survives_enricher_failure():
    class _Boom:
        async def enrich(self, cve_id):
            raise RuntimeError("NVD down")

    out = await build_cve_exploitation_context([_finding(rule_id="cve-2024-6387")], enricher=_Boom())
    assert out == ""  # one bad lookup → no block, no raise


# --------------------------------------------------------------------------- #
# gate
# --------------------------------------------------------------------------- #


def test_gate_off_by_default(monkeypatch):
    for k in ("KRYON_CVE_EXPLOIT_CONTEXT", "KRYON_RED_TEAM", "KRYON_CAPABLE_MODEL"):
        monkeypatch.delenv(k, raising=False)
    assert is_cve_exploit_context_enabled() is False


def test_gate_explicit_on(monkeypatch):
    monkeypatch.setenv("KRYON_CVE_EXPLOIT_CONTEXT", "true")
    assert is_cve_exploit_context_enabled() is True


def test_gate_explicit_off_overrides_profile(monkeypatch):
    monkeypatch.setenv("KRYON_CVE_EXPLOIT_CONTEXT", "false")
    monkeypatch.setenv("KRYON_RED_TEAM", "true")
    assert is_cve_exploit_context_enabled() is False


def test_gate_auto_on_under_red_team(monkeypatch):
    monkeypatch.delenv("KRYON_CVE_EXPLOIT_CONTEXT", raising=False)
    monkeypatch.setenv("KRYON_RED_TEAM", "true")
    assert is_cve_exploit_context_enabled() is True


# --------------------------------------------------------------------------- #
# PoC injection (curated hint + ExploitDB raw fetch)
# --------------------------------------------------------------------------- #


def test_format_renders_poc_when_provided():
    d = _detail("CVE-2021-41773", description="Path traversal in Apache 2.4.49.")
    out = format_exploitation_context([d], poc_by_cve={"CVE-2021-41773": "curl --path-as-is 'http://<TARGET>/x'"})
    assert "PoC / técnica de explotación" in out
    assert "--path-as-is" in out


def test_format_no_poc_section_without_map():
    # Backward-compat: default poc_by_cve=None → no PoC section (existing behavior).
    d = _detail("CVE-2021-41773", description="desc")
    assert "PoC / técnica" not in format_exploitation_context([d])


async def test_build_injects_curated_hint_for_known_cve():
    # The bench fix: CVE-2021-41773 must carry the exact --path-as-is + %2e syntax.
    findings = [_finding(rule_id="cve-2021-41773")]
    enricher = _StubEnricher({"CVE-2021-41773": _detail("CVE-2021-41773", description="Apache 2.4.49 traversal.")})
    out = await build_cve_exploitation_context(findings, enricher=enricher, fetch_poc=False)
    assert "--path-as-is" in out
    assert "%2e" in out
    assert "cgi-bin" in out


async def test_fetch_poc_excerpt_converts_exploits_url_to_raw():
    from kryon.intelligence.cve_context_injector import _fetch_poc_excerpt

    seen = {}

    async def _fetcher(url):
        seen["url"] = url
        return "id; cat /etc/passwd  # PoC body"

    out = await _fetch_poc_excerpt(["https://www.exploit-db.com/exploits/50383"], fetcher=_fetcher)
    assert seen["url"] == "https://www.exploit-db.com/raw/50383"
    assert "PoC body" in out


async def test_build_falls_back_to_fetch_when_no_curated_hint():
    # A CVE with no _EXPLOIT_HINTS entry uses the raw ExploitDB fetch.
    findings = [_finding(rule_id="cve-2099-9999")]
    enricher = _StubEnricher(
        {
            "CVE-2099-9999": _detail(
                "CVE-2099-9999", description="novel bug", exploit_refs=["https://www.exploit-db.com/exploits/99999"]
            )
        }
    )

    async def _fetcher(url):
        return "the concrete exploit payload line"

    out = await build_cve_exploitation_context(findings, enricher=enricher, poc_fetcher=_fetcher)
    assert "the concrete exploit payload line" in out


async def test_fetch_poc_excerpt_empty_without_edb_ref():
    from kryon.intelligence.cve_context_injector import _fetch_poc_excerpt

    assert await _fetch_poc_excerpt(["https://other.com/x"]) == ""
    assert await _fetch_poc_excerpt([]) == ""
