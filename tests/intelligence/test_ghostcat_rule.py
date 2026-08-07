"""Exposed Tomcat AJP/1.3 (port 8009) → Ghostcat file read (CVE-2020-1938). Kryon detected the AJP
exposure (compliance check) but had no exploit; this rule fires the vendored ghostcat module on the
webapp files that leak creds (WEB-INF/web.xml, context.xml, *.properties) and greps user:pass. Validated
live on THM tomghost: /WEB-INF/web.xml -> skyfuck:8730281lkjlkjdqlksalks (the SSH foothold)."""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import _rule_ghostcat_ajp_read, plan_next_action
from kryon.intelligence.fact_extractor import ExtractedFacts

_AJP = ExtractedFacts(services=((22, "ssh"), (8009, "ajp13"), (8080, "http-proxy")), hosts=("10.64.190.31",))


def test_fires_on_ajp_8009():
    rec = _rule_ghostcat_ajp_read(_AJP, [], "")
    assert rec is not None and rec.confidence >= 0.92
    assert "ghostcat" in rec.args and "8009" in rec.args and "GHOSTCAT-CREDS" in rec.args


def test_reads_cred_bearing_webapp_files():
    rec = _rule_ghostcat_ajp_read(_AJP, [], "")
    assert "/WEB-INF/web.xml" in rec.args
    assert "properties" in rec.args and "context.xml" in rec.args
    # uses the vendored module + targets the discovered host
    assert "kryon.tools.exploitation.ghostcat" in rec.args and "10.64.190.31" in rec.args


def test_skips_tomcat_error_page_false_positives():
    # the error-page guard + CSS exclusion keep the 404/500 page from false-positiving as creds
    rec = _rule_ghostcat_ajp_read(_AJP, [], "")
    assert "HTTP Status" in rec.args and "background-color" in rec.args


def test_fires_on_ajp_by_service_name():
    facts = ExtractedFacts(services=((8009, "ajp13"),), hosts=("x",))
    assert _rule_ghostcat_ajp_read(facts, [], "") is not None


def test_abstains_without_ajp():
    assert _rule_ghostcat_ajp_read(ExtractedFacts(services=((8080, "http"),), hosts=("x",)), [], "") is None


def test_abstains_once_run():
    assert _rule_ghostcat_ajp_read(_AJP, ["[GHOSTCAT-CREDS /WEB-INF/web.xml]"], "") is None


def test_plan_selects_ghostcat_on_ajp():
    rec = plan_next_action(_AJP, prior_tool_args=["nmap ... (service_scan)"], intent="")
    assert rec is not None and "ghostcat" in rec.args
