"""Webmin CVE-2019-15107 unauthenticated RCE rule (password_change.cgi backdoor). Self-contained
like the FTP-webshell rule: a Webmin banner -> fire the exploit -> root. Validated live on THM
Source: the rule's command returned uid=0(root) + the root flag THM{UPDATE_YOUR_INSTALL} in one
autoexec. The searchsploit rule surfaces this CVE; this one runs it.
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import (
    _rule_webmin_password_change_rce,
    plan_next_action,
)
from kryon.intelligence.fact_extractor import ExtractedFacts

_WEBMIN = ExtractedFacts(services=((10000, "http"),), versions=(("MiniServ", "1.890 (Webmin httpd)"),))


def test_fires_on_webmin_banner():
    rec = _rule_webmin_password_change_rce(_WEBMIN, [], "")
    assert rec is not None
    assert rec.confidence >= 0.92
    assert "password_change.cgi" in rec.args
    assert "expired=" in rec.args  # the qx/$in{'expired'}/ injection point
    assert "WEBMIN-RCE" in rec.args  # self-verifying marker


def test_matches_webmin_or_miniserv_product():
    assert _rule_webmin_password_change_rce(ExtractedFacts(versions=(("Webmin", "1.920"),)), [], "") is not None
    assert _rule_webmin_password_change_rce(ExtractedFacts(versions=(("MiniServ", "1.890"),)), [], "") is not None


def test_abstains_without_webmin():
    assert _rule_webmin_password_change_rce(ExtractedFacts(versions=(("Apache", "2.4.18"),)), [], "") is None
    assert _rule_webmin_password_change_rce(ExtractedFacts(services=((80, "http"),)), [], "") is None


def test_abstains_when_already_run():
    assert _rule_webmin_password_change_rce(_WEBMIN, ["curl ... password_change.cgi ..."], "") is None


def test_plan_selects_it_on_webmin_before_searchsploit():
    # The direct RCE should win over merely surfacing the exploit via searchsploit.
    rec = plan_next_action(_WEBMIN, prior_tool_args=[], intent="")
    assert rec is not None and "WEBMIN-RCE" in rec.args
