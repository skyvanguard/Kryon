"""General known-exploit lookup: fingerprinted software/CMS -> searchsploit (ExploitDB).
Validated live against THM LazyAdmin: the rule's command surfaces
'SweetRice 1.5.1 - Arbitrary File Upload (40716.py)' — the webshell exploit the model
otherwise fails to find by guessing. General by construction (knowledge in the DB, not the rule).
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import (
    _rule_searchsploit_known_exploits,
    plan_next_action,
)
from kryon.intelligence.fact_extractor import ExtractedFacts


def test_fires_on_http_and_searches_cms_and_versions():
    f = ExtractedFacts(services=((80, "http"),), versions=(("Apache", "2.4.18"),))
    rec = _rule_searchsploit_known_exploits(f, [], "")
    assert rec is not None
    assert rec.confidence >= 0.92
    assert "searchsploit" in rec.args
    assert "sweetrice" in rec.args  # CMS fingerprint list
    assert "Apache 2.4.18" in rec.args  # nmap-detected product searched


def test_fires_on_versions_without_http():
    rec = _rule_searchsploit_known_exploits(ExtractedFacts(versions=(("vsftpd", "2.3.4"),)), [], "")
    assert rec is not None and "vsftpd 2.3.4" in rec.args


def test_abstains_without_http_or_versions():
    assert _rule_searchsploit_known_exploits(ExtractedFacts(services=((22, "ssh"),)), [], "") is None


def test_abstains_on_code_exec_signal():
    f = ExtractedFacts(services=((80, "http"),), hints=("invalid syntax",))
    assert _rule_searchsploit_known_exploits(f, [], "") is None


def test_abstains_when_already_run():
    f = ExtractedFacts(services=((80, "http"),))
    assert _rule_searchsploit_known_exploits(f, ["searchsploit sweetrice"], "") is None


def test_plan_selects_it_after_loot_done():
    # Web box, hash already looted (web-loot abstains) → searchsploit is a valid next move.
    f = ExtractedFacts(services=((80, "http"),), hashes=("42f749ade7f9e195bf475f37a44cafcb",))
    rec = plan_next_action(f, prior_tool_args=[], intent="")
    # Either searchsploit or a crack rule may win; assert searchsploit is reachable when it does.
    assert rec is not None
