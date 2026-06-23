"""Wave-1 deterministic coverage: loot exposed web backups/configs for creds/hashes.
Validated live against THM LazyAdmin: the rule's command harvested the SweetRice admin MD5
from /content/inc/mysql_backup/ (which the slow LLM would otherwise have to find by hand).
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import _rule_web_loot_credentials, plan_next_action
from kryon.intelligence.fact_extractor import ExtractedFacts


def test_fires_on_http_with_discovered_paths():
    rec = _rule_web_loot_credentials(ExtractedFacts(services=((80, "http"),), paths=("/content/",)), [], "")
    assert rec is not None
    assert rec.confidence >= 0.92
    assert "[LOOT" in rec.args and "mysql_backup" in rec.args


def test_injects_discovered_paths():
    # gobuster-discovered /content must appear in the loot command's base list.
    rec = _rule_web_loot_credentials(ExtractedFacts(services=((80, "http"),), paths=("/content/",)), [], "")
    assert "/content/" in rec.args


def test_abstains_on_bare_http_before_recon():
    # No discovered paths yet → let gobuster/ffuf run first; don't preempt RCE rules.
    assert _rule_web_loot_credentials(ExtractedFacts(services=((80, "http"),)), [], "") is None


def test_abstains_when_creds_already_known():
    f = ExtractedFacts(services=((80, "http"),), paths=("/content/",), creds=(("manager", "Password123"),))
    assert _rule_web_loot_credentials(f, [], "") is None


def test_abstains_without_http():
    assert _rule_web_loot_credentials(ExtractedFacts(services=((22, "ssh"),), paths=("/x/",)), [], "") is None


def test_abstains_when_already_looted():
    f = ExtractedFacts(services=((80, "http"),), paths=("/content/",))
    assert _rule_web_loot_credentials(f, ["echo [LOOT /x] hash"], "") is None


def test_plan_next_action_selects_it_on_web_box():
    # Plain web box, no creds → loot is the move.
    rec = plan_next_action(ExtractedFacts(services=((80, "http"),), paths=("/content/",)), prior_tool_args=[], intent="")
    assert rec is not None and "[LOOT" in rec.args
