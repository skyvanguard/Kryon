"""Wave-1 deterministic coverage: loot exposed web backups/configs for creds/hashes.
Validated live against THM LazyAdmin: the rule's command harvested the SweetRice admin MD5
from /content/inc/mysql_backup/ (which the slow LLM would otherwise have to find by hand).
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import _rule_web_loot_credentials, plan_next_action
from kryon.intelligence.fact_extractor import ExtractedFacts


def test_fires_self_contained_on_bare_http():
    # Self-contained: fires on HTTP alone (no facts.paths needed) and probes its own
    # curated dir list including the CMS backup convention that leaks LazyAdmin's hash.
    rec = _rule_web_loot_credentials(ExtractedFacts(services=((80, "http"),)), [], "")
    assert rec is not None
    assert rec.confidence >= 0.92
    assert "[LOOT" in rec.args and "mysql_backup" in rec.args and "/content/" in rec.args


def test_appends_discovered_paths_when_present():
    rec = _rule_web_loot_credentials(ExtractedFacts(services=((80, "http"),), paths=("/secretapp/",)), [], "")
    assert "/secretapp/" in rec.args


def test_abstains_on_code_exec_signal():
    # An eval/REPL-RCE target belongs to the code-exec rules, not web-loot.
    f = ExtractedFacts(services=((80, "http"),), hints=("invalid syntax",))
    assert _rule_web_loot_credentials(f, [], "") is None


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
