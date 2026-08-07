"""Tests for the post-detection --dbs enumeration planner rule.

The planner recommends schema enumeration (--dbs, names only) after sqlmap has
probed a parametrized endpoint. It deliberately never recommends a raw --dump
(data extraction with possible PII is left to the masked sqlmap_dump_database
tool the skill drives).
"""

from __future__ import annotations

import pytest

from kryon.intelligence.exploit_chain_planner import (
    _RULES,
    _rule_sqlmap_dbs_after_detection,
)
from kryon.intelligence.fact_extractor import ExtractedFacts


def _facts():
    return ExtractedFacts(hosts=("10.0.0.5",), paths=("/item.php?id=1",))


@pytest.mark.unit
def test_fires_after_sqlmap_ran():
    rec = _rule_sqlmap_dbs_after_detection(_facts(), ["sqlmap -u http://10.0.0.5/item.php?id=1 --batch"], "")
    assert rec is not None
    assert rec.tool == "run_command"
    assert "--dbs" in rec.args
    # planner must never recommend a raw data dump
    assert "--dump" not in rec.args
    assert "10.0.0.5" in rec.args


@pytest.mark.unit
def test_abstains_before_sqlmap():
    assert _rule_sqlmap_dbs_after_detection(_facts(), [], "") is None


@pytest.mark.unit
def test_abstains_after_enumeration_started():
    prior = ["sqlmap -u http://10.0.0.5/item.php?id=1 --dbs"]
    assert _rule_sqlmap_dbs_after_detection(_facts(), prior, "") is None


@pytest.mark.unit
def test_abstains_after_dump_tool_used():
    prior = ["sqlmap ...", "sqlmap_dump_database(url=...)"]
    assert _rule_sqlmap_dbs_after_detection(_facts(), prior, "") is None


@pytest.mark.unit
def test_abstains_without_parametrized_path():
    facts = ExtractedFacts(hosts=("10.0.0.5",), paths=("/about",))
    assert _rule_sqlmap_dbs_after_detection(facts, ["sqlmap -u http://x"], "") is None


@pytest.mark.unit
def test_abstains_without_host():
    facts = ExtractedFacts(paths=("/item.php?id=1",))
    assert _rule_sqlmap_dbs_after_detection(facts, ["sqlmap -u http://x"], "") is None


@pytest.mark.unit
def test_rule_is_registered():
    assert _rule_sqlmap_dbs_after_detection in _RULES
