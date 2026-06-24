"""PHP endpoint + fuzzed parameter → command injection, base64-aware (CWE-78). The active-rce skills
use nuclei, which needs the param name and matches the command output verbatim — so it misses an app
that returns the RCE output BASE64-encoded. THM U.A. High School: /assets/index.php?cmd=id -> base64 of
uid=33(www-data). This rule fuzzes the common RCE params against discovered .php endpoints and decodes
base64. Validated live on U.A. High School."""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import _rule_php_cmdi_param, plan_next_action
from kryon.intelligence.fact_extractor import ExtractedFacts

_WEB = ExtractedFacts(services=((80, "http"),), hosts=("10.67.136.209",), paths=("/index.html", "/assets"))


def test_fires_on_web_surface():
    rec = _rule_php_cmdi_param(_WEB, [], "")
    assert rec is not None and rec.confidence >= 0.92
    assert "PHP-CMDI" in rec.args and "?$k=id" in rec.args


def test_base64_aware_detection():
    rec = _rule_php_cmdi_param(_WEB, [], "")
    # decodes a base64 body to find uid= (the U.A. High School case nuclei misses)
    assert "base64 -d" in rec.args and "uid=[0-9]" in rec.args


def test_fuzzes_common_rce_params_and_probes_assets_index():
    rec = _rule_php_cmdi_param(_WEB, [], "")
    for k in ("cmd", "command", "exec"):
        assert k in rec.args
    assert "/assets/index.php" in rec.args  # the common cmdi spot is probed even if not crawled


def test_includes_discovered_php_endpoints():
    facts = ExtractedFacts(services=((80, "http"),), hosts=("x",), paths=("/api/run.php?x=1",))
    rec = _rule_php_cmdi_param(facts, [], "")
    assert "/api/run.php" in rec.args


def test_abstains_without_web():
    assert _rule_php_cmdi_param(ExtractedFacts(hosts=("x",), paths=("/a.php",)), [], "") is None


def test_abstains_once_run():
    assert _rule_php_cmdi_param(_WEB, ["[PHP-CMDI http://x/assets/index.php?cmd= (base64)]"], "") is None
