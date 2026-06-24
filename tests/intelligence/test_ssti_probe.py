"""SSTI probe over the discovered web surface (CWE-1336): a unique 1337*1337 marker across template
engines confirms injection, then the engine RCE payload runs. Validated end-to-end against a local
vulnerable Flask/Jinja2 app: detected {{1337*1337}}->1787569 and fired os.popen('id') for uid=. THM
Rabbit Store's chain ends in a Jinja2 SSTI -> RCE; this is the general engine for any reachable SSTI.
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import _rule_ssti_probe, plan_next_action
from kryon.intelligence.fact_extractor import ExtractedFacts

_WEB = ExtractedFacts(services=((80, "http"),), hosts=("cloudsite.thm",), paths=("/page?name=x", "/api/search?q=1"))


def test_fires_on_param_web_surface():
    rec = _rule_ssti_probe(_WEB, [], "")
    assert rec is not None and rec.confidence >= 0.92
    assert "1787569" in rec.args and "SSTI-HIT" in rec.args


def test_covers_multiple_template_engines():
    rec = _rule_ssti_probe(_WEB, [], "")
    for wrapper in ("{{1337*1337}}", "${1337*1337}", "#{1337*1337}", "<%=1337*1337%>"):
        assert wrapper in rec.args
    # Jinja2 RCE payload present
    assert "os.popen" in rec.args and "cycler" in rec.args


def test_injects_into_existing_param_not_appends():
    # the path already carries ?name= — the command must inject into that param (strip its value),
    # not append a duplicate the server ignores (the bug the live Flask test caught)
    rec = _rule_ssti_probe(_WEB, [], "")
    assert r'BASE="${u%%\?*}"' in rec.args or r"%%\?*" in rec.args


def test_abstains_without_web_or_paths():
    assert _rule_ssti_probe(ExtractedFacts(services=((80, "http"),), hosts=("x",)), [], "") is None
    assert _rule_ssti_probe(ExtractedFacts(hosts=("x",), paths=("/a?b=1",)), [], "") is None


def test_abstains_when_already_run():
    assert _rule_ssti_probe(_WEB, [": ssti_probe ... [SSTI-HIT]"], "") is None
