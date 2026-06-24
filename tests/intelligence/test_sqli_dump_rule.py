"""Crawled parametrized GET endpoint → sqlmap auto-dump for flags (CWE-89). Target-driven, unlike the
bench-hardcoded F191 pre_hook: it attaches common SQLi param names to the app's OWN crawled paths and
runs sqlmap end-to-end (detect + --dump), greaping the dumped rows for THM{...}. Validated live on THM
SQHell: --technique=E --dump on /post?id=1 returned THM{FLAG5:...} (the bench hook + the model both
got 0 flags)."""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import _rule_sqli_dump, plan_next_action
from kryon.intelligence.fact_extractor import ExtractedFacts

_WEB = ExtractedFacts(
    services=((80, "http"),), hosts=("10.64.184.204",), paths=("/post", "/user", "/login")
)


def test_fires_on_crawled_paths():
    rec = _rule_sqli_dump(_WEB, [], "")
    assert rec is not None and rec.confidence >= 0.92
    assert "sqlmap" in rec.args and "--dump" in rec.args and "SQLI-DUMP" in rec.args


def test_attaches_common_params_and_greps_thm():
    rec = _rule_sqli_dump(_WEB, [], "")
    # builds base?param=1 across common SQLi param names + greps the dumped rows
    assert "?$k=1" in rec.args
    for k in ("id", "user", "page"):
        assert k in rec.args
    assert "THM" in rec.args


def test_targets_the_discovered_base_paths():
    rec = _rule_sqli_dump(_WEB, [], "")
    assert "/post" in rec.args and "/user" in rec.args


def test_drops_static_assets():
    facts = ExtractedFacts(
        services=((80, "http"),), hosts=("x",), paths=("/static/app.js", "/img/logo.png", "/post")
    )
    rec = _rule_sqli_dump(facts, [], "")
    assert "/static/app.js" not in rec.args and "logo.png" not in rec.args
    assert "/post" in rec.args


def test_drops_auth_forms():
    # /login + /register are POST auth, not GET ?id= injectable — probing them burns the timeout
    facts = ExtractedFacts(
        services=((80, "http"),), hosts=("x",), paths=("/login", "/register", "/post", "/user")
    )
    rec = _rule_sqli_dump(facts, [], "")
    assert "for b in /post /user;" in rec.args  # only content paths probed, auth dropped


def test_abstains_without_web_or_paths():
    assert _rule_sqli_dump(ExtractedFacts(services=((80, "http"),), hosts=("x",)), [], "") is None
    assert _rule_sqli_dump(ExtractedFacts(hosts=("x",), paths=("/a",)), [], "") is None


def test_abstains_once_run():
    assert _rule_sqli_dump(_WEB, ["[SQLI-DUMP http://x/post?id=1]"], "") is None
    assert _rule_sqli_dump(_WEB, ["[SQLI-VULN http://x/user?id=1]"], "") is None
