"""Wave-1 deterministic scenario coverage: anonymous-writable-FTP + web-served dir →
webshell RCE (the live Spice Hut chain). Validated end-to-end against the real box:
the rule's command got uid=33(www-data) where the local LLM burned 25 turns and failed.
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import (
    _rule_ftp_anon_webshell_upload,
    plan_next_action,
)
from kryon.intelligence.fact_extractor import ExtractedFacts


def test_fires_on_ftp_plus_http_non_ad():
    f = ExtractedFacts(services=((21, "ftp"), (22, "ssh"), (80, "http")))
    rec = _rule_ftp_anon_webshell_upload(f, [], "")
    assert rec is not None
    assert rec.confidence >= 0.92  # autoexec-eligible — deterministic RCE attempt
    assert "k.php" in rec.args and "anonymous" in rec.args
    assert "RCE CONFIRMED" in rec.args  # self-verifying command


def test_abstains_on_ad_target():
    # AD box (domain present) — secretsdump/asrep chain owns it, not webshell upload.
    f = ExtractedFacts(services=((21, "ftp"), (80, "http")), domains=("corp.local",))
    assert _rule_ftp_anon_webshell_upload(f, [], "") is None


def test_abstains_without_ftp_or_web():
    assert _rule_ftp_anon_webshell_upload(ExtractedFacts(services=((22, "ssh"), (80, "http"))), [], "") is None
    assert _rule_ftp_anon_webshell_upload(ExtractedFacts(services=((21, "ftp"), (22, "ssh"))), [], "") is None


def test_abstains_when_already_attempted():
    f = ExtractedFacts(services=((21, "ftp"), (80, "http")))
    assert _rule_ftp_anon_webshell_upload(f, ["curl -T /tmp/k.php ftp://x"], "") is None


def test_fires_on_https_and_alt_http_ports():
    assert _rule_ftp_anon_webshell_upload(ExtractedFacts(services=((21, "ftp"), (443, "https"))), [], "") is not None
    assert _rule_ftp_anon_webshell_upload(ExtractedFacts(services=((21, "ftp"), (8080, "http-alt"))), [], "") is not None


def test_plan_next_action_selects_it():
    f = ExtractedFacts(services=((21, "ftp"), (80, "http")))
    rec = plan_next_action(f, prior_tool_args=[], intent="")
    assert rec is not None and "k.php" in rec.args
