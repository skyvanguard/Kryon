"""Eval-injection RCE on a non-web service (Python input(), exposed REPL, 'send exploits' prompt).
Banner-grab + __import__('os').popen() in one shot — the model recognises this class but fumbles the
raw-socket framing (THM Develpy: 19 turns without landing it). Validated live: the rule's command
returned uid=1000(king) + the user.txt flag against Develpy's port-10000 Python 2 input() service.
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import _rule_eval_service_rce, plan_next_action
from kryon.intelligence.fact_extractor import ExtractedFacts

_SVC = ExtractedFacts(services=((22, "ssh"), (10000, "snet-sensor-mgmt")), hosts=("10.67.157.203",))


def test_fires_on_non_web_service_port():
    rec = _rule_eval_service_rce(_SVC, [], "")
    assert rec is not None
    assert rec.confidence >= 0.92
    assert "10000" in rec.args and "__import__" in rec.args
    assert "EVAL-RCE" in rec.args and "user.txt" in rec.args


def test_excludes_web_ssh_dns_ports():
    # only web/ssh/dns/smtp open → nothing to eval-probe
    assert _rule_eval_service_rce(ExtractedFacts(services=((80, "http"), (22, "ssh"), (53, "dns"))), [], "") is None


def test_abstains_when_already_run():
    assert _rule_eval_service_rce(_SVC, [": eval_svc ... [EVAL-RCE 10000]"], "") is None


def test_only_probes_uncommon_ports_not_known_services():
    # known services (Redis/SMB/MySQL) have their own rules and aren't eval prompts → excluded,
    # so the eval probe doesn't preempt them; it targets the weird raw port (e.g. :10000)
    assert _rule_eval_service_rce(ExtractedFacts(services=((6379, "redis"),), hosts=("x",)), [], "") is None
    assert _rule_eval_service_rce(ExtractedFacts(services=((9001, "tcpwrapped"),), hosts=("x",)), [], "") is not None


def test_command_gates_payload_behind_eval_signature():
    # safe-by-design: the command only fires the payload when the banner matches an eval signature
    rec = _rule_eval_service_rce(_SVC, [], "")
    assert "Traceback|SyntaxError" in rec.args and "input(" in rec.args


def test_plan_selects_eval_rce_on_raw_service():
    rec = plan_next_action(_SVC, prior_tool_args=[], intent="")
    assert rec is not None and "EVAL-RCE" in rec.args
