"""FASE 9.A — distilled YAML rule tests.

Three concentric layers of pinning:

1. ``parse_distilled_rule`` validates a Python dict (post-YAML-load).
   Tests cover required fields, type coercion, and predicate parsing.
2. ``DistilledRule.as_callable`` returns a planner-shaped function.
   Tests exercise each predicate (hints_any_of, services_have_non_ssh_port,
   creds_present, not_invoked_before, ...) + the args template
   substitution.
3. ``load_distilled_rules`` walks a directory and surfaces only valid
   rules. Tests use tmp_path to isolate filesystem effects.

The goal is to be confident that an operator dropping a YAML file in
``~/.kryon/distilled_rules/`` extends the planner without breaking
anything when the YAML is malformed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kryon.intelligence.distillation import (
    DistilledRule,
    load_distilled_rules,
    parse_distilled_rule,
)
from kryon.intelligence.fact_extractor import ExtractedFacts


# ---------------------------------------------------------------------------
# parse_distilled_rule — schema validation
# ---------------------------------------------------------------------------


def test_parse_minimal_valid_rule() -> None:
    data = {
        "name": "minimal",
        "emit": {
            "tool": "run_command",
            "args": "echo hello",
        },
    }
    rule = parse_distilled_rule(data)
    assert rule.name == "minimal"
    assert rule.tool == "run_command"
    assert rule.args_template == "echo hello"
    # Default confidence keeps low-stakes rules out of the OPERATOR
    # DIRECTIVE block.
    assert rule.confidence == 0.8


def test_parse_rejects_missing_name() -> None:
    with pytest.raises(ValueError, match="name"):
        parse_distilled_rule({"emit": {"tool": "x", "args": "y"}})


def test_parse_rejects_missing_emit_tool() -> None:
    with pytest.raises(ValueError, match="tool"):
        parse_distilled_rule({"name": "x", "emit": {"args": "y"}})


def test_parse_rejects_missing_emit_args() -> None:
    with pytest.raises(ValueError, match="args"):
        parse_distilled_rule({"name": "x", "emit": {"tool": "y"}})


def test_parse_rejects_confidence_out_of_range() -> None:
    with pytest.raises(ValueError, match="confidence"):
        parse_distilled_rule({
            "name": "x",
            "confidence": 1.5,
            "emit": {"tool": "y", "args": "z"},
        })


def test_parse_accepts_string_hints_as_single_entry() -> None:
    """``hints_any_of: "invalid syntax"`` (no list) should coerce to
    a single-element tuple. YAML often writes scalars when there's
    only one entry."""
    rule = parse_distilled_rule({
        "name": "x",
        "emit": {"tool": "y", "args": "z"},
        "when": {"hints_any_of": "invalid syntax"},
    })
    assert rule.hints_any_of == ("invalid syntax",)


# ---------------------------------------------------------------------------
# DistilledRule.as_callable — predicates + substitutions
# ---------------------------------------------------------------------------


def _make_rule(**overrides):
    """Helper: minimal DistilledRule + overrides."""
    defaults = {
        "name": "test",
        "confidence": 0.9,
        "tool": "run_command",
        "args_template": "echo test",
        "rationale": "test",
    }
    defaults.update(overrides)
    return DistilledRule(**defaults)


def test_hints_any_of_fires_when_one_matches() -> None:
    rule = _make_rule(hints_any_of=("invalid syntax", "nameerror"))
    fn = rule.as_callable()
    facts = ExtractedFacts(hints=("oh look, invalid syntax somewhere",))
    assert fn(facts, [], "") is not None


def test_hints_any_of_abstains_when_none_match() -> None:
    rule = _make_rule(hints_any_of=("invalid syntax",))
    fn = rule.as_callable()
    facts = ExtractedFacts(hints=("an unrelated hint",))
    assert fn(facts, [], "") is None


def test_hints_all_of_requires_every_match() -> None:
    rule = _make_rule(hints_all_of=("invalid syntax", "permission denied"))
    fn = rule.as_callable()
    only_one = ExtractedFacts(hints=("invalid syntax — boom",))
    assert fn(only_one, [], "") is None
    both = ExtractedFacts(hints=("invalid syntax", "permission denied"))
    assert fn(both, [], "") is not None


def test_services_non_ssh_port_substitutes_into_args() -> None:
    """The ``{port}`` placeholder in args gets replaced with the first
    non-22 port from facts.services when the predicate fires."""
    rule = _make_rule(
        args_template="echo 'probe' | nc -q 1 -w 5 <target> {port}",
        services_have_non_ssh_port=True,
    )
    fn = rule.as_callable()
    facts = ExtractedFacts(services=((22, "ssh"), (8000, "http-alt")))
    rec = fn(facts, [], "")
    assert rec is not None
    assert "8000" in rec.args
    # ``<target>`` stays as a literal — the reflective runner does that
    # substitution downstream with the concrete host.
    assert "<target>" in rec.args


def test_services_non_ssh_port_abstains_when_only_22_known() -> None:
    rule = _make_rule(
        args_template="echo x | nc <target> {port}",
        services_have_non_ssh_port=True,
    )
    fn = rule.as_callable()
    facts = ExtractedFacts(services=((22, "ssh"),))
    assert fn(facts, [], "") is None


def test_creds_present_substitutes_user_and_password() -> None:
    rule = _make_rule(
        args_template="sshpass -p '{password}' ssh {user}@<target> id",
        creds_present=True,
    )
    fn = rule.as_callable()
    facts = ExtractedFacts(creds=(("alice", "hunter2"),))
    rec = fn(facts, [], "")
    assert rec is not None
    assert "alice" in rec.args
    assert "hunter2" in rec.args


def test_domains_present_substitutes_domain() -> None:
    rule = _make_rule(
        args_template="GetNPUsers.py -no-pass {domain}/",
        domains_present=True,
    )
    fn = rule.as_callable()
    facts = ExtractedFacts(domains=("corp.local",))
    rec = fn(facts, [], "")
    assert rec is not None
    assert "corp.local" in rec.args


def test_not_invoked_before_blocks_after_marker_appears() -> None:
    rule = _make_rule(not_invoked_before=("kryon-probe",))
    fn = rule.as_callable()
    fresh = ExtractedFacts()
    assert fn(fresh, [], "") is not None
    seen = ["echo 'print(\"kryon-probe\")' | nc target 8000"]
    assert fn(fresh, seen, "") is None


def test_invoked_before_requires_marker() -> None:
    """``invoked_before`` is the chain-ordering predicate — rule
    abstains until a prior stage's marker shows up in history."""
    rule = _make_rule(invoked_before=("kryon-probe",))
    fn = rule.as_callable()
    fresh = ExtractedFacts()
    assert fn(fresh, [], "") is None
    seen = ["echo 'print(\"kryon-probe\")' | nc target 8000"]
    assert fn(fresh, seen, "") is not None


def test_users_present_minimum_threshold() -> None:
    rule = _make_rule(users_present=2)
    fn = rule.as_callable()
    one_user = ExtractedFacts(users=("alice",))
    assert fn(one_user, [], "") is None
    two_users = ExtractedFacts(users=("alice", "bob"))
    assert fn(two_users, [], "") is not None


def test_callable_returns_recommendation_with_correct_confidence() -> None:
    rule = _make_rule(confidence=0.77)
    fn = rule.as_callable()
    rec = fn(ExtractedFacts(), [], "")
    assert rec is not None
    assert rec.confidence == 0.77


# ---------------------------------------------------------------------------
# load_distilled_rules — directory scan + error tolerance
# ---------------------------------------------------------------------------


def _write_yaml(directory: Path, filename: str, body: str) -> Path:
    p = directory / filename
    p.write_text(body, encoding="utf-8")
    return p


def test_load_returns_empty_when_directory_missing(tmp_path: Path) -> None:
    rules = load_distilled_rules(tmp_path / "does-not-exist")
    assert rules == []


def test_load_picks_up_valid_yaml(tmp_path: Path) -> None:
    _write_yaml(tmp_path, "rule.yaml", """
name: simple_probe
confidence: 0.9
when:
  hints_any_of:
    - "invalid syntax"
  services_have_non_ssh_port: true
emit:
  tool: run_command
  args: 'echo probe | nc <target> {port}'
  rationale: ok
""")
    rules = load_distilled_rules(tmp_path)
    assert len(rules) == 1
    facts = ExtractedFacts(
        hints=("invalid syntax",),
        services=((8000, "http-alt"),),
    )
    rec = rules[0](facts, [], "")
    assert rec is not None
    assert "8000" in rec.args


def test_load_skips_malformed_yaml_without_crashing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A bad YAML must NOT take the planner down. Log a warning,
    continue with whatever valid rules exist."""
    _write_yaml(tmp_path, "bad.yaml", "this is not: : valid: yaml: ::")
    _write_yaml(tmp_path, "good.yaml", """
name: ok
emit:
  tool: run_command
  args: 'echo x'
""")
    rules = load_distilled_rules(tmp_path)
    assert len(rules) == 1  # only the good one


def test_load_skips_yaml_missing_required_fields(tmp_path: Path) -> None:
    """``emit.tool`` is required — file without it gets skipped."""
    _write_yaml(tmp_path, "missing.yaml", """
name: incomplete
emit:
  args: 'echo x'
""")
    rules = load_distilled_rules(tmp_path)
    assert rules == []


def test_load_orders_files_lexicographically(tmp_path: Path) -> None:
    """Operators use numeric prefixes (00_, 99_) to control ordering.
    The loader must respect lexicographic file order."""
    _write_yaml(tmp_path, "20_second.yaml", """
name: second
emit: {tool: run_command, args: 'echo second'}
""")
    _write_yaml(tmp_path, "10_first.yaml", """
name: first
emit: {tool: run_command, args: 'echo first'}
""")
    rules = load_distilled_rules(tmp_path)
    # The first-fired rule's args contain "echo first".
    rec = rules[0](ExtractedFacts(), [], "")
    assert rec is not None
    assert "first" in rec.args


def test_distilled_rule_args_keep_target_placeholder_literal(
    tmp_path: Path,
) -> None:
    """``<target>`` survives unsubstituted — the reflective runner
    fills it later with the concrete host. This is the contract."""
    _write_yaml(tmp_path, "x.yaml", """
name: with_target
emit:
  tool: run_command
  args: 'ssh user@<target> id'
""")
    rules = load_distilled_rules(tmp_path)
    rec = rules[0](ExtractedFacts(), [], "")
    assert rec is not None
    assert "<target>" in rec.args


# ---------------------------------------------------------------------------
# Integration with plan_next_action
# ---------------------------------------------------------------------------


def test_distilled_rule_fires_via_plan_next_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end: drop a YAML file, override the lookup directory,
    enable reload, call plan_next_action — the rule should fire if
    its preconditions hold AND no hard-coded F1-F8 rule beats it
    on the same facts."""
    from kryon.intelligence import exploit_chain_planner as planner_mod

    _write_yaml(tmp_path, "novel.yaml", """
name: novel_class_marker
confidence: 0.95
when:
  hints_any_of:
    - "kryon-novel-class-marker"
emit:
  tool: run_command
  args: 'echo from-distilled <target>'
  rationale: distilled fallback for novel CTF class
""")
    monkeypatch.setenv("KRYON_DISTILLED_RULES_DIR", str(tmp_path))
    monkeypatch.setenv("KRYON_DISTILLED_RULES_RELOAD", "true")
    # Clear the module cache so the new directory is rescanned.
    monkeypatch.setattr(planner_mod, "_CACHED_DISTILLED_RULES", None)

    # Pick a hint string no hard-coded rule recognises so only the
    # distilled rule has a chance to fire.
    facts = ExtractedFacts(hints=("kryon-novel-class-marker",))
    rec = planner_mod.plan_next_action(facts, [], "")
    assert rec is not None
    assert "from-distilled" in rec.args
