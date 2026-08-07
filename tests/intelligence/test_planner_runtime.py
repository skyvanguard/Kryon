"""FASE 6 — planner_runtime ContextVar contract tests.

The runtime bridge is the seam between the reflective_runner (where
facts + tool history live) and the execute_planner_directive
function_tool (which the LLM invokes from inside the SDK tool-use
loop). The tests pin three invariants:

1. ``set_current_state`` snapshots the inputs (callers can mutate the
   passed list afterwards without leaking state into the ContextVar).
2. ``get_current_state`` returns ``None`` outside a set window —
   the tool must refuse rather than synthesizing a bogus run.
3. ``clear_current_state`` actually clears so the next run starts
   fresh.

ContextVar semantics aren't exercised here (single-task tests); the
parent-task isolation invariant is covered implicitly by the
SDK's own asyncio test suite.
"""

from __future__ import annotations

from kryon.intelligence.fact_extractor import EMPTY, ExtractedFacts
from kryon.intelligence.planner_runtime import (
    clear_current_state,
    get_current_state,
    get_current_state_or_default,
    set_current_state,
)


def test_state_defaults_to_none_outside_set_window() -> None:
    """Fresh ContextVar in this test's task scope → None."""
    clear_current_state()
    assert get_current_state() is None


def test_get_state_or_default_returns_empty_facts_when_unset() -> None:
    """For callers that want a non-Optional shape."""
    clear_current_state()
    state = get_current_state_or_default()
    assert state.facts is EMPTY
    assert state.prior_tool_args == ()


def test_set_state_then_get_returns_same_snapshot() -> None:
    facts = ExtractedFacts(users=("alice",), domains=("thm.local",))
    set_current_state(facts, ["nc 1.2.3.4 8000", "curl http://x"])
    state = get_current_state()
    assert state is not None
    assert state.facts is facts
    assert "nc 1.2.3.4 8000" in state.prior_tool_args
    clear_current_state()


def test_set_state_snapshots_prior_args_into_tuple() -> None:
    """Caller may pass a mutable list and then continue appending to
    it; the ContextVar must hold an immutable tuple of the values at
    set-time."""
    args_list = ["nc 1.2.3.4 8000"]
    set_current_state(EMPTY, args_list)
    args_list.append("LEAKED — should not be visible in snapshot")
    state = get_current_state()
    assert state is not None
    assert isinstance(state.prior_tool_args, tuple)
    assert "LEAKED — should not be visible in snapshot" not in state.prior_tool_args
    clear_current_state()


def test_clear_state_resets_to_none() -> None:
    set_current_state(EMPTY, ())
    assert get_current_state() is not None
    clear_current_state()
    assert get_current_state() is None


def test_state_facts_field_is_passthrough_not_copied() -> None:
    """ExtractedFacts is frozen, so identity preservation is fine and
    cheaper than a deep copy. Confirm the snapshot holds the same
    object."""
    facts = ExtractedFacts(users=("alice",))
    set_current_state(facts, ())
    state = get_current_state()
    assert state is not None
    assert state.facts is facts
    clear_current_state()


# ---------------------------------------------------------------------------
# FASE 11.M — sub-call exposure
# ---------------------------------------------------------------------------
#
# When ``execute_planner_directive`` runs a tool internally (e.g. fires a
# ``run_command gobuster ...`` after reading the planner's directive),
# the reflective runner's ``tool_history`` doesn't see the underlying
# command — only the wrapper invocation. That breaks rule abstain checks
# that key off the inner args (e.g. ``_was_invoked(prior_args, "common.txt")``).
#
# Fix: a small per-task append/drain log so the executor can record the
# args it ran and the runner can merge them into ``tool_history`` at
# the next reflection boundary.


def test_subcall_log_empty_by_default() -> None:
    """No record_planner_subcall calls → drain returns []."""
    from kryon.intelligence.planner_runtime import drain_planner_subcalls

    drain_planner_subcalls()  # clear any leftover from sibling tests
    assert drain_planner_subcalls() == []


def test_record_and_drain_returns_args_in_order() -> None:
    """Multiple recorded sub-calls drain in insertion order."""
    from kryon.intelligence.planner_runtime import (
        drain_planner_subcalls,
        record_planner_subcall,
    )

    drain_planner_subcalls()  # clear
    record_planner_subcall("gobuster dir -u http://t/a -w common.txt")
    record_planner_subcall("gobuster dir -u http://t/b -w common.txt")
    drained = drain_planner_subcalls()
    assert len(drained) == 2
    assert "/a" in drained[0]
    assert "/b" in drained[1]


def test_peek_returns_subcalls_without_clearing() -> None:
    """peek lets a within-chunk directive see the sub-calls already made this chunk (so the planner
    advances instead of re-emitting the same rec), while drain (chunk boundary) still owns clearing."""
    from kryon.intelligence.planner_runtime import (
        drain_planner_subcalls,
        peek_planner_subcalls,
        record_planner_subcall,
    )

    drain_planner_subcalls()  # clear leftovers
    assert peek_planner_subcalls() == []
    record_planner_subcall(": wp_webshell; theme-editor.php …")
    # peek sees it AND does not consume it — two peeks return the same thing
    assert peek_planner_subcalls() == [": wp_webshell; theme-editor.php …"]
    assert peek_planner_subcalls() == [": wp_webshell; theme-editor.php …"]
    # the runner's drain still gets it afterwards
    assert drain_planner_subcalls() == [": wp_webshell; theme-editor.php …"]
    assert peek_planner_subcalls() == []


def test_drain_clears_the_buffer() -> None:
    """Second consecutive drain must be empty — the runner reads-
    and-clears each reflection boundary."""
    from kryon.intelligence.planner_runtime import (
        drain_planner_subcalls,
        record_planner_subcall,
    )

    drain_planner_subcalls()
    record_planner_subcall("some-cmd --flag")
    assert drain_planner_subcalls() == ["some-cmd --flag"]
    assert drain_planner_subcalls() == []


def test_record_after_drain_starts_fresh_buffer() -> None:
    """Drain shouldn't leave the buffer in a state that rejects
    further appends — record after drain must accumulate normally."""
    from kryon.intelligence.planner_runtime import (
        drain_planner_subcalls,
        record_planner_subcall,
    )

    drain_planner_subcalls()
    record_planner_subcall("first")
    drain_planner_subcalls()  # clear
    record_planner_subcall("second")
    assert drain_planner_subcalls() == ["second"]


def test_record_handles_empty_args_string() -> None:
    """Defensive — empty/whitespace args should not crash but also
    shouldn't pollute the log (downstream `_was_invoked` substring
    checks would silently match the empty string against anything)."""
    from kryon.intelligence.planner_runtime import (
        drain_planner_subcalls,
        record_planner_subcall,
    )

    drain_planner_subcalls()
    record_planner_subcall("")
    record_planner_subcall("   ")
    assert drain_planner_subcalls() == []


# ---------------------------------------------------------------------------
# FASE 11.Q — high-confidence directive probe for SDK tool_choice forcing
# ---------------------------------------------------------------------------
#
# ``has_high_confidence_directive`` is the seam the SDK uses to decide
# whether to upgrade ``tool_choice`` to ``"required"`` for the next
# model call. The invariants matter because the SDK calls it on every
# turn — a single misbehavior (raising, mutating state, returning True
# when there's no run) would either break the chunked loop or force
# tool calls when there's nothing to plan against.


def test_has_high_conf_directive_returns_false_when_no_run_in_flight(
    monkeypatch,
) -> None:
    """No reflective run → no state → no directive. Hard-rule: never
    force tool_choice when the SDK is being driven by code that didn't
    register a run (e.g. unit tests, dashboard call paths)."""
    from kryon.intelligence.planner_runtime import has_high_confidence_directive

    clear_current_state()
    assert has_high_confidence_directive() is False


def test_has_high_conf_directive_returns_false_when_planner_emits_none(
    monkeypatch,
) -> None:
    """State exists but no rule fires (empty facts) → planner returns
    None → False."""
    from kryon.intelligence.planner_runtime import has_high_confidence_directive

    set_current_state(EMPTY, ())
    try:
        assert has_high_confidence_directive() is False
    finally:
        clear_current_state()


def test_has_high_conf_directive_true_when_rec_above_threshold(
    monkeypatch,
) -> None:
    """When ``plan_next_action`` returns a rec with confidence above
    the threshold, the probe says True."""
    from kryon.intelligence import planner_runtime as pr
    from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

    fake_rec = NextActionRecommendation(
        tool="run_command",
        args="curl http://target",
        rationale="test",
        confidence=0.95,
    )

    def _fake_plan(*_args, **_kwargs):
        return fake_rec

    monkeypatch.setattr(
        "kryon.intelligence.exploit_chain_planner.plan_next_action",
        _fake_plan,
    )

    set_current_state(EMPTY, ("nmap -sV 10.0.0.1",))
    try:
        assert pr.has_high_confidence_directive() is True
    finally:
        clear_current_state()


def test_has_high_conf_directive_false_when_rec_below_threshold(
    monkeypatch,
) -> None:
    """A rec at 0.80 (default rule confidence) must NOT trigger the
    SDK forcing. Only ≥ 0.92 directives — the same cutoff
    ``render_for_prompt`` uses for the imperative OPERATOR DIRECTIVE
    phrasing."""
    from kryon.intelligence import planner_runtime as pr
    from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

    low_rec = NextActionRecommendation(
        tool="run_command",
        args="curl http://target",
        rationale="test",
        confidence=0.80,
    )

    monkeypatch.setattr(
        "kryon.intelligence.exploit_chain_planner.plan_next_action",
        lambda *_a, **_k: low_rec,
    )

    set_current_state(EMPTY, ("nmap -sV 10.0.0.1",))
    try:
        assert pr.has_high_confidence_directive() is False
    finally:
        clear_current_state()


def test_has_high_conf_directive_honors_env_threshold(monkeypatch) -> None:
    """Operator can lower the cutoff via env (active pentest profile
    where confidence-0.85 directives still beat the model's free
    sampling). Default stays 0.92 for banca-safe."""
    from kryon.intelligence import planner_runtime as pr
    from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

    mid_rec = NextActionRecommendation(
        tool="run_command",
        args="curl http://target",
        rationale="test",
        confidence=0.85,
    )

    monkeypatch.setattr(
        "kryon.intelligence.exploit_chain_planner.plan_next_action",
        lambda *_a, **_k: mid_rec,
    )

    set_current_state(EMPTY, ())
    monkeypatch.setenv("KRYON_PLANNER_DIRECTIVE_THRESHOLD", "0.80")
    try:
        assert pr.has_high_confidence_directive() is True
    finally:
        clear_current_state()


def test_has_high_conf_directive_explicit_threshold_overrides_env(
    monkeypatch,
) -> None:
    """The ``threshold`` argument always wins over env — useful for
    SDK call paths that want a stricter local cutoff."""
    from kryon.intelligence import planner_runtime as pr
    from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

    rec = NextActionRecommendation(
        tool="run_command",
        args="curl http://target",
        rationale="test",
        confidence=0.85,
    )

    monkeypatch.setattr(
        "kryon.intelligence.exploit_chain_planner.plan_next_action",
        lambda *_a, **_k: rec,
    )

    set_current_state(EMPTY, ())
    monkeypatch.setenv("KRYON_PLANNER_DIRECTIVE_THRESHOLD", "0.50")
    try:
        # Explicit threshold of 0.90 trumps env 0.50 — 0.85 < 0.90 → False
        assert pr.has_high_confidence_directive(threshold=0.90) is False
    finally:
        clear_current_state()


def test_has_high_conf_directive_returns_false_when_planner_raises(
    monkeypatch,
) -> None:
    """A planner-rule crash must NOT bubble into the SDK call path.
    Return False, log at debug — the SDK falls through to its normal
    tool_choice handling."""
    from kryon.intelligence import planner_runtime as pr

    def _boom(*_a, **_k):
        raise RuntimeError("simulated rule crash")

    monkeypatch.setattr(
        "kryon.intelligence.exploit_chain_planner.plan_next_action",
        _boom,
    )

    set_current_state(EMPTY, ())
    try:
        assert pr.has_high_confidence_directive() is False
    finally:
        clear_current_state()


def test_has_high_conf_directive_handles_invalid_env_threshold(
    monkeypatch,
) -> None:
    """Garbled env value (e.g. ``foo``) must fall back to the 0.92
    default, not crash. Operator misconfiguration shouldn't break the
    SDK loop."""
    from kryon.intelligence import planner_runtime as pr
    from kryon.intelligence.exploit_chain_planner import NextActionRecommendation

    rec_above = NextActionRecommendation(tool="run_command", args="x", rationale="t", confidence=0.95)
    monkeypatch.setattr(
        "kryon.intelligence.exploit_chain_planner.plan_next_action",
        lambda *_a, **_k: rec_above,
    )
    set_current_state(EMPTY, ())
    monkeypatch.setenv("KRYON_PLANNER_DIRECTIVE_THRESHOLD", "not-a-float")
    try:
        # 0.95 ≥ 0.92 default → True even though env is garbled
        assert pr.has_high_confidence_directive() is True
    finally:
        clear_current_state()


def test_planner_intent_set_and_get() -> None:
    """execute_planner_directive passed intent='' because the runtime never carried the objective, so
    keyword-gated rules (wpscan) only fired when markers landed in facts — which a web_fetch JSON envelope
    doesn't surface. set/get_planner_intent threads the user's objective so those rules fire on intent."""
    from kryon.intelligence.planner_runtime import get_planner_intent, set_planner_intent

    set_planner_intent("")
    assert get_planner_intent() == ""
    set_planner_intent("active pentest wordpress /blog vhost internal.thm")
    assert "wordpress" in get_planner_intent()
    # truncated, never crashes on None-ish
    set_planner_intent("x" * 5000)
    assert len(get_planner_intent()) == 2000


def test_wpscan_rule_fires_from_intent_when_facts_lack_wp_markers() -> None:
    """The THM Internal v9 failure: facts from a web_fetch JSON envelope had no wp-content/wp-includes
    paths, so with intent='' the planner skipped wpscan into jwt_forge/ssrf. With the objective threaded
    as intent, the wpscan rule fires."""
    from kryon.intelligence.exploit_chain_planner import plan_next_action
    from kryon.intelligence.fact_extractor import ExtractedFacts

    facts = ExtractedFacts(services=((80, "http"), (22, "ssh")), hosts=("10.0.0.9",), paths=("/login.php",))
    prior = [": service_scan; nmap 10.0.0.9"]
    assert plan_next_action(facts, prior, intent="") is None or "wpscan" not in (
        plan_next_action(facts, prior, intent="").args or ""
    )
    rec = plan_next_action(facts, prior, intent="active pentest WordPress en /blog")
    assert rec is not None and ("wpscan" in rec.args or "wp_brute" in rec.args)


def test_chunk_facts_accumulate_and_merge() -> None:
    """Capa 3 — a directive's own output facts must be visible to the NEXT directive of the same chunk
    (state.facts only refreshes at the chunk boundary). wpscan cracks a cred → it must reach wp_webshell
    the same chunk, not vanish until the next reflection."""
    from kryon.intelligence.fact_extractor import EMPTY, ExtractedFacts, extract_facts
    from kryon.intelligence.planner_runtime import get_chunk_facts, init_chunk_facts, record_chunk_facts

    init_chunk_facts()
    assert get_chunk_facts() is EMPTY
    record_chunk_facts(extract_facts("wpscan", "Valid Combinations Found: | Username: admin, Password: my2boys"))
    assert ("admin", "my2boys") in get_chunk_facts().creds
    record_chunk_facts(ExtractedFacts(hosts=("10.0.0.9",)))
    merged = get_chunk_facts()
    assert ("admin", "my2boys") in merged.creds and "10.0.0.9" in merged.hosts
    init_chunk_facts()  # chunk boundary resets
    assert get_chunk_facts() is EMPTY


def test_record_chunk_facts_ignores_empty() -> None:
    from kryon.intelligence.fact_extractor import EMPTY
    from kryon.intelligence.planner_runtime import get_chunk_facts, init_chunk_facts, record_chunk_facts

    init_chunk_facts()
    record_chunk_facts(EMPTY)
    assert get_chunk_facts() is EMPTY


def test_already_issued_guard_skips_repeated_directive() -> None:
    """Capa 2 — a directive whose : name; signature is already in prior must be skipped, so a rule that
    doesn't self-abstain on its own emitted form (jwt_forge) stops looping."""
    from kryon.intelligence.exploit_chain_planner import _already_issued, _directive_signature

    assert _directive_signature(": jwt_forge; echo x") == "jwt_forge"
    assert _directive_signature("nmap -sV") == ""
    assert _already_issued(": jwt_forge; echo a", [": jwt_forge; echo earlier"]) is True
    assert _already_issued(": wpscan; H=x", [": service_scan; nmap"]) is False
