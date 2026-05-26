"""FASE 7 — Python REPL exploit chain rule tests.

These rules encode the manual pwn chain that resolved THM Pyrat
(documented in the commit message). Each rule's precondition + ordering
is pinned so the chain advances stage-by-stage across reflection turns.

The chain:

1. nmap surfaces Python errors (NameError / SyntaxError / null-byte) →
   ``_rule_confirm_python_repl_with_print`` fires, recommending
   ``echo 'print("kryon-probe")' | nc target port``.
2. The probe confirms exec() — facts.hints picks up the kryon-probe
   token from the response — AND a follow-up tool call hits
   ``Permission denied`` on the script. Then
   ``_rule_introspect_python_main_module`` fires, recommending the
   ``sys.modules['__main__']`` dump.
3. After introspection, ``_rule_extract_bytecode_constants`` fires,
   recommending the ``co_consts`` walk over all callables.
4. Independently, ``_rule_git_dubious_ownership_bypass`` fires when
   git's ownership guard appears in facts.hints.
5. Independently, ``_rule_explore_world_readable_dirs`` fires when
   we land in www-data and don't yet have creds.

Tests pin each rule's precondition + abstention + non-interference
(rules don't double-fire on subsequent reflections).
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import plan_next_action
from kryon.intelligence.fact_extractor import ExtractedFacts


# ---------------------------------------------------------------------------
# _rule_confirm_python_repl_with_print
# ---------------------------------------------------------------------------


def test_python_repl_confirm_fires_on_name_error_hint() -> None:
    """nmap surfaced ``name 'GET' is not defined`` → confirm REPL."""
    facts = ExtractedFacts(
        hints=("is not defined",),
        services=((8000, "http-alt"),),
    )
    rec = plan_next_action(facts, [], "")
    assert rec is not None
    assert "python_repl_confirm" in rec.args
    assert "kryon-probe" in rec.args
    assert "nc " in rec.args
    assert rec.confidence >= 0.9


def test_python_repl_confirm_fires_on_compile_null_bytes_hint() -> None:
    """The ``source code string cannot contain null bytes`` signal is
    CPython's compile() error — also indicative of a REPL."""
    facts = ExtractedFacts(
        hints=("source code string cannot contain null bytes",),
        services=((9000, "http-alt"),),
    )
    rec = plan_next_action(facts, [], "")
    assert rec is not None
    assert "python_repl_confirm" in rec.args


def test_python_repl_confirm_skips_port_22() -> None:
    """A NameError on port 22 isn't a Python REPL — that's SSH banner
    drift. Rule must not fire."""
    facts = ExtractedFacts(
        hints=("is not defined",),
        services=((22, "ssh"),),
    )
    rec = plan_next_action(facts, [], "")
    # No non-22 port → rule abstains. May still fire other rules but
    # not the python_repl_confirm one.
    assert rec is None or "python_repl_confirm" not in rec.args


def test_python_repl_confirm_skips_when_already_invoked() -> None:
    """Once the probe has been sent, don't re-recommend it."""
    facts = ExtractedFacts(
        hints=("is not defined",),
        services=((8000, "http-alt"),),
    )
    prior = ["echo 'print(\"kryon-probe\")' | nc -q 1 -w 5 target 8000"]
    rec = plan_next_action(facts, prior, "")
    assert rec is None or "python_repl_confirm" not in rec.args


# ---------------------------------------------------------------------------
# _rule_introspect_python_main_module
# ---------------------------------------------------------------------------


def test_introspect_fires_after_repl_confirmed_and_perm_denied() -> None:
    """Probe ran (kryon-probe in history) AND a follow-up hit
    Permission denied on the script — introspection is the next step."""
    facts = ExtractedFacts(
        hints=(
            "is not defined",
            "[errno 13] permission denied",
        ),
        services=((8000, "http-alt"),),
    )
    prior = [
        "echo 'print(\"kryon-probe\")' | nc -q 1 -w 5 target 8000",
        "open('/root/pyrat.py').read()",
    ]
    rec = plan_next_action(facts, prior, "")
    assert rec is not None
    assert "python_repl_introspect" in rec.args
    assert "sys.modules" in rec.args
    assert "__main__" in rec.args


def test_introspect_skips_without_perm_denied_signal() -> None:
    """If we can read the script file directly, no need for the
    in-memory module dump."""
    facts = ExtractedFacts(
        hints=("is not defined",),
        services=((8000, "http-alt"),),
    )
    prior = ["echo 'print(\"kryon-probe\")' | nc -q 1 -w 5 target 8000"]
    rec = plan_next_action(facts, prior, "")
    # Permission-denied signal missing → introspection abstains.
    assert rec is None or "python_repl_introspect" not in rec.args


def test_introspect_skips_when_already_invoked() -> None:
    facts = ExtractedFacts(
        hints=("is not defined", "permission denied"),
        services=((8000, "http-alt"),),
    )
    prior = [
        "echo 'print(\"kryon-probe\")' | nc -q 1 -w 5 target 8000",
        "echo 'import sys; m=sys.modules[\"__main__\"]; print(dir(m))' | nc target 8000",
    ]
    rec = plan_next_action(facts, prior, "")
    assert rec is None or "python_repl_introspect" not in rec.args


# ---------------------------------------------------------------------------
# _rule_extract_bytecode_constants
# ---------------------------------------------------------------------------


def test_bytecode_consts_fires_after_introspection() -> None:
    """Introspection ran → extract co_consts from all callables."""
    facts = ExtractedFacts(
        hints=("is not defined",),
        services=((8000, "http-alt"),),
    )
    prior = [
        "echo 'print(\"kryon-probe\")' | nc -q 1 -w 5 target 8000",
        "echo 'import sys; m=sys.modules[\"__main__\"]; print(dir(m))' | nc target 8000",
    ]
    rec = plan_next_action(facts, prior, "")
    assert rec is not None
    assert "python_repl_bytecode_consts" in rec.args
    assert "co_consts" in rec.args


def test_bytecode_consts_skips_when_introspection_not_yet_run() -> None:
    facts = ExtractedFacts(
        hints=("is not defined", "permission denied"),
        services=((8000, "http-alt"),),
    )
    rec = plan_next_action(facts, [], "")
    # introspection step hasn't fired in history → consts skips
    assert rec is None or "python_repl_bytecode_consts" not in rec.args


def test_bytecode_consts_skips_when_already_invoked() -> None:
    facts = ExtractedFacts(
        hints=("is not defined", "permission denied"),
        services=((8000, "http-alt"),),
    )
    prior = [
        "echo 'print(\"kryon-probe\")' | nc target 8000",
        "echo 'import sys; m=sys.modules[\"__main__\"]; print(dir(m))' | nc target 8000",
        "echo 'import sys; m=sys.modules[\"__main__\"]; [print(getattr(m,n).__code__.co_consts) for n in dir(m)]' | nc target 8000",
    ]
    rec = plan_next_action(facts, prior, "")
    assert rec is None or "python_repl_bytecode_consts" not in rec.args


# ---------------------------------------------------------------------------
# _rule_git_dubious_ownership_bypass
# ---------------------------------------------------------------------------


def test_git_dubious_bypass_fires_on_signal() -> None:
    facts = ExtractedFacts(hints=("detected dubious ownership",))
    rec = plan_next_action(facts, [], "")
    assert rec is not None
    assert "git_dubious_bypass" in rec.args
    assert "cp -r" in rec.args
    assert "git log" in rec.args


def test_git_dubious_bypass_skips_without_signal() -> None:
    facts = ExtractedFacts(hints=())
    rec = plan_next_action(facts, [], "")
    # No dubious-ownership hint → rule abstains.
    assert rec is None or "git_dubious_bypass" not in rec.args


def test_git_dubious_bypass_skips_when_already_copied() -> None:
    facts = ExtractedFacts(hints=("detected dubious ownership",))
    prior = ["cp -r /opt/dev /tmp/dev_copy && cd /tmp/dev_copy && git log --all -p"]
    rec = plan_next_action(facts, prior, "")
    assert rec is None or "git_dubious_bypass" not in rec.args


# ---------------------------------------------------------------------------
# _rule_explore_world_readable_dirs
# ---------------------------------------------------------------------------


def test_explore_lateral_fires_on_www_data_uid() -> None:
    """uid=33 in the hints is the canonical www-data tell."""
    facts = ExtractedFacts(hints=("uid=33(www-data) gid=33(www-data)",))
    rec = plan_next_action(facts, [], "")
    assert rec is not None
    assert "explore_lateral_dirs" in rec.args
    assert "/opt" in rec.args
    assert "/var/backups" in rec.args


def test_explore_lateral_skips_when_creds_present() -> None:
    """Once we have a cred, we don't need to crawl for one."""
    facts = ExtractedFacts(
        hints=("uid=33(www-data)",),
        creds=(("alice", "Password123"),),
    )
    rec = plan_next_action(facts, [], "")
    assert rec is None or "explore_lateral_dirs" not in rec.args


def test_explore_lateral_skips_when_already_listed() -> None:
    facts = ExtractedFacts(hints=("uid=33(www-data)",))
    prior = ["explore_lateral_dirs marker", "ls -la /opt /tmp"]
    rec = plan_next_action(facts, prior, "")
    assert rec is None or "explore_lateral_dirs" not in rec.args


def test_explore_lateral_skips_when_not_low_priv() -> None:
    """uid=0 / regular user → rule abstains."""
    facts = ExtractedFacts(hints=("uid=1000(alice) gid=1000(alice)",))
    rec = plan_next_action(facts, [], "")
    assert rec is None or "explore_lateral_dirs" not in rec.args


# ---------------------------------------------------------------------------
# Chain ordering — bytecode consts wins over introspect wins over confirm
# ---------------------------------------------------------------------------


def test_f7_confirm_wins_over_f3_netcat_when_python_signal_present() -> None:
    """FASE 8.A precedence: when both ``"basic connection"`` AND a
    Python REPL signal (``"invalid syntax"`` / NameError) are in
    hints, the F7 ``_rule_confirm_python_repl_with_print`` MUST fire
    instead of the F3 ``_rule_netcat_raw_on_basic_connection_hint``.

    This was the blocker in Pyrat run #15c: the F3 rule burned the
    recommendation slot first, leaving the F7 incremental chain
    unreachable across the rest of the run.
    """
    facts = ExtractedFacts(
        hints=("try a more basic connection", "invalid syntax"),
        services=((8000, "http-alt"),),
    )
    rec = plan_next_action(facts, [], "")
    assert rec is not None
    # F7 emits the ``python_repl_confirm`` marker comment + the
    # ``kryon-probe`` token. F3 would emit a bare ``echo 'help' | nc``.
    assert "python_repl_confirm" in rec.args
    assert "kryon-probe" in rec.args
    # And NOT the F3 payload.
    assert "echo -e 'help" not in rec.args


def test_f3_netcat_still_fires_without_python_signal() -> None:
    """Negative control: when ONLY the ``basic connection`` hint is
    present (no Python REPL signal), F3 should still fire. We don't
    want the abstention to over-trigger."""
    facts = ExtractedFacts(
        hints=("try a more basic connection",),
        services=((8000, "http-alt"),),
    )
    rec = plan_next_action(facts, [], "")
    assert rec is not None
    # FASE 11.G — F3 now emits the same ``print("kryon-probe")`` probe
    # directly, jumping straight to a REPL confirm instead of routing
    # through a ``help`` send that produces no socket output. The two
    # rules differ in their preconditions (hint phrasing vs Python
    # syntax error), not in the probe command.
    assert 'print("kryon-probe")' in rec.args
    assert "nc -w 5" in rec.args
    # NOT the F7 chain marker comment.
    assert "python_repl_confirm" not in rec.args


def test_chain_advances_stage_by_stage() -> None:
    """Walk the chain forward across simulated reflection turns and
    confirm each new bit of prior_args / facts advances the planner
    to the next stage."""
    # Stage 1: only the NameError hint + non-22 port → confirm step
    f1 = ExtractedFacts(
        hints=("is not defined",),
        services=((8000, "http-alt"),),
    )
    r1 = plan_next_action(f1, [], "")
    assert r1 is not None and "python_repl_confirm" in r1.args

    # Stage 2: probe sent + permission denied → introspect step
    f2 = ExtractedFacts(
        hints=("is not defined", "permission denied"),
        services=((8000, "http-alt"),),
    )
    p2 = ["echo 'print(\"kryon-probe\")' | nc -q 1 -w 5 target 8000"]
    r2 = plan_next_action(f2, p2, "")
    assert r2 is not None and "python_repl_introspect" in r2.args

    # Stage 3: introspection ran → bytecode consts step
    p3 = p2 + ["echo 'import sys; m=sys.modules[\"__main__\"]; print(dir(m))' | nc target 8000"]
    r3 = plan_next_action(f2, p3, "")
    assert r3 is not None and "python_repl_bytecode_consts" in r3.args
