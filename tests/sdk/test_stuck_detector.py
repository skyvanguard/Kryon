"""F85.E — StuckDetector unit tests.

Verifies the triple-hash sliding-window pattern recommended by prior
art (Manus / agent-patterns / AutoGPT post-mortem):

  - Identical (tool, args, result) repeated → intervention then abort
  - Identical tool but DIFFERENT args → polling, never blocks
  - Identical tool+args but DIFFERENT results → still progressing
  - Window slides: old entries fall off after N
  - Args canonicalised so {"a":1,"b":2} == {"b":2,"a":1}
"""

from __future__ import annotations

import pytest

from kryon.sdk.agents._stuck_detector import StuckAction, StuckDetector


def test_first_call_always_continues():
    det = StuckDetector()
    action = det.record("nmap", {"target": "x"}, "open: 22")
    assert action.kind == "continue"


def test_two_identical_triples_emit_intervention():
    det = StuckDetector(window_size=6, intervene_at=2, abort_at=4)
    det.record("get_users", "{}", "alice,bob")
    action = det.record("get_users", "{}", "alice,bob")
    assert action.kind == "intervene"
    assert action.tool_name == "get_users"
    assert action.repeat_count == 2
    # First (non-final) nudge tells the model it's looping + how to pivot.
    assert "not making progress" in action.message.lower()
    assert "last warning" not in action.message.lower()


def test_three_identical_triples_emit_abort():
    det = StuckDetector(window_size=5, intervene_at=2, abort_at=3)
    det.record("get_users", "{}", "alice,bob")
    det.record("get_users", "{}", "alice,bob")  # intervene
    action = det.record("get_users", "{}", "alice,bob")
    assert action.kind == "abort"
    assert action.repeat_count == 3


def test_generic_404s_across_paths_do_not_abort_result_band():
    # Enumeration: many different paths all returning 404 is recon, not a loop.
    # The args-independent RESULT band must NOT abort on these.
    det = StuckDetector(window_size=8, result_intervene_at=2, result_abort_at=3)
    body = "HTTP 404: Not Found — the requested path was not found on this server"
    actions = [det.record("web_fetch_smart", {"url": f"/p{i}"}, body) for i in range(6)]
    assert all(a.kind == "continue" for a in actions), [a.kind for a in actions]


def test_identical_real_output_across_args_still_aborts_result_band():
    # A genuine "different question, identical NON-error answer" loop must still trip.
    det = StuckDetector(window_size=8, result_intervene_at=2, result_abort_at=3)
    body = "internal admin dashboard v2 with the full user list rendered"
    kinds = [det.record("read_file", {"path": f"/f{i}"}, body).kind for i in range(4)]
    assert "abort" in kinds


def test_escalating_interventions_then_abort():
    """Fix-pivot: each distinct repeat-count in the warning band
    [intervene_at, abort_at) fires one escalating nudge. The count just
    before abort is the FINAL warning. This gives a looping agent two
    actionable chances to pivot before the run is stopped."""
    det = StuckDetector(window_size=6, intervene_at=2, abort_at=4)
    det.record("x", "{}", "y")  # count 1 → continue
    a2 = det.record("x", "{}", "y")  # count 2 → intervene (non-final)
    a3 = det.record("x", "{}", "y")  # count 3 → intervene (final warning)
    a4 = det.record("x", "{}", "y")  # count 4 → abort
    assert a2.kind == "intervene"
    assert "last warning" not in a2.message.lower()
    assert a3.kind == "intervene"
    assert "last warning" in a3.message.lower()
    assert a4.kind == "abort"
    assert a4.repeat_count == 4


def test_default_thresholds_are_lenient_pivot_friendly():
    """Defaults give two nudges (count 2, 3) then abort at 4 — not the
    old single-nudge-then-die-at-3."""
    det = StuckDetector()
    assert (det.window_size, det.intervene_at, det.abort_at) == (6, 2, 4)


def test_different_args_dont_count_as_repeat():
    """Polling with varying args is legitimate behaviour, not a loop."""
    det = StuckDetector()
    for tgt in ["host-a", "host-b", "host-c", "host-d", "host-e"]:
        action = det.record("ping", {"target": tgt}, "alive")
        assert action.kind == "continue", f"args={tgt} got {action.kind}"


def test_short_variable_polling_is_allowed():
    """A short burst of the same action with drifting results (e.g. a
    couple of paginated reads) is legitimate — stays under the lenient
    action band, no nudge."""
    det = StuckDetector()
    for i in range(3):
        action = det.record("read_page", '{"page": 1}', f"chunk-{i}")
        assert action.kind == "continue", f"call {i} got {action.kind}"


def test_same_action_variable_result_intervenes_then_aborts():
    """The duckduckgo bug: same tool+args repeated, but the result drifts
    each call (line-count changes), so the result-aware triple never
    matches. The action-only path must still nudge (count 4, 5) and then
    abort (count 6). Before this fix the loop ran unbounded."""
    det = StuckDetector()  # action_intervene_at=4, action_abort_at=6
    actions = [det.record("duckduckgo_search", '{"query": "cashbox web app"}', f"243-{i} lines") for i in range(6)]
    # Calls 1-3 (index 0-2): still in the lenient zone.
    assert all(a.kind == "continue" for a in actions[:3])
    # Call 4 (index 3): first action nudge.
    assert actions[3].kind == "intervene"
    assert "same action" in actions[3].message.lower()
    assert "last warning" not in actions[3].message.lower()
    # Call 5 (index 4): final warning.
    assert actions[4].kind == "intervene"
    assert "last warning" in actions[4].message.lower()
    # Call 6 (index 5): abort — the loop is stopped even though no result repeated.
    assert actions[5].kind == "abort"
    assert actions[5].repeat_count == 6


def test_action_thresholds_default_lenient():
    """Action band is more lenient than the triple band (4/6 vs 2/4)."""
    det = StuckDetector()
    assert (det.action_intervene_at, det.action_abort_at) == (4, 6)


def test_identical_triple_still_aborts_before_action_path():
    """When the result IS identical too, the stronger triple path owns it and
    aborts at 4 (not 6) — the action path doesn't weaken existing behaviour."""
    det = StuckDetector()
    kinds = [det.record("get_users", "{}", "alice,bob").kind for _ in range(4)]
    assert kinds[-1] == "abort"


def test_window_slides_so_old_loops_age_out():
    """If the same triple appears 2 times then 3 OTHER calls happen,
    a single subsequent re-occurrence is not "the third strike"
    because the first 2 fell out of the window."""
    det = StuckDetector(window_size=3, intervene_at=2, abort_at=3)
    det.record("a", "{}", "x")
    det.record("a", "{}", "x")  # intervene
    det.record("b", "{}", "y")
    det.record("c", "{}", "z")
    det.record("d", "{}", "w")
    # First two ('a', ...) are now out of the 3-slot window.
    action = det.record("a", "{}", "x")
    assert action.kind == "continue"


def test_arg_order_does_not_matter():
    """{'a':1,'b':2} and {'b':2,'a':1} must hash to the same args key."""
    det = StuckDetector()
    det.record("t", {"a": 1, "b": 2}, "r")
    action = det.record("t", {"b": 2, "a": 1}, "r")
    assert action.kind == "intervene", "args canonicalised to same hash"


def test_string_args_and_dict_args_with_same_payload_collide():
    """SDK passes args as JSON string; tests sometimes use dicts.
    Both should hash to the same key when the content is equivalent."""
    det = StuckDetector()
    det.record("t", '{"k": 1}', "r")
    action = det.record("t", {"k": 1}, "r")
    assert action.kind == "intervene"


def test_abort_at_must_exceed_intervene_at():
    with pytest.raises(ValueError, match="abort_at"):
        StuckDetector(intervene_at=3, abort_at=3)


def test_intervene_at_must_be_at_least_two():
    """intervene_at=1 makes no sense — the very first call has no
    repeat yet."""
    with pytest.raises(ValueError, match="intervene_at"):
        StuckDetector(intervene_at=1, abort_at=2)


def test_reset_clears_state():
    det = StuckDetector(intervene_at=2, abort_at=3)
    det.record("a", "{}", "x")
    det.record("a", "{}", "x")
    det.reset()
    # After reset, the next 'a' is fresh; needs 2 more to trigger intervene
    action = det.record("a", "{}", "x")
    assert action.kind == "continue"


def test_unhashable_args_fall_back_to_repr():
    """Tool args can theoretically contain non-JSON types (set, etc).
    The detector should not crash — fall back to repr-based hashing."""
    det = StuckDetector()
    weird_args = {"set": {1, 2, 3}}  # sets are not JSON-serializable
    # Should not raise
    a1 = det.record("t", weird_args, "r")
    a2 = det.record("t", weird_args, "r")
    assert a1.kind == "continue"
    assert a2.kind == "intervene"


def test_tool_call_args_reads_the_tool_call_not_the_output():
    """Regression — the detector got args from `fr.run_item.raw_item`, which is the function_call_OUTPUT
    item (call_id/output/type) with NO arguments, so every same-tool call hashed to (tool, "") and the
    run false-aborted at turn 0 (THM Internal: web_fetch_smart on /blog vs /wp-login vs /xmlrpc). Now it
    reads `fr.tool_call` (the ResponseFunctionToolCall, which carries .arguments)."""
    from types import SimpleNamespace

    from kryon.sdk.agents._run_impl import _tool_call_args

    call = SimpleNamespace(name="web_fetch_smart", arguments='{"url":"http://x/blog"}')
    assert _tool_call_args(call) == '{"url":"http://x/blog"}'
    assert _tool_call_args({"arguments": '{"url":"http://x/wp"}'}) == '{"url":"http://x/wp"}'
    assert _tool_call_args(SimpleNamespace(name="x")) == ""  # no .arguments → empty, not crash
    assert _tool_call_args({}) == ""
    assert _tool_call_args(None) == ""  # interrupted/missing call → empty, not crash


def test_distinct_urls_do_not_false_abort():
    """The v4 failure: 6 web_fetch_smart calls across 3 DISTINCT urls (legitimate
    recon) must NOT abort — only a genuine same-(tool,args) loop should."""
    det = StuckDetector()
    urls = [
        '{"url":"http://t/blog"}',
        '{"url":"http://t/blog/wp-login.php"}',
        '{"url":"http://t/blog/xmlrpc.php"}',
    ] * 2
    actions = [det.record("web_fetch_smart", u, f"body-{i}") for i, u in enumerate(urls)]
    assert all(a.kind != "abort" for a in actions)

    # …but the same url 6× is a real loop and still aborts.
    det2 = StuckDetector()
    loop = [det2.record("web_fetch_smart", '{"url":"http://t/x"}', f"r{i}") for i in range(6)]
    assert any(a.kind == "abort" for a in loop)


# --- result-keyed band: same tool, DIFFERENT args, SAME result (the planner-loop bug) ---

# Leaked source the model kept re-deriving on THM Crypto Failures (>=24 chars → meaningful).
_SRC = "<?php function make_secure_cookie($t,$s){foreach(str_split($t,8) as $e) $c.=crypt($e,$s);} ?>"


def test_same_result_varying_args_intervenes():
    """The autonomous Crypto Failures loop: the model varied its planner directive each
    turn (different args) but the tool returned the SAME leaked source every time. Both
    args-keyed bands stay silent; the result band must catch it at 3."""
    det = StuckDetector()  # defaults: result_intervene_at=3, result_abort_at=5
    assert det.record("execute_planner_directive", '{"q":"analyze auth"}', _SRC).kind == "continue"
    assert det.record("execute_planner_directive", '{"q":"recheck cookie"}', _SRC).kind == "continue"
    a = det.record("execute_planner_directive", '{"q":"inspect salt"}', _SRC)
    assert a.kind == "intervene" and "SAME result" in a.message


def test_same_result_varying_args_aborts():
    det = StuckDetector()
    for i in range(4):  # counts 1..4 (intervene at 3 and 4)
        det.record("execute_planner_directive", f'{{"q":{i}}}', _SRC)
    a = det.record("execute_planner_directive", '{"q":99}', _SRC)  # 5th identical result
    assert a.kind == "abort"


def test_varying_args_and_results_no_false_positive():
    """Genuine progress — same tool, different args, DIFFERENT results — must NOT trip
    the result band (each result is unique → count stays 1)."""
    det = StuckDetector()
    actions = [
        det.record("execute_planner_directive", f'{{"q":{i}}}', f"distinct finding number {i} " * 2) for i in range(6)
    ]
    assert all(a.kind == "continue" for a in actions)


def test_trivial_repeated_result_guarded():
    """Short/empty outputs aren't a re-derivation loop — the <24-char guard skips them so a
    tool returning a tiny constant ('ok') across different args doesn't trip the band."""
    det = StuckDetector()
    actions = [det.record("ping_host", f'{{"h":{i}}}', "ok") for i in range(6)]
    assert all(a.kind == "continue" for a in actions)


# --- L4 volatile auth tokens: signed session cookies / CSRF / JWT ---

# The 9 distinct Flask-signed session cookies observed live across ONE THM-room
# POST /upload → GET /dashboard loop. Before the fix each response hashed uniquely
# (the cookie drifts every turn) so the detector never fired — the run reached
# 4855+ lines of the same two-call loop without a single intervention.
_THM_COOKIES = [
    "session=.eJwdjcEKgzAQRH9l2IsXUVqEF",
    "session=.eJwdjcEKgzAQRH9l2IsXUVqEFn_DYx",
    "session=.eJyNjcEKg0AMRH8l5OJFlJZtK_6GRxFJY",
    "session=.eJyNjcEKgzAQRH9l2YsXUVq0tf6Gxy",
    "session=.eJyNzU0OgkAMBeCrNN2wISCIf1yDpSFk6",
    "session=.eJyNzU0OgkAMBeCrNN2wIeAPROQaLA0hd",
]


def test_web_session_cookie_loop_aborts():
    """The THM 'Hollow Shell' loop: the model curls POST /upload every turn with a
    fresh signed session cookie in BOTH the args (-H "Cookie: session=…") and the
    result (Set-Cookie in the response). Once auth tokens are canonicalized, the two
    calls collapse to one signature and the ACTION/RESULT bands catch the loop."""
    det = StuckDetector()
    kinds = []
    for c in _THM_COOKIES:
        args = {"command": f'curl -s -i -X POST http://t:5000/upload -H "Cookie: {c}" -F f=@shell.zip'}
        result = f"HTTP/1.1 200 OK\nSet-Cookie: {c}; HttpOnly\n<html>dashboard: no shell yet</html>"
        kinds.append(det.record("run_command", args, result).kind)
    assert "abort" in kinds, kinds


def test_jwt_and_csrf_tokens_canonicalized():
    """Bearer JWT and CSRF form tokens are volatile auth material too — a poll that
    only differs in the token must collapse and eventually trip."""
    det = StuckDetector()
    tokens = [
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig{}".format(i) for i in range(6)
    ]
    kinds = [
        det.record("run_command", {"command": f"curl -H 'Authorization: Bearer {t}' http://t/api"}, f"200 OK {t}").kind
        for t in tokens
    ]
    assert "abort" in kinds, kinds


def test_token_normalization_keeps_distinct_endpoints_apart():
    """Canonicalizing the cookie must NOT erase the real difference between two
    endpoints — /upload and /dashboard with the same cookie class stay distinct, so
    a genuine two-step alternation isn't falsely collapsed into one signature."""
    det = StuckDetector()
    c = _THM_COOKIES[0]
    up = det.record("run_command", {"command": f'curl -X POST http://t/upload -H "Cookie: {c}"'}, "uploaded")
    dash = det.record("run_command", {"command": f'curl http://t/dashboard -H "Cookie: {c}"'}, "listing")
    # Different endpoints → first-seen for each → neither is a repeat.
    assert up.kind == "continue" and dash.kind == "continue"


# --- L1/L2: persistent detector default window catches 2-tool alternation ---


@pytest.mark.strict_stuck_detector
def test_build_stuck_detector_default_window_is_8():
    """Default window 8 (was 6) so an A,B,A,B alternation reaches abort_at=4."""
    from kryon.sdk.agents.run import _build_stuck_detector

    d = _build_stuck_detector()
    assert d.window_size == 8
    assert d.abort_at == 4


@pytest.mark.strict_stuck_detector
def test_two_tool_alternation_aborts_with_default_window():
    """A,B,A,B,A,B… must ABORT — the exact loop the old window=6 missed."""
    from kryon.sdk.agents.run import _build_stuck_detector

    d = _build_stuck_detector()
    kinds = []
    for i in range(16):
        tool = "nmap" if i % 2 == 0 else "whatweb"
        kinds.append(d.record(tool, {"target": "x"}, "same-result-" + tool).kind)
        if kinds[-1] == "abort":
            break
    assert "abort" in kinds, f"alternation never aborted: {kinds}"


def test_runner_run_accepts_stuck_detector_param():
    """Runner.run must accept a driver-provided detector (cross-chunk persistence)."""
    import inspect

    from kryon.sdk.agents.run import Runner

    assert "stuck_detector" in inspect.signature(Runner.run.__func__).parameters


def test_shared_stuck_detector_context_sets_and_resets():
    from kryon.sdk.agents.run import _SHARED_STUCK_DETECTOR, shared_stuck_detector

    assert _SHARED_STUCK_DETECTOR.get() is None
    with shared_stuck_detector() as d:
        assert _SHARED_STUCK_DETECTOR.get() is d
    assert _SHARED_STUCK_DETECTOR.get() is None


# --- Advance-style tools (execute_planner_directive) — exempt from the ACTION band ---
# Root cause of the Juice Shop e2e abort (turn 8, "6/6 identical ACTIONS — result varies"):
# execute_planner_directive is called with identical args by contract (each call advances
# the planner one step; the result changes). The ACTION band false-positived on it.


def test_advance_tool_exempt_from_action_band_when_result_varies():
    # identical args every call, DIFFERENT result each time (planner advancing) → never abort.
    det = StuckDetector(window_size=8, action_intervene_at=4, action_abort_at=6)
    for i in range(8):
        action = det.record(
            "execute_planner_directive", "{}", f"PLANNER EXECUTED step {i}: directive number {i} distinct output"
        )
        assert action.kind == "continue", f"aborted at call {i} (kind={action.kind})"


def test_advance_tool_still_aborts_on_identical_result_triple():
    # a genuinely stuck planner returns the SAME directive (same result) → TRIPLE band catches it.
    det = StuckDetector(window_size=6, intervene_at=2, abort_at=4)
    kinds = [
        det.record("execute_planner_directive", "{}", "SAME directive output repeated unchanged").kind
        for _ in range(4)
    ]
    assert "abort" in kinds


def test_normal_tool_still_aborts_on_action_band():
    # non-advance tool with identical args + drifting results still trips the ACTION band (no regression).
    det = StuckDetector(window_size=8, action_intervene_at=4, action_abort_at=6)
    kinds = [det.record("web_search", "{}", f"results: {i} distinct hits found on page number {i}").kind for i in range(6)]
    assert "abort" in kinds


def test_advance_tools_configurable():
    # the exemption set is injectable; a tool NOT in it still trips the ACTION band.
    det = StuckDetector(window_size=8, action_abort_at=6, advance_tools=frozenset())
    kinds = [det.record("execute_planner_directive", "{}", f"distinct result number {i} here").kind for i in range(6)]
    assert "abort" in kinds
