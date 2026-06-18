"""micro_compact_history — trims OLD large tool outputs so a long engagement's
history doesn't snowball. Now wired into the reflective runner (investigate),
not just the REPL: a 44-min web pentest grew the history to ~20K tokens and made
Devstral re-process all of it per turn.
"""

from __future__ import annotations

from kryon.services.micro_compact import micro_compact_history


def _asst(cid: str) -> dict:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [{"id": cid, "type": "function", "function": {"name": "run_command", "arguments": "{}"}}],
    }


def _hist_with_big_outputs(n: int, size: int) -> list[dict]:
    hist: list[dict] = [{"role": "system", "content": "sys"}, {"role": "user", "content": "audit"}]
    for i in range(n):
        hist.append(_asst(f"c{i}"))
        hist.append({"role": "tool", "tool_call_id": f"c{i}", "content": "X" * size})
    hist.append({"role": "assistant", "content": "still thinking, next step..."})  # recent → preserved
    return hist


def test_trims_old_large_tool_outputs():
    hist = _hist_with_big_outputs(n=8, size=4000)
    before = sum(len(str(m.get("content") or "")) for m in hist)
    trimmed = micro_compact_history(hist)
    after = sum(len(str(m.get("content") or "")) for m in hist)
    assert trimmed == 8
    assert after < before // 2  # major reduction (was ~81%)


def test_preserves_small_outputs_and_recent_assistant():
    hist = _hist_with_big_outputs(n=2, size=50)  # outputs below budget
    trimmed = micro_compact_history(hist, budget=1000)
    assert trimmed == 0  # nothing big enough to trim
    assert hist[-1]["content"] == "still thinking, next step..."  # recent untouched


def test_truncated_output_keeps_head_and_tail():
    hist = [
        {"role": "user", "content": "go"},
        _asst("c0"),
        {"role": "tool", "tool_call_id": "c0", "content": "HEAD" + "M" * 5000 + "TAIL"},
        {"role": "assistant", "content": "done"},
    ]
    micro_compact_history(hist)
    out = hist[2]["content"]
    assert len(out) < 5000
    assert "HEAD" in out and "TAIL" in out  # head + tail preserved, middle dropped


def test_empty_history_is_noop():
    assert micro_compact_history([]) == 0


def _asst_named(cid: str, name: str) -> dict:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [{"id": cid, "type": "function", "function": {"name": name, "arguments": "{}"}}],
    }


def test_compacts_offensive_tools_now_in_allowlist():
    # Regression: sqlmap / web_fetch_smart (≤500KB) / ffuf / hydra / nxc produce
    # large output but were absent from LARGE_OUTPUT_TOOLS → never compacted →
    # context bloat. They must compact now.
    for name in ("sqlmap", "web_fetch_smart", "ffuf", "hydra", "nxc", "enum4linux"):
        hist = [
            {"role": "system", "content": "s"},
            {"role": "user", "content": "u"},
            _asst_named("c0", name),
            {"role": "tool", "tool_call_id": "c0", "content": "X" * 4000},
            {"role": "assistant", "content": "next step"},
        ]
        assert micro_compact_history(hist) == 1, name
