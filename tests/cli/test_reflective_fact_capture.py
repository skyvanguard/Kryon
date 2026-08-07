"""on_tool_end must keep enough raw tool output for fact synthesis.

Regression: it saved only str(result)[:500], and the fact extractor's ONLY raw
source is that capture — so the privesc line (`sudo -l` NOPASSWD), hashes, and
later nmap ports (all past char 500) never reached accumulated_facts and the model
"forgot" what it discovered. Now a 16KB `output_facts` slice feeds the extractor
while `output_preview` stays 500 for chain/display."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from kryon.cli.reflective_runner import ItemCaptureHooks, _chunk_text_from_capture


def _tool(name: str):
    return SimpleNamespace(name=name)


@pytest.mark.asyncio
async def test_privesc_line_past_500_chars_is_captured_for_facts():
    hooks = ItemCaptureHooks()
    # A realistic `sudo -l` where the exploitable line sits well past char 500.
    filler = "\n".join(f"    env_keep+={i}" for i in range(120))  # >500 chars of noise
    result = "Matching Defaults entries:\n" + filler + "\n(ALL) NOPASSWD: /usr/bin/find\n"
    assert len(result) > 500

    await hooks.on_tool_start(None, None, _tool("run_command"))
    await hooks.on_tool_end(None, None, _tool("run_command"), result)

    item = hooks.captured_items[0]
    # preview stays small (chain/display), facts slice keeps the exploitable line
    assert len(item["output_preview"]) == 500
    assert "NOPASSWD" not in item["output_preview"]
    assert "NOPASSWD: /usr/bin/find" in item["output_facts"]

    # the fact-synthesis text source must surface it
    chunk = _chunk_text_from_capture(hooks)
    assert "NOPASSWD: /usr/bin/find" in chunk


@pytest.mark.asyncio
async def test_facts_slice_is_capped_not_unbounded():
    hooks = ItemCaptureHooks()
    huge = "A" * 50000
    await hooks.on_tool_start(None, None, _tool("linpeas"))
    await hooks.on_tool_end(None, None, _tool("linpeas"), huge)
    assert len(hooks.captured_items[0]["output_facts"]) == 16000
