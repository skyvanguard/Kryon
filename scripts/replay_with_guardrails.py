"""Replay call 26 of the obsidian session, but first pass the history
through the Fix B filter (drop prose-plan contamination) to simulate what
Kryon would send now. Compare with the unfiltered baseline.
"""
import json
import os
import sys
import urllib.request

from kryon.sdk.agents.models.openai_chatcompletions import (
    _is_prose_plan_contamination,
)

path = sys.argv[1]
call_idx = int(sys.argv[2])

with open(path, encoding="utf-8") as f:
    calls = [json.loads(line) for line in f if "event" not in json.loads(line)]

c = calls[call_idx]

raw_tools = c.get("tools") or []
wrapped = []
for rt in raw_tools:
    title = rt.get("title", "unknown_tool")
    name = title.replace("_args", "") if title.endswith("_args") else title
    wrapped.append({
        "type": "function",
        "function": {
            "name": name,
            "description": f"Tool inferred from {title}",
            "parameters": rt,
        },
    })

# Apply Fix B: drop prose-plan assistant messages (no tool_calls) from history
original_msgs = c["messages"]
filtered_msgs = []
dropped = 0
for m in original_msgs:
    if (
        m.get("role") == "assistant"
        and not m.get("tool_calls")
        and _is_prose_plan_contamination(m.get("content", ""))
    ):
        dropped += 1
        continue
    filtered_msgs.append(m)

print(f"messages: original={len(original_msgs)} filtered={len(filtered_msgs)} dropped={dropped}")

def fire(messages, tag):
    payload = {
        "model": c["model"],
        "messages": messages,
        "tools": wrapped,
        "tool_choice": "required",
        "stream": False,
    }
    req = urllib.request.Request(
        "http://kryon-ollama:11434/v1/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=180) as r:
        resp = json.loads(r.read().decode())
    msg = resp["choices"][0]["message"]
    print(f"[{tag}] finish={resp['choices'][0].get('finish_reason')} tool_calls={bool(msg.get('tool_calls'))}")
    if msg.get("tool_calls"):
        for tc in msg["tool_calls"]:
            fn = tc.get("function", {})
            print(f"  -> {fn.get('name')}({str(fn.get('arguments'))[:120]})")
    else:
        print(f"  content: {str(msg.get('content') or '')[:300]}")

fire(original_msgs, "baseline (unfiltered)")
fire(filtered_msgs, "fix B applied (filtered)")
