"""Diagnostic: inspect JSONL session log to analyze tool-call behavior."""
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "/workspace/logs/last"
calls = []
events = []
with open(path, encoding="utf-8") as f:
    for line in f:
        d = json.loads(line)
        if "event" not in d:
            calls.append(d)
        else:
            events.append(d)

print(f"Total llm_calls: {len(calls)}")
print(f"Total events: {len(events)}")
print()

# Per-call summary
print("=" * 100)
print(f"{'#':>3} {'tools':>5} {'msgs':>4} {'last_user':<60} {'last_asst_had_tc':>16}")
print("-" * 100)
for i, c in enumerate(calls):
    msgs = c.get("messages", [])
    tools_ct = len(c.get("tools") or [])
    last_user = ""
    last_asst_had_tc = None
    for m in msgs:
        if m.get("role") == "user":
            last_user = str(m.get("content", ""))[:58].replace("\n", " ")
        if m.get("role") == "assistant":
            last_asst_had_tc = bool(m.get("tool_calls"))
    print(f"{i:>3} {tools_ct:>5} {len(msgs):>4} {last_user!r:<60} {str(last_asst_had_tc):>16}")
print()

# Look for calls with user message mentioning obsidian / analiza / vuln
print("=" * 100)
print("USER MESSAGES IN THIS SESSION (deduped):")
print("-" * 100)
seen = set()
for c in calls:
    for m in c.get("messages", []):
        if m.get("role") == "user":
            txt = str(m.get("content", "")).strip()[:200]
            if txt and txt not in seen:
                seen.add(txt)
                print(f"  - {txt!r}")
print()

# Tool calls issued in transcript
print("=" * 100)
print("TOOL CALLS FOUND IN MESSAGE HISTORY (from later calls):")
print("-" * 100)
seen_tc = set()
for c in calls:
    for m in c.get("messages", []):
        if m.get("role") == "assistant" and m.get("tool_calls"):
            for tc in m.get("tool_calls") or []:
                key = json.dumps(tc, sort_keys=True)
                if key in seen_tc:
                    continue
                seen_tc.add(key)
                fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                name = fn.get("name", "?")
                args = str(fn.get("arguments", ""))[:120]
                print(f"  - {name}({args})")
print()

# Tool results
print("=" * 100)
print("TOOL OUTPUTS FOUND (deduped, truncated):")
print("-" * 100)
seen_to = set()
for c in calls:
    for m in c.get("messages", []):
        if m.get("role") == "tool":
            content = str(m.get("content", ""))[:300].replace("\n", " ")
            key = content[:120]
            if key in seen_to:
                continue
            seen_to.add(key)
            print(f"  - {content!r}")
