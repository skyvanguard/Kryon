"""Replay call 26 but remove prior assistant 'prose plan' messages to test
whether history contamination is causing the model to ignore tool_choice."""
import json
import sys
import urllib.request

path = sys.argv[1]
call_idx = int(sys.argv[2])
strategy = sys.argv[3] if len(sys.argv) > 3 else "clean"

calls = []
with open(path, encoding="utf-8") as f:
    for line in f:
        d = json.loads(line)
        if "event" not in d:
            calls.append(d)

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

messages = list(c["messages"])

if strategy == "clean":
    # Strip all assistant text messages that don't carry tool_calls
    # Keep system + user + (assistant with tool_calls) + tool
    cleaned = []
    for m in messages:
        role = m.get("role")
        if role == "assistant" and not m.get("tool_calls") and m.get("content"):
            continue  # drop prose-only assistant messages
        cleaned.append(m)
    messages = cleaned
elif strategy == "last_user_only":
    # Keep only the system prompt + the final user message
    sys_msg = next((m for m in messages if m.get("role") == "system"), None)
    last_user = next((m for m in reversed(messages) if m.get("role") == "user"), None)
    messages = [m for m in [sys_msg, last_user] if m]
elif strategy == "append_steer":
    # Prepend a steering user message after the last turn
    messages = messages + [
        {"role": "user", "content": "Use the run_command tool NOW. Do not write a plan. Do not use markdown. Emit a tool_call."}
    ]

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
print(f"[strategy={strategy}] msgs={len(messages)} prompt_tokens={resp.get('usage',{}).get('prompt_tokens')}")
print(f"finish_reason: {resp['choices'][0].get('finish_reason')}")
print(f"has tool_calls: {bool(msg.get('tool_calls'))}")
if msg.get("tool_calls"):
    for tc in msg["tool_calls"]:
        fn = tc.get("function", {})
        print(f"  {fn.get('name')}({str(fn.get('arguments'))[:150]})")
print(f"content: {str(msg.get('content') or '')[:300]}")
