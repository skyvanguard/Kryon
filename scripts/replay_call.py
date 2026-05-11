"""Replay a specific llm_call from a JSONL session log against Ollama to see
what the model actually produces under the exact same conditions.
"""
import json
import os
import sys
import urllib.request

path = sys.argv[1]
call_idx = int(sys.argv[2])
force_required = len(sys.argv) > 3 and sys.argv[3] == "force"

calls = []
with open(path, encoding="utf-8") as f:
    for line in f:
        d = json.loads(line)
        if "event" not in d:
            calls.append(d)

c = calls[call_idx]

# Build OpenAI-style tool wrapper: the logged tools are just the raw
# params_json_schema — re-wrap to what Kryon actually sends.
raw_tools = c.get("tools") or []
wrapped = []
for rt in raw_tools:
    # Derive name from title field (e.g. "add_to_memory_semantic_args" -> "add_to_memory_semantic")
    title = rt.get("title", "unknown_tool")
    name = title.replace("_args", "") if title.endswith("_args") else title
    wrapped.append({
        "type": "function",
        "function": {
            "name": name,
            "description": f"Parameters inferred from {title}",
            "parameters": rt,
        },
    })

payload = {
    "model": c["model"],
    "messages": c["messages"],
    "tools": wrapped,
    "stream": False,
}
if force_required:
    payload["tool_choice"] = "required"

api = os.environ.get("OLLAMA_URL", "http://kryon-ollama:11434/v1/chat/completions")
data = json.dumps(payload).encode()
req = urllib.request.Request(api, data=data, headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=180) as r:
    resp = json.loads(r.read().decode())

msg = resp["choices"][0]["message"]
print("=== RESPONSE ===")
print("finish_reason:", resp["choices"][0].get("finish_reason"))
print("has tool_calls:", bool(msg.get("tool_calls")))
if msg.get("tool_calls"):
    for tc in msg["tool_calls"]:
        fn = tc.get("function", {})
        print(f"  tool: {fn.get('name')} args={fn.get('arguments')}")
print()
print("content (first 800 chars):")
print(str(msg.get("content") or "")[:800])
print()
print("reasoning (first 500 chars):")
print(str(msg.get("reasoning") or "")[:500])
print()
print("usage:", resp.get("usage"))
