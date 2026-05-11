"""Minimal tool-call test against Ollama, variable context size."""
import json
import sys
import urllib.request

scenario = sys.argv[1] if len(sys.argv) > 1 else "simple"

base_messages = [
    {"role": "system", "content": "You are an assistant that calls tools. Always use tools when asked to execute something."},
    {"role": "user", "content": "ejecuta el analisis del repositorio obsidian-mind ya clonado — revisa el codigo busca vulnerabilidades"},
]

if scenario == "padded":
    # Pad context with filler messages to simulate a long conversation
    pad = [
        {"role": "user", "content": "hola"},
        {"role": "assistant", "content": "Hola, soy Kryon."},
        {"role": "user", "content": "quiero analizar un repositorio"},
        {"role": "assistant", "content": "Claro, dame el URL."},
    ] * 20  # 80 messages
    messages = [base_messages[0]] + pad + [base_messages[1]]
elif scenario == "large_system":
    large_system = "# KRYON — Autonomous Cybersecurity Intelligence Platform\n" + ("blah blah guideline line " * 500)
    messages = [
        {"role": "system", "content": large_system},
        base_messages[1],
    ]
else:
    messages = base_messages

payload = {
    "model": "kryon-14b",
    "messages": messages,
    "tools": [
        {"type": "function", "function": {
            "name": "run_command",
            "description": "Execute a shell command",
            "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
        }},
        {"type": "function", "function": {
            "name": "duckduckgo_search",
            "description": "Web search",
            "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
        }},
    ],
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
print(f"[scenario={scenario}]")
print(f"finish_reason: {resp['choices'][0].get('finish_reason')}")
print(f"has tool_calls: {bool(msg.get('tool_calls'))}")
if msg.get("tool_calls"):
    for tc in msg["tool_calls"]:
        print(f"  {tc.get('function',{}).get('name')}({tc.get('function',{}).get('arguments')})")
print(f"content: {str(msg.get('content') or '')[:300]}")
print(f"tokens: prompt={resp.get('usage',{}).get('prompt_tokens')} completion={resp.get('usage',{}).get('completion_tokens')}")
