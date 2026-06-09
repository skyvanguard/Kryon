"""Fase 1 (v2) — convert public T-C-O walkthroughs into Kryon's tool-calling
chat format, mapping each shell command to the REAL Kryon tool when one exists.

v1 mapped every command to `run_command`. The cashbox A/B showed that's not how
Kryon's agent operates: it has specific tools (`nmap`, `web_fetch_smart`,
`validate_sqli`, `gobuster_dir`, …) and only falls back to `run_command` for
generic shell. A FT trained only on `run_command` goes out-of-distribution and
loops. v2 maps `nmap …` → the `nmap` tool, `curl http…` → `web_fetch_smart`,
`sqlmap` → `validate_sqli`, etc., with the tools' real names/schemas (verified
against src/kryon/tools/), and `run_command` only for everything else.

Source: Pentest-R1 (MIT) `data/steps/*.json`.
Output: `data/finetune/{train,val}.jsonl` + `data/finetune/tools.json`.

Usage:
    python scripts/finetune/convert_dataset.py \
        --steps data/finetune/pentest-r1/data/steps --out data/finetune
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
from pathlib import Path

SYSTEM_PROMPT = (
    "You are Kryon, an autonomous offensive-security agent operating a tight "
    "ReAct loop. You have specific tools — prefer the most specific one for the "
    "job (e.g. `nmap` to scan, `web_fetch_smart` to fetch a URL, `validate_sqli` "
    "for SQL injection, `gobuster_dir` to brute-force paths) and fall back to "
    "`run_command` only for generic shell.\n"
    "At each turn: read the previous observation, reason briefly, then EITHER "
    "call exactly one tool that advances the objective, OR — when the objective "
    "is met — STOP and report the result. Never repeat an identical call, never "
    "loop, and do not call a tool once the goal is achieved."
)

# Real Kryon tool specs (names + params verified against src/kryon/tools/).
# Only the ones Pentest-R1 commands actually map to; the rest → run_command.
KRYON_TOOLS = [
    ("run_command", "Run a single shell command on the Kali box.",
     {"command": ("string", "The exact shell command.")}),
    ("nmap", "Port/service/OS scan of a target with nmap.",
     {"target": ("string", "Host or IP to scan."), "args": ("string", "Extra nmap flags, e.g. '-A -p-'.")}),
    ("web_fetch_smart", "HTTP GET a URL and return HTML→markdown.",
     {"url": ("string", "The URL to fetch.")}),
    ("duckduckgo_search", "Free web/OSINT search.",
     {"query": ("string", "Search query.")}),
    ("gobuster_dir", "Directory/file brute-force over HTTP.",
     {"target": ("string", "Base URL."), "wordlist": ("string", "Wordlist path (optional).")}),
    ("ffuf_scan", "Fuzz a URL/parameter with ffuf.",
     {"url": ("string", "Target URL with FUZZ marker."), "wordlist": ("string", "Wordlist path (optional).")}),
    ("nikto_scan", "Web server vulnerability scan with nikto.",
     {"target": ("string", "Target host/URL.")}),
    ("nuclei_scan", "Template-based vuln scan with nuclei.",
     {"target": ("string", "Target URL."), "tags": ("string", "Template tags (optional).")}),
    ("whatweb_scan", "Web technology fingerprint.",
     {"target": ("string", "Target URL.")}),
    ("hydra_attack", "Credential brute-force with hydra.",
     {"target": ("string", "Target host."), "service": ("string", "Service, e.g. ssh/http-post-form."),
      "username": ("string", "Username or user list."), "password_list": ("string", "Password list path.")}),
    ("validate_sqli", "Confirm SQL injection (sqlmap wrapper).",
     {"target_url": ("string", "URL with the injectable parameter."), "parameter": ("string", "Parameter name.")}),
    ("validate_xss", "Confirm reflected/stored XSS.",
     {"target_url": ("string", "Target URL."), "payload": ("string", "XSS payload (optional).")}),
]


def _tool_spec(name, desc, params):
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": desc,
            "parameters": {
                "type": "object",
                "properties": {p: {"type": t, "description": d} for p, (t, d) in params.items()},
                "required": [next(iter(params))],
            },
        },
    }


TOOLS_JSON = [_tool_spec(n, d, p) for n, d, p in KRYON_TOOLS]

_URL_RE = re.compile(r"https?://[^\s'\"]+")


def _strip_prefixes(tokens: list[str]) -> list[str]:
    # Drop leading sudo / env assignments / timeout wrappers.
    while tokens and (tokens[0] in ("sudo", "timeout", "proxychains", "stdbuf") or "=" in tokens[0]):
        # timeout takes a duration arg; sudo may take flags — be conservative,
        # just drop the single wrapper token and (for timeout) its number.
        if tokens[0] == "timeout" and len(tokens) > 1 and re.match(r"^\d+", tokens[1]):
            tokens = tokens[2:]
        else:
            tokens = tokens[1:]
    return tokens


def _last_hostish(tokens: list[str]) -> str | None:
    """Heuristic target: last token that isn't a flag or a flag's value."""
    for tok in reversed(tokens):
        if tok.startswith("-"):
            continue
        if _URL_RE.match(tok) or re.match(r"^[\w.-]+\.[a-zA-Z]{2,}$", tok) or re.match(r"^\d+\.\d+\.\d+\.\d+", tok):
            return tok
        # bare hostname like '0day.thm' or 'target'
        if re.match(r"^[\w.-]+$", tok) and "/" not in tok:
            return tok
    return None


def map_command(cmd: str) -> tuple[str, dict]:
    """Map a Pentest-R1 shell command to (kryon_tool_name, args)."""
    cmd = cmd.strip()
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        tokens = cmd.split()
    tokens = _strip_prefixes(tokens)
    if not tokens:
        return "run_command", {"command": cmd}
    base = tokens[0].split("/")[-1].lower()
    rest = tokens[1:]
    url = (_URL_RE.search(cmd) or [None])
    url = url.group(0) if hasattr(url, "group") else None

    if base == "nmap":
        target = _last_hostish(rest)
        if target:
            args = " ".join(t for t in rest if t != target)
            return "nmap", {"target": target, "args": args}
    elif base in ("curl", "wget", "http", "httpie") and url:
        return "web_fetch_smart", {"url": url}
    elif base in ("gobuster", "dirsearch", "dirb", "feroxbuster", "dirbuster"):
        return "gobuster_dir", {"target": url or _last_hostish(rest) or cmd}
    elif base == "ffuf" and url:
        return "ffuf_scan", {"url": url}
    elif base == "nikto":
        return "nikto_scan", {"target": url or _last_hostish(rest) or cmd}
    elif base == "nuclei":
        return "nuclei_scan", {"target": url or _last_hostish(rest) or cmd}
    elif base == "whatweb":
        return "whatweb_scan", {"target": url or _last_hostish(rest) or cmd}
    elif base == "hydra":
        return "hydra_attack", {"target": _last_hostish(rest) or cmd, "service": ""}
    elif base == "sqlmap":
        return "validate_sqli", {"target_url": url or cmd, "parameter": ""}
    elif base in ("dalfox", "xsser"):
        return "validate_xss", {"target_url": url or cmd}
    # Generic shell — cat, ls, ssh, nc, python, msfconsole, searchsploit, etc.
    return "run_command", {"command": cmd}


_SUCCESS_MARKERS = ("flag", "captured", "completed", "root.txt", "shell", "uid=0", "compromis")


def _stop_message(last_result: str) -> dict:
    confirmed = any(m in last_result.lower() for m in _SUCCESS_MARKERS)
    body = (
        "Objective achieved — the goal was confirmed by the last observation. "
        "Stopping here; no further commands are needed."
        if confirmed
        else "I have gathered the relevant evidence above and the objective is met. "
        "Stopping here rather than issuing redundant commands."
    )
    return {"role": "assistant", "content": body}


def convert_walkthrough(data: dict, wid: str) -> list[dict] | None:
    initial = (data.get("initial_prompt") or "").strip()
    steps = data.get("steps") or []
    if not initial or not steps:
        return None
    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Goal: {initial}\n\nWhat is the next action?"},
    ]
    last_result = ""
    for step in steps:
        thought = (step.get("thought") or "").strip()
        command = (step.get("command") or "").strip()
        result = (step.get("result") or "").strip()
        if not command:
            continue
        tool_name, tool_args = map_command(command)
        call_id = f"call_{wid}_{step.get('step_number', len(messages))}"
        messages.append(
            {
                "role": "assistant",
                "content": thought,
                "tool_calls": [
                    {
                        "id": call_id,
                        "type": "function",
                        "function": {"name": tool_name, "arguments": json.dumps(tool_args)},
                    }
                ],
            }
        )
        messages.append({"role": "tool", "tool_call_id": call_id, "content": result})
        last_result = result
    if len(messages) <= 2:
        return None
    messages.append(_stop_message(last_result))
    return messages


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--steps", default="data/finetune/pentest-r1/data/steps")
    ap.add_argument("--out", default="data/finetune")
    ap.add_argument("--val-frac", type=float, default=0.1)
    args = ap.parse_args()

    steps_dir = Path(args.steps)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(steps_dir.glob("*.json"))
    if not files:
        print(f"no walkthroughs under {steps_dir}")
        return 1

    examples: list[dict] = []
    tool_hist: dict[str, int] = {}
    skipped = 0
    for fp in files:
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            skipped += 1
            continue
        msgs = convert_walkthrough(data, fp.stem)
        if msgs is None:
            skipped += 1
            continue
        for m in msgs:
            for tc in m.get("tool_calls", []) or []:
                name = tc["function"]["name"]
                tool_hist[name] = tool_hist.get(name, 0) + 1
        examples.append({"messages": msgs})

    n_val = max(1, int(len(examples) * args.val_frac))
    val, train = examples[:n_val], examples[n_val:]

    (out_dir / "tools.json").write_text(json.dumps(TOOLS_JSON, indent=2), encoding="utf-8")
    for name, rows in (("train", train), ("val", val)):
        with (out_dir / f"{name}.jsonl").open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    turns = [len(e["messages"]) for e in examples]
    print(f"converted={len(examples)} skipped={skipped}  train={len(train)} val={len(val)}")
    print(f"messages/example: min={min(turns)} max={max(turns)} avg={sum(turns) / len(turns):.1f}")
    print("tool-call distribution:")
    for name, cnt in sorted(tool_hist.items(), key=lambda kv: -kv[1]):
        print(f"  {name:18s} {cnt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
