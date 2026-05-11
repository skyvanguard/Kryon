"""F14.0 spike — LLM pentest reasoning gate.

For each of 10 ground-truth scenarios:
  1. Ask qwen3-coder: given this recon output, what's the next step and why?
  2. Apply deterministic baseline (rule-based priority).
  3. Auto-judge LLM and baseline vs expert_vector + expert_next_step.
  4. Emit scoreboard + gate decision.

Auto-judge uses structured keyword matching for the VECTOR category and
tool/CVE tokens for the STEP. Manual review is recorded in a TSV for the
operator to override any automated call.

Gate:
  - LLM accuracy >= 70%: full F14 pentest operator justified.
  - LLM accuracy 40-70% AND LLM > deterministic: co-pilot mode (F14 with LLM-assist framing).
  - LLM accuracy < 40% OR LLM <= deterministic: pivot to Option 2 compliance deterministic.
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
from pathlib import Path

SCENARIOS = Path("/tmp/f14_scenarios.yaml")
OUT = Path("/tmp/f14_spike_results.jsonl")
MODEL = "qwen3-coder:30b-32k"
ENDPOINT = "http://ollama:11434/v1"


SYSTEM = """You are a pentester helping plan the next step of an engagement.
You just ran initial recon against a target. Given the recon output,
propose ONE next command to run. Be specific — exact tool, exact target,
and one-sentence rationale.

Reply in EXACTLY this format on a single line:
NEXT: <exact command> | RATIONALE: <one sentence>
"""


USER_TEMPLATE = """Recon output for {target}:
{recon}

What is your next command? Remember: ONE command, specific, with rationale."""


# Very small YAML subset parser (we control the file, so no full yaml needed)
def load_scenarios(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    scenarios: list[dict] = []
    current: dict | None = None
    key_buf: list[str] = []
    multi_key: str | None = None
    multi_val: list[str] = []
    indent_block: int | None = None

    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        raw = line.rstrip()
        if not raw or raw.lstrip().startswith("#"):
            i += 1
            continue
        # End of block-scalar when indent decreases
        if multi_key is not None:
            # Check if this line is still in the block
            stripped = line.lstrip(" ")
            cur_indent = len(line) - len(stripped)
            if cur_indent >= (indent_block or 0) and stripped:
                multi_val.append(line[(indent_block or 0):])
                i += 1
                continue
            else:
                if current is not None:
                    current[multi_key] = "\n".join(multi_val).rstrip() + "\n"
                multi_key = None
                multi_val = []
                indent_block = None
                # fall through to re-parse this line as a new key

        s = line.lstrip()
        indent = len(line) - len(s)

        if s.startswith("scenarios:"):
            i += 1
            continue
        if s.startswith("- id:"):
            if current is not None:
                scenarios.append(current)
            current = {"id": s.split(":", 1)[1].strip()}
            i += 1
            continue
        if ":" in s and current is not None:
            k, _, v = s.partition(":")
            k = k.strip()
            v = v.strip()
            if v == "|":
                multi_key = k
                multi_val = []
                indent_block = indent + 2  # content indented 2 past the key
                i += 1
                continue
            current[k] = v.strip('"')
            i += 1
            continue
        i += 1

    # Flush final multi-line and current
    if multi_key is not None and current is not None:
        current[multi_key] = "\n".join(multi_val).rstrip() + "\n"
    if current is not None:
        scenarios.append(current)
    return scenarios


# --- deterministic baseline ----------------------------------------

_PRIORITY = [
    # (port_list or keyword, vector, suggested_tool)
    (["445", "139"], "smb", "enum4linux-ng -A $target"),
    (["21"], "ftp", "ftp $target  # attempt anonymous login"),
    (["3306"], "mysql", "nmap -sV --script mysql-info,mysql-empty-password $target -p 3306"),
    (["5432"], "postgres", "nmap --script pgsql-brute $target"),
    (["80", "443", "8080", "8443"], "web", "gobuster dir -u http://$target -w /usr/share/wordlists/dirb/common.txt"),
    (["22"], "ssh", "hydra -l root -P rockyou.txt ssh://$target  # or key recon"),
    (["25"], "smtp", "smtp-user-enum -M VRFY -U users.txt -t $target"),
]


def deterministic_next(recon: str) -> tuple[str, str]:
    ports = set(re.findall(r"^(\d+)/tcp\s+open", recon, re.M))
    for ports_list, vector, tool in _PRIORITY:
        if any(p in ports for p in ports_list):
            return vector, tool
    return "unknown", "nmap -sV -sC -p- $target  # full rescan"


# --- LLM call -------------------------------------------------------

def llm_next_step(scenario: dict) -> tuple[str, float]:
    body = json.dumps({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": USER_TEMPLATE.format(
                target=scenario.get("id", ""),
                recon=scenario.get("recon_output", ""),
            )},
        ],
        "temperature": 0,
        "top_p": 1,
        "max_tokens": 400,
    }).encode()
    req = urllib.request.Request(
        f"{ENDPOINT}/chat/completions",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": "Bearer ollama"},
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            doc = json.loads(r.read())
    except Exception as exc:
        return f"ERROR: {exc}", time.time() - t0
    content = (doc.get("choices") or [{}])[0].get("message", {}).get("content", "")
    return content.strip(), time.time() - t0


# --- scoring --------------------------------------------------------

_VECTOR_KEYWORDS = {
    "smb": ["smb", "samba", "smbclient", "enum4linux", "netbios", "ms17-010", "eternalblue",
            "ms08-067", "usermap", "445", "rpcclient"],
    "ftp": ["ftp", "anonymous", "vsftpd", "ftp-anon", "21/tcp"],
    "web": ["http", "gobuster", "dirb", "nikto", "wpscan", "drupalgeddon", "drupal", "hfs",
            "httpfile", "curl", "browse", "/dev/", "propfind", "webdav", "mod_ssl", "openfuck",
            "openluck", "wget", "phpbash", "changelog.txt", "burp"],
    "ssh": ["ssh", "hydra ssh", "openssh"],
    "mysql": ["mysql"],
    "smtp": ["smtp", "vrfy"],
    "unknown": [],
}


def match_vector(text: str, expected: str) -> bool:
    t = text.lower()
    kws = _VECTOR_KEYWORDS.get(expected, [])
    return any(k in t for k in kws)


def match_step(text: str, expert_step: str) -> bool:
    """Fuzzy match on signature tokens from expert answer."""
    t = text.lower()
    e = expert_step.lower()
    # Extract CVE refs or named exploits from expert
    tokens = set()
    for pat in [r"cve-\d{4}-\d{4,6}", r"ms\d{2}-\d{3}",
                r"drupalgeddon\d?", r"eternalblue", r"openfuck", r"phpbash",
                r"usermap_script", r"usermap", r"drupal"]:
        tokens.update(re.findall(pat, e))
    # Also extract tool primary keywords
    tool_map = [
        ("metasploit", "metasploit"),
        ("searchsploit", "searchsploit"),
        ("gobuster", "gobuster"),
        ("enum4linux", "enum4linux"),
        ("ftp", "ftp "),
        ("browser", "browser"),
    ]
    for expert_kw, _ in tool_map:
        if expert_kw in e:
            tokens.add(expert_kw)
    # Score
    if not tokens:
        return False
    hits = sum(1 for tok in tokens if tok in t)
    return hits >= 1


def score(llm_text: str, deterministic_tool: str, scenario: dict) -> dict:
    expected_vector = scenario.get("expert_vector", "")
    expected_step = scenario.get("expert_next_step", "")

    llm_vector_ok = match_vector(llm_text, expected_vector)
    llm_step_ok = match_step(llm_text, expected_step)
    if llm_vector_ok and llm_step_ok:
        llm_grade = "CORRECT"
    elif llm_vector_ok:
        llm_grade = "PARTIAL"
    else:
        llm_grade = "WRONG"

    det_vector_ok = match_vector(deterministic_tool, expected_vector)
    det_step_ok = match_step(deterministic_tool, expected_step)
    if det_vector_ok and det_step_ok:
        det_grade = "CORRECT"
    elif det_vector_ok:
        det_grade = "PARTIAL"
    else:
        det_grade = "WRONG"

    return {
        "llm_grade": llm_grade,
        "llm_vector_match": llm_vector_ok,
        "llm_step_match": llm_step_ok,
        "det_grade": det_grade,
        "det_vector_match": det_vector_ok,
        "det_step_match": det_step_ok,
    }


# --- driver ---------------------------------------------------------

def main() -> None:
    scenarios = load_scenarios(SCENARIOS)
    print(f"Loaded {len(scenarios)} scenarios")
    results = []
    for s in scenarios:
        llm_text, lat = llm_next_step(s)
        det_vector, det_tool = deterministic_next(s.get("recon_output", ""))
        sc = score(llm_text, f"{det_vector} {det_tool}", s)
        entry = {
            "id": s.get("id"),
            "source": s.get("source"),
            "expert_vector": s.get("expert_vector"),
            "expert_next_step": s.get("expert_next_step"),
            "llm_response": llm_text,
            "llm_latency_s": round(lat, 2),
            "deterministic_vector": det_vector,
            "deterministic_tool": det_tool,
            **sc,
        }
        results.append(entry)
        print(f"  [{s.get('id'):22s}] LLM={sc['llm_grade']:8s} DET={sc['det_grade']:8s}  lat={lat:.1f}s")

    OUT.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in results) + "\n",
                   encoding="utf-8")

    # Aggregate
    from collections import Counter
    llm_c = Counter(r["llm_grade"] for r in results)
    det_c = Counter(r["det_grade"] for r in results)
    n = len(results)
    llm_correct = llm_c.get("CORRECT", 0)
    det_correct = det_c.get("CORRECT", 0)
    llm_partial = llm_c.get("PARTIAL", 0)
    det_partial = det_c.get("PARTIAL", 0)

    print()
    print("=== F14.0 spike results ===")
    print(f"{'Grader':<14}{'CORRECT':<10}{'PARTIAL':<10}{'WRONG':<8}")
    print(f"{'LLM':<14}{llm_correct}/{n}        {llm_partial}/{n}        {llm_c.get('WRONG', 0)}/{n}")
    print(f"{'Deterministic':<14}{det_correct}/{n}        {det_partial}/{n}        {det_c.get('WRONG', 0)}/{n}")
    print()
    llm_acc = llm_correct / n
    det_acc = det_correct / n
    llm_acc_lenient = (llm_correct + llm_partial) / n
    det_acc_lenient = (det_correct + det_partial) / n
    print(f"LLM CORRECT accuracy:       {llm_acc:.1%}")
    print(f"LLM CORRECT+PARTIAL:        {llm_acc_lenient:.1%}")
    print(f"Deterministic CORRECT:      {det_acc:.1%}")
    print(f"Deterministic C+P:          {det_acc_lenient:.1%}")
    print()

    # Gate decision
    if llm_acc >= 0.70:
        verdict = "PASS — full F14 pentest operator sprint justified"
    elif llm_acc >= 0.40 and llm_acc > det_acc:
        verdict = "CO-PILOT — F14 as LLM-assisted, not LLM-autonomous"
    elif llm_acc <= det_acc:
        verdict = "FAIL — LLM does not beat deterministic; pivot to Option 2 (compliance deterministic)"
    else:
        verdict = "FAIL — LLM accuracy <40%; pivot to Option 2"
    print(f"GATE VERDICT: {verdict}")


if __name__ == "__main__":
    main()
