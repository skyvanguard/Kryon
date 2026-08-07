"""FASE 5 — canonical tool invocation templates.

Sister module to G5 (``fact_extractor._INVOCATION_ANTI_PATTERNS``).
Where G5 surfaces hints AFTER the model issued a tool with subtly-wrong
flags, this module surfaces the correct flags BEFORE the next
invocation — as a markdown reference block injected into each
reflection turn.

The detection key is the tool history: we scan recent ``args_preview``
strings for any of the known tool names and render only the templates
that match. That keeps the block focused on what the model is actively
using and avoids spamming irrelevant tools.

Banca-safe: pure data + string formatting. No I/O, no LLM calls.
"""

from __future__ import annotations

# Tool name → (canonical invocation, one-line rationale).
# Order matters only when one name is a substring of another (e.g.
# ``ssh`` is in ``sshpass``); the detector iterates this dict so put
# the more specific entries first when there's ambiguity. The
# templates use ``<placeholder>`` for caller-supplied fields so the
# model can spot the substitution at a glance.
_TOOL_TEMPLATES: dict[str, tuple[str, str]] = {
    # AD / impacket
    "GetNPUsers.py": (
        "GetNPUsers.py -no-pass -dc-ip <host> -usersfile users.txt <domain>/ -outputfile /tmp/asrep_hashes.txt",
        "Save hashes to a file so the next stage (hashcat) can read them. -no-pass = AS-REP roast without creds.",
    ),
    "GetUserSPNs.py": (
        "GetUserSPNs.py -dc-ip <host> -request <domain>/<user>:'<pass>' -outputfile /tmp/spn_hashes.txt",
        "Kerberoast pulls TGS tickets for service accounts. The -request "
        "flag emits hash format ready for hashcat -m 13100.",
    ),
    "secretsdump.py": (
        "secretsdump.py -just-dc-ntlm <domain>/<user>:'<pass>'@<host>",
        "DRSUAPI dump of NTDS.DIT. -just-dc-ntlm skips the slower system-secrets path.",
    ),
    "bloodhound-python": (
        "bloodhound-python -u '<user>' -p '<pass>' -d <domain> -c all -ns <host>",
        "-c all collects users/groups/computers/sessions/ACLs. Run "
        "the BloodHound CE GUI afterwards to query attack paths.",
    ),
    # LDAP / SMB
    "ldapsearch": (
        "ldapsearch -x -H ldap://<host> -b 'DC=<dc1>,DC=<dc2>' -s sub '(objectClass=user)' sAMAccountName",
        "Always include an objectClass filter — the unfiltered "
        "subtree dump floods the chunk. Asking for a single "
        "attribute keeps output greppable.",
    ),
    "smbclient": (
        "smbclient -L //<host> -N",
        "-N = no password (NULL session). Use ``-U guest`` for "
        "explicit guest auth or ``-U '<user>%<pass>'`` once you have creds.",
    ),
    "nxc": (
        "nxc smb <host> -u guest -p '' --shares",
        "netexec (formerly crackmapexec) — replace ``smb`` with "
        "``ldap`` / ``winrm`` / ``rdp`` for the matching probe. "
        "--users / --groups / --pass-pol on ldap protocol.",
    ),
    # Network probes
    "nc": (
        "nc -q 1 -w 5 <host> <port>",
        "-q 1 = close 1 second after EOF on stdin. -w 5 = abort if "
        "the connection takes more than 5 seconds. Without these "
        "flags the subprocess hangs the chunk.",
    ),
    "ncat": (
        "ncat --recv-only --idle-timeout 5s <host> <port>",
        "ncat's --idle-timeout is the equivalent of nc -w. "
        "--recv-only forbids sending so a probe doesn't accidentally "
        "interact with a custom protocol.",
    ),
    # Web probes
    "curl": (
        "curl -s --max-time 10 -L -o - http://<host>/<path>",
        "Always pass --max-time on probes — slow targets behind a "
        "WAF can hang for minutes otherwise. -s silences progress, "
        "-L follows redirects, -o - emits body to stdout.",
    ),
    "wget": (
        "wget -q -t 1 -T 10 -O - http://<host>/<path>",
        "-t 1 = one attempt only. -T 10 = 10s timeout. -O - = stdout.",
    ),
    # Scanners
    "nmap": (
        "nmap -sV -sC -Pn -T4 --top-ports 1000 <host>",
        "-Pn skips host discovery (THM/HTB targets often block ICMP). "
        "-sV grabs banners, -sC runs default NSE scripts. "
        "--top-ports 1000 is faster than a full TCP scan and covers "
        "common services.",
    ),
    "sqlmap": (
        "sqlmap -u 'http://<host>/<path>?<param>=val' --batch --level=3 --risk=2 --random-agent",
        "--batch answers all interactive prompts with the safe "
        "default. level 3 + risk 2 covers cookies/headers/UA and "
        "stacked queries without going destructive.",
    ),
    "nuclei": (
        "nuclei -u http://<host> -severity high,critical -timeout 5",
        "Filter to high/critical to keep noise down. -timeout 5 bounds slow templates.",
    ),
    "gobuster": (
        "gobuster dir -u http://<host> -w /usr/share/wordlists/dirb/common.txt -t 20 -q",
        "-t 20 keeps thread count reasonable for shared targets. -q silences banner.",
    ),
    # Auth / pivot
    "sshpass": (
        "sshpass -p '<pass>' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null <user>@<host> '<cmd>'",
        "Inline ssh with a captured password. Strict host key "
        "checking off + null known_hosts so the first connect "
        "doesn't prompt. Always quote <cmd>.",
    ),
    "hashcat": (
        "hashcat -m <mode> -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --show",
        "Modes: 18200 (krb5asrep), 13100 (krb5tgs), 1000 (NTLM), "
        "5600 (NetNTLMv2). --show pulls already-cracked from the "
        "potfile without re-running the engine.",
    ),
    "john": (
        "john --wordlist=/usr/share/wordlists/rockyou.txt --format=<format> hashes.txt",
        "Formats: krb5asrep-23, krb5tgs, NT (NTLM). Run ``john --show`` after to surface cracked entries.",
    ),
}


def _detect_tools_in_args(args_preview: str) -> list[str]:
    """Scan a single ``args_preview`` (the run_command body or
    function_tool args) for any of the templated tool names. Returns
    matched names in insertion order of the templates dict."""
    if not args_preview:
        return []
    lower = args_preview.lower()
    return [name for name in _TOOL_TEMPLATES if name.lower() in lower]


def format_templates_for_recent_tools(args_previews: list[str]) -> str:
    """Build the ``🛠️ Canonical tool invocations`` block for a
    reflection turn. Inputs:

    * ``args_previews`` — list of the args_preview strings from the
      most recent ``_ToolCallRecord`` entries. Caller already trims
      the tail (e.g. last 8) before passing.

    Returns markdown ready for prompt injection. Empty string when
    no recent tool matched any template (don't pollute the prompt
    with an empty header).

    Caps the rendered list at 5 tools so the block stays compact —
    if the model used more than 5 distinct tools recently, the most
    recent 5 win.
    """
    if not args_previews:
        return ""
    seen: set[str] = set()
    ordered_names: list[str] = []
    # Walk the previews from newest to oldest so the most-recently-used
    # tools win the 5-cap.
    for preview in reversed(args_previews):
        for name in _detect_tools_in_args(preview):
            if name not in seen:
                seen.add(name)
                ordered_names.append(name)
    if not ordered_names:
        return ""
    lines: list[str] = [
        "\n🛠️ **Canonical tool invocations** "
        "(use these flag sets — anything else risks hanging the "
        "chunk or flooding output):\n",
    ]
    for name in ordered_names[:5]:
        canonical, why = _TOOL_TEMPLATES[name]
        lines.append(f"- **{name}** → `` {canonical} ``")
        lines.append(f"  - *Why*: {why}")
    return "\n".join(lines) + "\n"


__all__ = [
    "format_templates_for_recent_tools",
    "_detect_tools_in_args",
]
