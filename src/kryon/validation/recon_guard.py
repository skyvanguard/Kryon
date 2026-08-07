"""Recon-only gate — refuse port-scanning / intrusive exploitation commands.

Even in ``--active`` mode, a *discovery* engagement (map the HTTP surface: dirs,
vhosts, endpoints, methods) must not port-scan or exploit. In a live run the
model, handed an ``--active`` toolset, ran ``nmap --top-ports 2000`` against the
target despite an explicit "no port scan" instruction — because the prompt does
NOT govern the tool layer. This is the technical gate: with ``KRYON_RECON_ONLY``
set, any command invoking a port scanner or an intrusive exploit tool is refused
with an observation that redirects the model back to HTTP discovery. Ordinary web
recon (curl, ffuf, whatweb, HTTP fetches) is untouched.

Pure + import-light so it can be consulted from the run_command hot path and unit
tested without a shell.
"""

from __future__ import annotations

import re

from kryon.util.env import env_bool

# Binaries that scan ports/networks — never needed to discover an HTTP surface.
_PORTSCAN = ("nmap", "masscan", "rustscan", "zmap", "unicornscan", "naabu")
# Intrusive exploitation / credential-bruteforce tooling.
_EXPLOIT = (
    "sqlmap",
    "hydra",
    "medusa",
    "ncrack",
    "patator",
    "msfconsole",
    "msfvenom",
    "metasploit",
    "commix",
)

_DENIED = _PORTSCAN + _EXPLOIT

_MSG = (
    "[KRYON_RECON_ONLY] '{tool}' is disabled: this is a recon-only (HTTP discovery) "
    "engagement — do NOT port-scan or exploit. Discover the API/app surface over HTTP "
    "instead: curl/web_fetch on /, /api, /api/v1, /api/v2, vhosts via the Host header, "
    "and methods GET/POST/OPTIONS. (Scanning/exploitation needs written authorization; "
    "unset KRYON_RECON_ONLY to enable it.)"
)


def _invoked_tool(command: str, binaries: tuple[str, ...]) -> str | None:
    """Return the first denied binary that appears in *command position* — at the
    start, after a shell separator (``;`` ``|`` ``&`` `` `` ``(``), after a known
    wrapper (``sudo``/``torsocks``/``proxychains``), or as a path basename — and is
    not merely a substring of a URL/path/flag. ``nmap`` in ``/x/nmap-results`` does
    not match; ``nmap -Pn`` and ``/usr/bin/nmap`` do.
    """
    for b in binaries:
        pat = rf"(?:^|[;&|`(]|\bsudo\s+|\btorsocks\s+|\bproxychains4?\s+|/)\s*{re.escape(b)}(?=\s|$)"
        if re.search(pat, command, re.IGNORECASE):
            return b
    return None


def recon_only_reason(command: str) -> str | None:
    """If ``KRYON_RECON_ONLY`` is set and *command* invokes a port scanner or an
    intrusive exploit tool, return a refusal observation for the model; else ``None``.
    """
    if not env_bool("KRYON_RECON_ONLY"):
        return None
    tool = _invoked_tool(command or "", _DENIED)
    if tool:
        return _MSG.format(tool=tool)
    return None


# Generic command-runner tools whose real binary lives inside their args.
_COMMAND_TOOLS = frozenset({"run_command", "run_command_async", "execute_code", "execute_command"})


def _command_from_arguments(arguments: object) -> str:
    """Extract the shell command / code string from a tool call's arguments,
    which the SDK passes as a JSON string (or already-decoded dict)."""
    if arguments is None:
        return ""
    if isinstance(arguments, str):
        try:
            import json

            arguments = json.loads(arguments)
        except (ValueError, TypeError):
            return arguments  # not JSON — scan the raw string anyway
    if isinstance(arguments, dict):
        for key in ("command", "cmd", "code", "shell"):
            val = arguments.get(key)
            if isinstance(val, str):
                return val
    return ""


def recon_only_reason_for_tool(tool_name: str, arguments: object = None) -> str | None:
    """Chokepoint variant of :func:`recon_only_reason`, keyed on the tool NAME.

    The dedicated wrappers (``nmap``, ``sqlmap_scan``, ``hydra``, …) call the raw
    dispatcher, not the guarded ``run_command``, so the string check never sees
    them — this is the gap that let ``investigate --active --recon-only`` port-scan.
    Blocks a tool whose identity IS a denied binary (by name), and still inspects
    the rendered command for generic runners. Returns a refusal or ``None``.
    """
    if not env_bool("KRYON_RECON_ONLY"):
        return None
    low = (tool_name or "").lower()
    # 1. Dedicated wrapper whose identity is a port-scan / exploit binary. Match
    #    exact ('nmap') or an underscore-suffixed variant ('sqlmap_scan').
    for binary in _DENIED:
        if low == binary or low.startswith(binary + "_"):
            return _MSG.format(tool=binary)
    # 2. Generic command runners: inspect the command carried in the args.
    if low in _COMMAND_TOOLS:
        cmd = _command_from_arguments(arguments)
        if cmd:
            return recon_only_reason(cmd)
    return None
