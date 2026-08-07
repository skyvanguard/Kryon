"""Placeholder-target guard — stop the model scanning a made-up host.

The small local model, seeded by skill examples like ``nmap HOST`` /
``curl https://HOST``, runs those literally when it has no real target — looping
recon against a host that never resolves until the stuck-detector aborts.

Network tools call :func:`placeholder_reason` on their target/url. When it
returns a message, the tool returns that message *instead of* scanning, telling
the model to ASK the user for a real target rather than retry a placeholder.

Conservative on purpose: only single-label placeholders (``HOST``, ``TARGET``),
angle/brace slots (``<target>``, ``{host}``) and obviously-fake IPs are flagged.
Real dotted hosts (``host.docker.internal``, ``example.com``) pass through.
"""

from __future__ import annotations

import json
import re

# Single-label hostnames that are placeholders, never real targets.
_PLACEHOLDER_HOSTS = {
    "host",
    "hosts",
    "target",
    "targets",
    "target_host",
    "targethost",
    "your_target",
    "your-target",
    "yourhost",
    "your_host",
    "host_ip",
    "target_ip",
    "ip",
    "ipaddress",
    "ip_address",
    "domain",
    "url",
    "hostname",
    "fqdn",
    "placeholder",
    "changeme",
    "victim",
    "attacker",
}
# Structured target ARGS: the whole value is the target, so ANY `<…>`/`{…}` is a
# placeholder (a real target is never wrapped). Bounded + no whitespace.
_ANY_BRACKET = re.compile(r"<[^>\s]{1,60}>|(?<!\$)\{[^}\s]{1,60}\}")

# Shell COMMANDS carry arbitrary payloads (XML/HTML), so a bracket there counts
# as a placeholder ONLY when it wraps a slot word — `<target>`/`{host}` are
# caught but `<methodCall>` / `<script>` are NOT (that would block a legit cmd).
_SLOT_WORDS = (
    r"target|host|hostname|url|uri|ip|ipaddr|ip[_-]?addr(?:ress)?|domain|fqdn|"
    r"rhost|your[_-]?target|your[_-]?host|your[_-]?domain|placeholder"
)
# `<slot>` always; `{slot}` only when NOT a shell var expansion (`${slot}`).
_BRACKET_SLOT = re.compile(r"<(?:" + _SLOT_WORDS + r")>|(?<!\$)\{(?:" + _SLOT_WORDS + r")\}", re.IGNORECASE)
_FAKE_IP = re.compile(r"^(?:x\.x\.x\.x|0\.0\.0\.0|1\.2\.3\.4|127\.0\.0\.1x)$", re.IGNORECASE)

_MSG = (
    "⛔ TARGET INVÁLIDO: '{t}' es un placeholder, no un objetivo real. "
    "NO escanees ni fetchees placeholders. DETENÉ el recon y PEDILE al usuario el "
    "objetivo concreto (URL, IP o host); esperá su respuesta antes de seguir. "
    "No inventes un host."
)


def _host_of(target: str) -> str:
    # Canonical host extraction (lowercased for the placeholder-set membership test).
    from kryon.util.net import bare_host

    return bare_host(target, lower=True)


def placeholder_reason(target: str | None) -> str | None:
    """A directive string when `target` is a placeholder, else None."""
    if target is None:
        return _MSG.format(t="(vacío)")
    t = str(target).strip()
    if not t:
        return _MSG.format(t="(vacío)")
    if _ANY_BRACKET.search(t):
        return _MSG.format(t=t)
    host = _host_of(t)
    if not host:
        return None
    if host in _PLACEHOLDER_HOSTS or _FAKE_IP.match(host):
        return _MSG.format(t=t)
    return None


def is_placeholder(target: str | None) -> bool:
    """Boolean convenience wrapper over :func:`placeholder_reason`."""
    return placeholder_reason(target) is not None


# For scanning a shell command (run_command) for un-substituted placeholders.
_URL_IN_CMD = re.compile(r"https?://[^\s'\"|>)]+", re.IGNORECASE)
# Uppercase standalone slots the model left un-substituted. Uppercase-only and
# fenced so shell vars ($HOST, ${HOST}), assignments (HOST=…), flags
# (--host-header) and words (GHOST) never match.
_BARE_SLOT = re.compile(r"(?<![\w.\-${])(HOSTNAME|HOST|TARGET_HOST|TARGET|YOUR_TARGET|YOURHOST)(?![\w.\-}=])")


def command_reason(command: str | None) -> str | None:
    """Directive when a shell command still carries a placeholder host/URL.

    Catches the `run_command("curl https://HOST/…")` / `wpscan --url HOST`
    class the structured-arg guard can't see. Conservative: URL hosts that are
    placeholders, `<slot>` brackets wrapping a slot WORD (not XML/HTML tags), or
    uppercase standalone HOST/TARGET — never shell variables or payloads.
    """
    if not command:
        return None
    m = _BRACKET_SLOT.search(command)
    if m:
        return _MSG.format(t=m.group(0))
    for um in _URL_IN_CMD.finditer(command):
        reason = placeholder_reason(um.group(0))
        if reason:
            return reason
    slot = _BARE_SLOT.search(command)
    if slot:
        return _MSG.format(t=slot.group(1))
    return None


# Canonical roots for an arg that names a scan target / a shell command. Matched
# token-wise (split on non-alphanumerics) against arg names, so ANY reasonable
# naming — target, url, scan_url, victim_host, target_ip, remote_addr — is
# covered without per-tool wiring. Liberal on the KEY is safe because the VALUE
# check (placeholder_reason) only fires on literal placeholders.
_TARGET_ROOTS = {
    "target", "targets", "host", "hosts", "hostname", "url", "urls", "uri",
    "ip", "ipaddr", "ipaddress", "domain", "fqdn", "addr", "address",
    "endpoint", "rhost", "site", "server", "destination", "dst", "machine", "victim",
}  # fmt: skip
_COMMAND_ROOTS = {"command", "commands", "cmd", "cmdline", "commandline", "shell"}
_KEY_TOKEN = re.compile(r"[a-z0-9]+")


def _key_tokens(key: object) -> set[str]:
    return set(_KEY_TOKEN.findall(str(key).lower()))


def guard_tool_args(tool_name: str, arguments: object) -> str | None:
    """Directive when any target/url/host arg (or shell command) in a tool call
    is a placeholder. Called from the SDK tool executor so EVERY tool — nmap,
    sqlmap, nuclei, gobuster, … and future ones — is covered in one place.

    Matches arg names token-wise against canonical roots (target/host/url/…), so
    a new tool naming its target `scan_url` or `victim_host` is auto-covered.
    `arguments` may be a JSON string (as the SDK passes) or a dict; anything
    unparseable / non-dict → None, so it never blocks a tool it can't inspect.
    """
    if isinstance(arguments, str):
        try:
            args = json.loads(arguments)
        except Exception:
            return None
    else:
        args = arguments
    if not isinstance(args, dict):
        return None

    for key, val in args.items():
        if not isinstance(val, str) or not val.strip():
            continue
        tokens = _key_tokens(key)
        if tokens & _COMMAND_ROOTS:
            reason = command_reason(val)
            if reason:
                return reason
        elif tokens & _TARGET_ROOTS:
            reason = placeholder_reason(val)
            if reason:
                return reason
    return None
