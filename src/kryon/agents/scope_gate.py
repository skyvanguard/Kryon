"""Scope cage — hard target enforcement at the tool-execution layer.

The agent's only constraint used to be the prompt, and a model will ignore it
(the passive-gate bug: a local model ran active nmap in "passive" mode). For SAFE
autonomy the cage must live where actions actually happen: every tool call that
touches a target is validated against the authorized engagement scope BEFORE it
runs. Out-of-scope → the call is refused and the agent receives a BLOCKED
observation it can adapt to. It physically cannot reach beyond scope, no matter
what the model decides.

Opt-in by declaring scope (the "written authorization" as a technical artifact):

    KRYON_SCOPE=10.65.168.0/24,*.creative.thm,https://app.target.com
    KRYON_SCOPE_DENY=10.65.168.1            # optional hard deny (e.g. the gateway)

With ``KRYON_SCOPE`` unset the gate is inactive (backward compatible). Localhost /
loopback is always allowed — it is the agent's own host, not an external target
(an SSRF payload of ``127.0.0.1`` still rides on an in-scope target's request).

Known limitation: target extraction is regex/key based, so an obfuscated target
(decimal IP, etc.) could slip the software gate — that is why the isolated
``kryon-pentest`` docker network + egress firewall are the defense-in-depth layer.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
from urllib.parse import urlparse

from kryon.agents.scope import ScopeEnforcer, ScopeRule

logger = logging.getLogger(__name__)

# Structured argument keys that name a network target.
_TARGET_KEYS = (
    "target", "targets", "host", "hostname", "url", "base_url", "target_url",
    "ip", "rhost", "rhosts", "domain", "subnet",
)
# Argument keys whose string value is a shell command / code to scan for targets.
_CMD_KEYS = ("command", "cmd", "code", "script")

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_URL_RE = re.compile(r"https?://[^\s\"'`]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b")


def _is_localhost(host: str) -> bool:
    h = host.lower().strip()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _host_of(value: str) -> str:
    """URL → hostname; otherwise the trimmed value itself."""
    v = value.strip()
    if v.lower().startswith(("http://", "https://")):
        return urlparse(v).hostname or v
    return v


class ScopeGate:
    """Validates a tool call's targets against the authorized scope."""

    def __init__(self, rules: list[ScopeRule], deny_cidrs: list[str]):
        self._enforcer = ScopeEnforcer(rules)
        self._deny: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for d in deny_cidrs:
            try:
                self._deny.append(ipaddress.ip_network(d, strict=False))
            except ValueError:
                logger.warning("scope cage: invalid deny CIDR %r", d)

    def _check_target(self, value: str) -> tuple[bool, str | None]:
        value = (value or "").strip()
        if not value:
            return True, None
        host = _host_of(value)
        if _is_localhost(host):
            return True, None  # the agent's own host, not an external target
        try:
            ip = ipaddress.ip_address(host)
            for net in self._deny:
                if ip in net:
                    return False, f"{host} is in the deny list ({net})"
        except ValueError:
            pass
        # Allow if EITHER the full value matches a url_prefix rule OR the extracted
        # host matches an ip/domain/cidr rule.
        if self._enforcer.is_allowed(value)[0]:
            return True, None
        return self._enforcer.is_allowed(host)

    def check_call(self, tool_name: str, args_json: str) -> tuple[bool, str | None]:
        """Return (allowed, reason). Blocks if ANY extracted target is out of
        scope. Args with no extractable target are allowed (non-network ops)."""
        try:
            args = json.loads(args_json) if isinstance(args_json, str) else (args_json or {})
        except (json.JSONDecodeError, TypeError, ValueError):
            return True, None
        if not isinstance(args, dict):
            return True, None

        targets: list[str] = []
        for key in _TARGET_KEYS:
            val = args.get(key)
            if isinstance(val, str) and val.strip():
                targets.append(val.strip())
            elif isinstance(val, (list, tuple)):
                targets.extend(str(x).strip() for x in val if str(x).strip())

        blob = " ".join(str(args.get(k, "")) for k in _CMD_KEYS if args.get(k))
        if blob:
            targets.extend(_IP_RE.findall(blob))
            targets.extend(_URL_RE.findall(blob))
            for m in _DOMAIN_RE.finditer(blob):
                d = m.group(1)
                if not d.endswith((".example.com", ".test", ".localhost")):
                    targets.append(d)

        for target in targets:
            ok, reason = self._check_target(target)
            if not ok:
                return False, reason
        return True, None


_GATE: ScopeGate | None = None
_LOADED = False


def _classify(entry: str) -> ScopeRule | None:
    """Auto-classify a scope entry into a ScopeRule (cidr/ip/url_prefix/domain)."""
    e = entry.strip()
    if not e:
        return None
    if e.lower().startswith(("http://", "https://")):
        return ScopeRule(rule_type="url_prefix", value=e.lower())
    if "/" in e:
        return ScopeRule(rule_type="cidr", value=e)
    try:
        ipaddress.ip_address(e)
        return ScopeRule(rule_type="ip", value=e)
    except ValueError:
        return ScopeRule(rule_type="domain", value=e.lstrip("*.").lower())


def get_scope_gate() -> ScopeGate | None:
    """Build the gate from env once. ``KRYON_SCOPE`` empty → None (inactive)."""
    global _GATE, _LOADED
    if _LOADED:
        return _GATE
    _LOADED = True
    raw = os.environ.get("KRYON_SCOPE", "").strip()
    if not raw:
        _GATE = None
        return None
    rules = [r for r in (_classify(e) for e in raw.split(",")) if r is not None]
    deny = [d.strip() for d in os.environ.get("KRYON_SCOPE_DENY", "").split(",") if d.strip()]
    _GATE = ScopeGate(rules, deny)
    logger.info("scope cage ACTIVE: %d scope rule(s), %d deny entr(ies)", len(rules), len(deny))
    return _GATE


def reset_scope_gate() -> None:
    """Test hook — force a re-read of the env on the next ``get_scope_gate``."""
    global _GATE, _LOADED
    _GATE, _LOADED = None, False
