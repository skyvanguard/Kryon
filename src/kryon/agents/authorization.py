"""Engagement authorization — the cage's "when" and "what", on top of scope's "where".

A real engagement authorizes three things: WHICH targets (scope), WHEN (a time
window), and WHAT intensity of action (a tier ceiling). The scope cage covers
"where"; this bundles all three into one gate consulted at the tool-execution
layer. Any constraint violated → the call is refused with an observation the
model can adapt to, so the agent stays inside its written authorization even when
running fully autonomously.

    KRYON_SCOPE=10.65.168.0/24,*.creative.thm     # where  (delegated to ScopeGate)
    KRYON_ENGAGEMENT_START=2026-06-18T02:00:00Z   # when   — not before
    KRYON_ENGAGEMENT_END=2026-06-18T06:00:00Z     # when   — not after
    KRYON_MAX_TIER=active                          # what   — passive|active|exploit|post

Any one set → the cage is active. All unset → inactive (backward compatible).

Tiers (ascending intrusiveness): ``passive`` (read-only recon) < ``active``
(scanning that touches the target) < ``exploit`` (exploitation / cred bruteforce)
< ``post`` (post-foothold: credential dumping, lateral movement, persistence).
A tool above ``KRYON_MAX_TIER`` is refused. Unknown tools default to ``active``;
the dangerous tiers are matched by explicit keyword so they are never silently
under-classified.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from kryon.agents.scope_gate import get_scope_gate, reset_scope_gate

logger = logging.getLogger(__name__)

_TIERS = {"passive": 1, "active": 2, "exploit": 3, "post": 4}
_TIER_NAME = {v: k for k, v in _TIERS.items()}

# Post-foothold: matched FIRST so these are never under-classified as active.
_POST_KW = (
    "dump_lsass", "dump_sam", "dump_kerberos", "dump_credential", "secretsdump",
    "mimikatz", "kerberoast", "asreproast", "dcsync", "pass_the_hash", "pass_the_ticket",
    "crack_ntlm", "extract_ntlm", "psexec", "wmiexec", "smbexec", "winexec", "dcomexec",
    "_lateral_movement", "evil_winrm", "bloodhound", "run_linpeas", "gtfobins",
    "persistence", "beacon", "_c2", "c2_server", "exfil", "implant", "backdoor",
    "timestomp", "find_attack_path", "enumerate_ad",
)
# Exploitation / intrusive credential attacks.
_EXPLOIT_KW = (
    "sqlmap_dump", "sqlmap_database", "exploit_file_upload", "exploit_java", "web_exploit",
    "msfvenom", "commix", "metasploit", "reverse_shell", "shell_session", "os_shell",
    "_rce", "payload_delivery", "credential_spray", "smart_password", "hydra", "medusa",
    "jwt_crack", "ffuf_api",
)
# Read-only recon / reasoning.
_PASSIVE_KW = (
    "web_fetch", "dns_", "whois", "shodan", "theharvester", "duckduckgo", "recall",
    "tool_search", "request_skill", "think", "read_", "reader", "corpus", "whatweb",
    "submit_finding", "calculate_mitre",
)


def _tool_tier(name: str) -> int:
    n = (name or "").lower()
    if any(k in n for k in _POST_KW):
        return _TIERS["post"]
    if any(k in n for k in _EXPLOIT_KW):
        return _TIERS["exploit"]
    if any(k in n for k in _PASSIVE_KW):
        return _TIERS["passive"]
    return _TIERS["active"]  # conservative default for unknown tools


def _parse_dt(s: str) -> datetime | None:
    s = (s or "").strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except ValueError:
        logger.warning("authorization: unparseable timestamp %r (expected ISO 8601)", s)
        return None


class EngagementAuthorization:
    """Window + tier + scope, checked in that order. Any fail → (False, reason)."""

    def __init__(self, scope_gate, start: datetime | None, end: datetime | None, max_tier: int | None):
        self.scope_gate = scope_gate
        self.start = start
        self.end = end
        self.max_tier = max_tier

    def authorize(self, tool_name: str, args_json: str) -> tuple[bool, str | None]:
        if self.start or self.end:
            now = datetime.now(timezone.utc)
            if self.start and now < self.start:
                return False, f"engagement window has not started yet (starts {self.start.isoformat()})"
            if self.end and now > self.end:
                return False, f"engagement window has ended ({self.end.isoformat()})"
        if self.max_tier is not None:
            tier = _tool_tier(tool_name)
            if tier > self.max_tier:
                return False, (
                    f"tool '{tool_name}' is tier '{_TIER_NAME[tier]}', above the authorized "
                    f"max tier '{_TIER_NAME[self.max_tier]}'"
                )
        if self.scope_gate is not None:
            return self.scope_gate.check_call(tool_name, args_json)
        return True, None


_AUTH: EngagementAuthorization | None = None
_AUTH_LOADED = False


def get_authorization() -> EngagementAuthorization | None:
    """Build the engagement authorization from env once. All constraints unset →
    None (cage inactive, backward compatible)."""
    global _AUTH, _AUTH_LOADED
    if _AUTH_LOADED:
        return _AUTH
    _AUTH_LOADED = True
    gate = get_scope_gate()  # reads KRYON_SCOPE
    start = _parse_dt(os.environ.get("KRYON_ENGAGEMENT_START", ""))
    end = _parse_dt(os.environ.get("KRYON_ENGAGEMENT_END", ""))
    tier_raw = os.environ.get("KRYON_MAX_TIER", "").strip().lower()
    max_tier = _TIERS.get(tier_raw) if tier_raw else None
    if gate is None and start is None and end is None and max_tier is None:
        _AUTH = None
        return None
    _AUTH = EngagementAuthorization(gate, start, end, max_tier)
    logger.info(
        "engagement authorization ACTIVE: scope=%s window=%s..%s max_tier=%s",
        bool(gate), start, end, _TIER_NAME.get(max_tier) if max_tier else None,
    )
    return _AUTH


def reset_authorization() -> None:
    """Test hook — force a re-read of the env (resets the scope gate too)."""
    global _AUTH, _AUTH_LOADED
    _AUTH, _AUTH_LOADED = None, False
    reset_scope_gate()
