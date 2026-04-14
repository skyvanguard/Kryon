"""Command safety classifier and dry-run mode.

Ported from Claude Code's destructiveCommandWarning.ts. Provides:
- classify_command(cmd) -> (severity, reason)
- get_destructive_warning(cmd) -> str | None
- is_dry_run_enabled() -> bool

Severity values: 'safe', 'caution', 'destructive'.
"""

from __future__ import annotations

import os
import re

# (regex, reason) pairs. Order matters: first match wins.
DESTRUCTIVE_PATTERNS: list[tuple[str, str]] = [
    # File deletion
    (r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR]", "recursive force-remove"),
    (r"rm\s+-[a-zA-Z]*[rR]\b", "recursive remove"),
    (r"rm\s+-[a-zA-Z]*f\b", "force-remove"),
    # Destructive overwrites of critical system files
    (r">\s*/etc/(passwd|shadow|hosts|sudoers|fstab|resolv\.conf)\b", "overwrite critical system file"),
    (r"dd\s+if=[^\s]+\s+of=/dev/(sd[a-z]|nvme|xvd|hd[a-z])", "direct disk write"),
    (r"\bmkfs\.[a-z0-9]+\b", "filesystem format"),
    # Database
    (r"\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA)\b", "drop/truncate database"),
    (r"\bDELETE\s+FROM\s+\w+\s*(;|\"|'|$)", "delete all rows (no WHERE)"),
    # Service/system stop
    (r"systemctl\s+(stop|disable|mask)\s+(ssh|sshd|network|networking|firewalld|iptables)\b", "stop critical service"),
    (r"\b(shutdown|poweroff|halt|reboot)\b", "system shutdown"),
    # Firewall (dangerous flush)
    (r"iptables\s+(-F|--flush)\b", "flush firewall rules"),
    (r"\bufw\s+disable\b", "disable firewall"),
    # Network
    (r"\bip\s+link\s+set\s+\S+\s+down\b", "bring network interface down"),
    # Infrastructure
    (r"\bkubectl\s+delete\b", "delete kubernetes resources"),
    (r"\bterraform\s+destroy\b", "destroy terraform infrastructure"),
    (r"\bdocker\s+system\s+prune\s+-[a-z]*a", "remove all docker resources"),
    (r"\bdocker\s+rm\s+-f\b", "force-remove docker container"),
    # Privilege/account changes
    (r"\buserdel\s+", "delete user account"),
    (r"\bchmod\s+-R\s+777\b", "world-writable recursive permissions"),
]

CAUTION_PATTERNS: list[tuple[str, str]] = [
    (r"\bsed\s+-i\b", "in-place file edit"),
    (r"\bsystemctl\s+(restart|reload)\b", "service restart"),
    (r"\bapt(-get)?\s+(install|remove|purge)\b", "package change"),
    (r"\byum\s+(install|remove)\b", "package change"),
    (r"\bdnf\s+(install|remove)\b", "package change"),
    (r"\bpip\s+install\b", "package install"),
    (r"\bgit\s+(reset|push)\b.*--force", "force git operation"),
]

_DESTRUCTIVE_COMPILED = [(re.compile(p, re.IGNORECASE), reason) for p, reason in DESTRUCTIVE_PATTERNS]
_CAUTION_COMPILED = [(re.compile(p, re.IGNORECASE), reason) for p, reason in CAUTION_PATTERNS]


def classify_command(command: str) -> tuple[str, str]:
    """Classify a shell command by destructiveness.

    Returns (severity, reason) where severity is one of 'safe', 'caution',
    'destructive'. For 'safe', reason is an empty string.
    """
    if not command or not command.strip():
        return ("safe", "")

    for pattern, reason in _DESTRUCTIVE_COMPILED:
        if pattern.search(command):
            return ("destructive", reason)

    for pattern, reason in _CAUTION_COMPILED:
        if pattern.search(command):
            return ("caution", reason)

    return ("safe", "")


def get_destructive_warning(command: str) -> str | None:
    """Return a human-readable warning if the command is destructive, else None."""
    severity, reason = classify_command(command)
    if severity == "destructive":
        return f"DESTRUCTIVE: {reason}"
    return None


def is_dry_run_enabled() -> bool:
    """Read KRYON_DRY_RUN env var. Truthy values: '1', 'true', 'yes', 'on'."""
    return os.getenv("KRYON_DRY_RUN", "false").strip().lower() in {"1", "true", "yes", "on"}
