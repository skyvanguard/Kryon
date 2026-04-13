"""
Command safety classifier — ported from Claude Code's
`tools/BashTool/destructiveCommandWarning.ts`.

Classifies shell commands by destructive potential before execution.
Works with both local and SSH'd commands (since run_command wraps SSH
calls as `ssh user@host 'cmd'`, we also match patterns inside quoted
remote commands).

Severities:
  - safe: read-only / informational (ls, cat, grep, systemctl status, ...)
  - caution: modifies state but typically reversible (sed -i, systemctl
    restart, apt install, cp/mv, ufw enable)
  - destructive: hard/impossible to reverse (rm -rf, dd of=/dev/..., DROP
    TABLE, mkfs, shutdown, iptables -F, terraform destroy, ...)

Usage:
    from kryon.services.command_safety import classify_command, is_dry_run_enabled

    severity, reason = classify_command("rm -rf /var/log")
    # severity = "destructive", reason = "recursive force-remove"

    if is_dry_run_enabled():
        return f"[DRY-RUN] Would execute: {cmd}"
"""

from __future__ import annotations

import os
import re

# Order matters: more specific / more dangerous patterns first
_DESTRUCTIVE_PATTERNS: list[tuple[str, str]] = [
    # Direct disk writes / filesystem destruction
    (r"\bdd\s+if=[^ ]+\s+of=/dev/(sd[a-z]|nvme|xvd|hd[a-z])", "direct disk write"),
    (r"\bmkfs\.[a-z0-9]+\b", "filesystem format"),
    (r"\bshred\b", "secure file shredding"),

    # System shutdown / reboot
    (r"\b(shutdown|poweroff|halt|reboot|init\s+0|init\s+6)\b", "system shutdown or reboot"),

    # Recursive/force removal
    (r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*f\b", "recursive force-remove"),
    (r"\brm\s+-[a-zA-Z]*f[a-zA-Z]*[rR]\b", "recursive force-remove"),
    (r"\brm\s+-[a-zA-Z]*[rR]\b", "recursive remove"),
    (r"\brm\s+-[a-zA-Z]*f\b", "force-remove"),

    # Overwrite of critical system files
    (r">\s*/etc/(passwd|shadow|sudoers|hosts|crontab|ssh/sshd_config)\b", "overwrite critical system file"),
    (r"\btee\s+/etc/(passwd|shadow|sudoers|hosts|crontab|ssh/sshd_config)\b", "overwrite critical system file via tee"),

    # Database destructive operations
    (r"\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA|USER|ROLE)\b", "drop/truncate database object"),
    (r"\bDELETE\s+FROM\s+\w+[ \t]*(;|\"|'|$)", "delete all rows from table"),

    # Firewall / network: lockout risk
    (r"\biptables\s+-F\b|\biptables\s+--flush\b", "flush firewall rules"),
    (r"\bnft\s+flush\s+ruleset\b", "flush nftables ruleset"),
    (r"\bufw\s+disable\b", "disable firewall"),
    (r"\bip\s+link\s+set\s+\S+\s+down\b", "bring network interface down"),

    # Critical service stops
    (r"\bsystemctl\s+(stop|disable|mask)\s+(ssh|sshd|network|networking|systemd-networkd|firewalld)\b",
     "stop/disable critical network service"),

    # Container/infra
    (r"\bkubectl\s+delete\b", "delete Kubernetes resources"),
    (r"\bterraform\s+destroy\b", "destroy Terraform infrastructure"),
    (r"\bdocker\s+system\s+prune\s+-[a-z]*a", "remove all docker resources"),
    (r"\bdocker\s+rm\s+-f\b.*\$\(docker\s+ps", "force remove all docker containers"),

    # Fork bomb (classic)
    (r":\s*\(\s*\)\s*{\s*:\|:&\s*}\s*;\s*:", "fork bomb"),

    # chmod/chown on critical paths
    (r"\bchmod\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+(/|/etc|/var|/usr|/home)(\s|$)", "recursive chmod on system path"),
    (r"\bchown\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+\S+\s+(/|/etc|/var|/usr|/home)(\s|$)", "recursive chown on system path"),
]

_CAUTION_PATTERNS: list[tuple[str, str]] = [
    # In-place file edits
    (r"\bsed\s+-[a-zA-Z]*i[a-zA-Z]*\b", "in-place file edit"),
    # Package install/remove
    (r"\b(apt|apt-get|yum|dnf|pacman|apk)\s+(install|remove|purge|autoremove)\b", "package management"),
    (r"\bpip\s+(install|uninstall)\b", "Python package change"),
    (r"\bnpm\s+(install|uninstall|remove)\b", "npm package change"),
    # Service restart
    (r"\bsystemctl\s+(restart|reload|start)\b", "service state change"),
    # Config overwrites via common patterns
    (r"\bcrontab\s+-[a-z]*r\b", "remove crontab"),
    (r"\bufw\s+(allow|deny|reject|delete)\b", "firewall rule change"),
    (r"\biptables\s+-A\b|\biptables\s+-D\b", "firewall rule change"),
]


def classify_command(command: str) -> tuple[str, str]:
    """Classify a shell command by its destructive potential.

    Returns (severity, reason) where severity is 'safe', 'caution', or
    'destructive', and reason is a short human-readable string (empty
    for 'safe').

    Handles SSH-wrapped commands by also scanning the quoted inner command.
    """
    if not command or not isinstance(command, str):
        return "safe", ""

    # Unwrap common SSH wrappers so patterns match the inner command too
    # e.g. `ssh user@host 'rm -rf /var/log'` → also scan `rm -rf /var/log`
    candidates = [command]
    for m in re.finditer(r"ssh\s+[^'\"]+['\"]([^'\"]+)['\"]", command):
        candidates.append(m.group(1))
    for m in re.finditer(r"sshpass\s+-p\s+\S+\s+ssh\s+[^'\"]+['\"]([^'\"]+)['\"]", command):
        candidates.append(m.group(1))

    for cmd in candidates:
        for pattern, reason in _DESTRUCTIVE_PATTERNS:
            if re.search(pattern, cmd):
                return "destructive", reason
        for pattern, reason in _CAUTION_PATTERNS:
            if re.search(pattern, cmd):
                return "caution", reason

    return "safe", ""


def get_destructive_warning(command: str) -> str | None:
    """Return a warning string if the command is destructive, else None."""
    severity, reason = classify_command(command)
    if severity == "destructive":
        return f"⚠️ DESTRUCTIVE: {reason}"
    return None


def is_dry_run_enabled() -> bool:
    """Check if KRYON_DRY_RUN environment variable is set to true."""
    return os.environ.get("KRYON_DRY_RUN", "").lower() in ("true", "1", "yes")


def format_dry_run_output(command: str, severity: str, reason: str) -> str:
    """Format a dry-run response that the model will see."""
    return (
        f"[DRY-RUN] Would execute: {command}\n"
        f"[CLASSIFIED] severity={severity} reason={reason or 'N/A'}\n"
        f"[NOTE] Dry-run mode is ON — no changes were applied. "
        f"Use '/dry-run off' to execute commands for real."
    )
