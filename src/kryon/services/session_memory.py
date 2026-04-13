"""
Session Memory — auto-maintained markdown notes about the current engagement.

Ported from Claude Code's `services/SessionMemory/sessionMemory.ts`.

After each turn, heuristic extractors scan the last few messages for key
facts (target, ports, tech, CVEs, phase) and write them to a small markdown
file. Before each turn, the file's contents are injected into the
conversation so the model always has session state — even after
auto-compaction clears older turns.

No LLM calls. All extraction is regex-based.

Usage:
    from kryon.services.session_memory import get_session_memory
    sm = get_session_memory()
    sm.update(last_messages)       # after turn
    context = sm.get_context()     # before turn
    sm.clear()                     # on /flush
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SESSION_FILE = os.environ.get("KRYON_SESSION_FILE", "/workspace/.kryon_session.md")

# Regex extractors
_URL_RE = re.compile(r"(?:https?://)?([a-z0-9._-]+\.[a-z]{2,})(?::\d+)?", re.I)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_NMAP_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)(?:\s+(\S+(?:\s+\S+)?))?", re.M)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_TECH_SIGNALS = {
    "apache": ["apache"],
    "nginx": ["nginx"],
    "iis": ["microsoft-iis"],
    "wordpress": ["wp-content", "wp-login", "wordpress"],
    "joomla": ["joomla", "/administrator"],
    "drupal": ["drupal"],
    "php": [" php/", "x-powered-by: php"],
    "laravel": ["laravel"],
    "node": ["express", "node.js"],
    "openssh": ["openssh"],
    "mysql": ["mysql", "mariadb"],
    "postgresql": ["postgresql"],
}
_SHELL_SIGNALS = [r"\buid=\d+", r"\bwhoami\b", r"\broot@"]
_FLAG_SIGNALS = [r"flag\{", r"HTB\{", r"THM\{", r"picoCTF\{"]


class SessionMemory:
    """Maintains a session-state markdown file updated by heuristics."""

    def __init__(self, filepath: str = _SESSION_FILE):
        self._path = Path(filepath)
        self._target: str | None = None
        self._resolved_ip: str | None = None
        self._ports: dict[int, str] = {}
        self._tech: set[str] = set()
        self._cves: set[str] = set()
        self._tools_run: list[str] = []
        self._findings: list[str] = []
        self._shell_gained = False
        self._flag_found = False
        self._last_update: str | None = None

    def update(self, recent_messages: list[dict[str, Any]]) -> None:
        """Extract facts from the last few messages and rewrite the file."""
        text = self._collect_text(recent_messages)
        if not text.strip():
            return

        self._extract_target(text)
        self._extract_ports(text)
        self._extract_tech(text)
        self._extract_cves(text)
        self._extract_tools(recent_messages)
        self._extract_signals(text)
        self._last_update = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")

        self._write()

    def get_context(self) -> str:
        """Return the current session notes, or empty string."""
        try:
            if self._path.exists():
                return self._path.read_text(encoding="utf-8")
        except Exception:
            pass
        return ""

    def clear(self) -> None:
        """Delete the session file and reset state."""
        try:
            self._path.unlink(missing_ok=True)
        except Exception:
            pass
        self.__init__(str(self._path))

    # ------------------------------------------------------------------
    # Extractors
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_text(messages: list[dict[str, Any]]) -> str:
        parts: list[str] = []
        for msg in messages:
            if not msg:
                continue
            c = msg.get("content")
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, list):
                for item in c:
                    if isinstance(item, dict):
                        parts.append(item.get("text") or item.get("content") or "")
                    elif isinstance(item, str):
                        parts.append(item)
        return "\n".join(parts)

    def _extract_target(self, text: str) -> None:
        if not self._target:
            m = _URL_RE.search(text)
            if m:
                self._target = m.group(1)
        if not self._resolved_ip:
            # Look for nmap-style "Nmap scan report for host (IP)"
            m = re.search(r"Nmap scan report for\s+\S+\s+\(([0-9.]+)\)", text)
            if m:
                self._resolved_ip = m.group(1)
            elif not self._resolved_ip:
                m = _IPV4_RE.search(text)
                if m:
                    self._resolved_ip = m.group(0)

    def _extract_ports(self, text: str) -> None:
        for m in _NMAP_PORT_RE.finditer(text):
            port = int(m.group(1))
            service = m.group(2).replace("ssl/", "")  # ssl/http → http
            version = (m.group(3) or "").strip()
            # Clean version: keep only alphanumeric + dots (drop nmap script artifacts)
            if version and not version[0].isalpha():
                version = ""
            self._ports[port] = f"{service} {version}".strip()

    def _extract_tech(self, text: str) -> None:
        lower = text.lower()
        for tech, signals in _TECH_SIGNALS.items():
            if any(sig in lower for sig in signals):
                self._tech.add(tech)

    def _extract_cves(self, text: str) -> None:
        self._cves.update(_CVE_RE.findall(text))

    def _extract_tools(self, messages: list[dict[str, Any]]) -> None:
        for msg in messages:
            if msg.get("role") != "assistant":
                continue
            for tc in msg.get("tool_calls") or []:
                name = (tc.get("function") or {}).get("name") or ""
                if name and name not in self._tools_run:
                    self._tools_run.append(name)

    def _extract_signals(self, text: str) -> None:
        for pat in _SHELL_SIGNALS:
            if re.search(pat, text, re.I):
                self._shell_gained = True
                if "Shell gained" not in self._findings:
                    self._findings.append("Shell gained")
                break
        for pat in _FLAG_SIGNALS:
            if re.search(pat, text):
                self._flag_found = True
                if "Flag found" not in self._findings:
                    self._findings.append("Flag found")
                break

    # ------------------------------------------------------------------
    # Writer
    # ------------------------------------------------------------------

    def _write(self) -> None:
        """Write session state as a Magic Doc (auto-updating security report)."""
        target_display = self._target or "Unknown"
        ip_display = f" ({self._resolved_ip})" if self._resolved_ip else ""

        lines = [
            f"# MAGIC DOC: Security Assessment — {target_display}",
            "",
            f"*Auto-updated by Kryon — last: {self._last_update or 'N/A'}*",
            "",
        ]

        # Target section
        lines.append("## Target")
        if self._target:
            lines.append(f"- **Host:** {self._target}{ip_display}")
        if self._tech:
            lines.append(f"- **Stack:** {', '.join(sorted(self._tech))}")
        lines.append("")

        # Ports table
        if self._ports:
            lines.append("## Open Ports")
            lines.append("")
            lines.append("| Port | Service |")
            lines.append("|------|---------|")
            for port in sorted(self._ports):
                lines.append(f"| {port} | {self._ports[port]} |")
            lines.append("")

        # CVEs
        if self._cves:
            lines.append("## CVEs Detected")
            lines.append("")
            for cve in sorted(self._cves):
                lines.append(f"- {cve}")
            lines.append("")

        # Findings
        if self._findings:
            lines.append("## Key Findings")
            lines.append("")
            for f in self._findings:
                lines.append(f"- {f}")
            lines.append("")

        # Status
        if self._shell_gained:
            lines.append("## Status: COMPROMISED")
            lines.append("")
            lines.append("Shell access obtained on target.")
            lines.append("")
        elif self._flag_found:
            lines.append("## Status: FLAG CAPTURED")
            lines.append("")

        # Tools chain
        if self._tools_run:
            lines.append("## Tools Executed")
            lines.append("")
            lines.append(f"{' → '.join(self._tools_run)}")
            lines.append("")

        # Recommendations (auto-generated from findings)
        recommendations = self._generate_recommendations()
        if recommendations:
            lines.append("## Recommendations")
            lines.append("")
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except Exception as e:
            logger.warning("session_memory write failed: %s", e)

    def _generate_recommendations(self) -> list[str]:
        """Auto-generate recommendations based on extracted findings."""
        recs: list[str] = []
        # Flatten ports + services into a single searchable string
        all_services = " ".join(f"{p} {v}" for p, v in self._ports.items()).lower() if self._ports else ""
        port_numbers = set(self._ports.keys()) if self._ports else set()

        # Email services open → check SPF/DKIM/DMARC
        if any(p in port_numbers for p in [110, 143, 993, 995, 25, 465, 587]) or "pop3" in all_services or "imap" in all_services or "smtp" in all_services:
            recs.append("Configure SPF, DKIM and DMARC records for email security")

        # Apache/nginx without version hiding
        if "apache" in self._tech or "nginx" in self._tech:
            recs.append("Hide server version in HTTP response headers")

        # CVEs found
        if self._cves:
            recs.append(f"Patch {len(self._cves)} identified CVE(s) immediately")

        # WordPress detected
        if "wordpress" in self._tech:
            recs.append("Audit WordPress plugins and themes for known vulnerabilities")
            recs.append("Disable XML-RPC if not needed (xmlrpc.php)")

        # SSH exposed
        if 22 in port_numbers or 2222 in port_numbers or "ssh" in all_services or "openssh" in all_services:
            recs.append("Disable root login via SSH and enforce key-based authentication")

        # No findings at all
        if not recs and self._tools_run:
            recs.append("Run deeper directory brute force for .bak, .old, .env files")
            recs.append("Perform authenticated testing if credentials are available")

        return recs


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_instance: SessionMemory | None = None


def get_session_memory() -> SessionMemory:
    """Return the global SessionMemory singleton."""
    global _instance
    if _instance is None:
        _instance = SessionMemory()
    return _instance
