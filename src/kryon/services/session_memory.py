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
_NMAP_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?", re.M)
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
            service = m.group(2)
            version = (m.group(3) or "").strip()
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
        lines = ["# KRYON Session State", ""]

        if self._target:
            lines.append(f"**Target:** {self._target}")
        if self._resolved_ip:
            lines.append(f"**IP:** {self._resolved_ip}")

        if self._ports:
            lines.append("")
            lines.append("## Open Ports")
            lines.append("| Port | Service |")
            lines.append("|------|---------|")
            for port in sorted(self._ports):
                lines.append(f"| {port} | {self._ports[port]} |")

        if self._tech:
            lines.append("")
            lines.append(f"**Tech detected:** {', '.join(sorted(self._tech))}")

        if self._cves:
            lines.append("")
            lines.append(f"**CVEs found:** {', '.join(sorted(self._cves))}")

        if self._findings:
            lines.append("")
            lines.append("## Key Findings")
            for f in self._findings:
                lines.append(f"- {f}")

        if self._tools_run:
            lines.append("")
            lines.append(f"**Tools executed:** {' → '.join(self._tools_run)}")

        if self._shell_gained:
            lines.append("")
            lines.append("**Status:** 🔴 Shell access obtained")
        elif self._flag_found:
            lines.append("")
            lines.append("**Status:** 🟢 Flag captured")

        if self._last_update:
            lines.append("")
            lines.append(f"*Last updated: {self._last_update}*")

        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except Exception as e:
            logger.warning("session_memory write failed: %s", e)


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
