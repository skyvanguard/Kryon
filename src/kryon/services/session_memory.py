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

import hashlib
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SESSION_FILE = os.environ.get("KRYON_SESSION_FILE", "/workspace/.kryon_session.md")

# Re-injection cap — Magic Doc was being re-injected 39x per session (24% of
# context = pure noise, caused drift + verbatim repeats). See ZERO_DAY_ROADMAP
# fix R2. Return empty context once the limit is hit OR when content hash is
# unchanged since the last injection.
_MAX_INJECTIONS = int(os.environ.get("KRYON_SM_MAX_INJECTIONS", "5"))

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
        # Credentials & loot are THE foothold — they must survive auto-compaction,
        # so they live in the durable Magic Doc (the model loses them from history).
        self._creds: list[str] = []
        self._loot: list[str] = []
        self._shell_gained = False
        self._flag_found = False
        self._last_update: str | None = None
        # Injection dedup state (fix R2)
        self._last_injected_hash: str | None = None
        self._injection_count: int = 0
        # T4-M1: how many history messages were already extracted. The caller passes
        # the FULL message_history every turn; without this offset update() re-scans
        # the entire transcript each call → O(n²) over a session. Extraction is
        # idempotent (sets / _add_unique / `if not self._target`), so processing only
        # the delta is safe.
        self._processed_count: int = 0

    def update(self, recent_messages: list[dict[str, Any]]) -> None:
        """Extract facts from the messages added since the last update and rewrite
        the file. Only the delta is scanned (T4-M1) — the caller hands us the full
        history each turn, so re-scanning all of it would be O(n²)."""
        total = len(recent_messages)
        # A shrunk/replaced history (compaction) → reprocess from the start.
        start = self._processed_count if 0 <= self._processed_count <= total else 0
        delta = recent_messages[start:]
        self._processed_count = total

        text = self._collect_text(delta)
        if not text.strip():
            return

        # Snapshot material state so a NEW foothold (cred/hash/shell/flag) can reset
        # the injection cap — otherwise the Magic Doc goes mute after 5 updates and
        # never re-injects the credentials the model needs 10 turns later.
        _before = (len(self._creds), len(self._loot), self._shell_gained, self._flag_found)

        self._extract_target(text)
        self._extract_ports(text)
        self._extract_tech(text)
        self._extract_cves(text)
        self._extract_tools(delta)
        self._extract_signals(text)
        self._extract_loot(text)
        self._last_update = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")

        _after = (len(self._creds), len(self._loot), self._shell_gained, self._flag_found)
        if _after != _before:
            self._injection_count = 0  # material progress → allow re-injection

        self._write()

    # Confirmed creds (user:pass, comma or backslash form) and loot (hashes/keys).
    _CRED_PAIR_RE = re.compile(r"Username:\s*([^\s,|]{1,64})\s*,\s*Password:\s*([^\s|]{1,128})", re.IGNORECASE)
    # AD form DOMAIN\user:pass only (backslash) — a '/' would match http://host:port.
    _CRED_COLON_RE = re.compile(r"\\([A-Za-z0-9._-]{1,64}):([^\s:|/]{2,128})")
    _NTLM_LOOT_RE = re.compile(r"\b([A-Za-z0-9._$-]+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::)")
    _KRB5_LOOT_RE = re.compile(r"\$krb5(?:asrep|tgs)\$[0-9A-Za-z*$./:_+@-]+")
    _SHADOW_LOOT_RE = re.compile(r"^([a-z_][a-z0-9_-]*:\$(?:1|2[aby]?|5|6|y)\$[^\s:]+)", re.MULTILINE)

    def _extract_loot(self, text: str) -> None:
        for m in self._CRED_PAIR_RE.finditer(text):
            self._add_unique(self._creds, f"{m.group(1)}:{m.group(2)}")
        for m in self._CRED_COLON_RE.finditer(text):
            self._add_unique(self._creds, f"{m.group(1)}:{m.group(2)}")
        for rx in (self._NTLM_LOOT_RE, self._KRB5_LOOT_RE, self._SHADOW_LOOT_RE):
            for m in rx.finditer(text):
                self._add_unique(self._loot, m.group(0) if rx is self._KRB5_LOOT_RE else m.group(1))

    @staticmethod
    def _add_unique(bucket: list[str], value: str, limit: int = 50) -> None:
        if value and value not in bucket and len(bucket) < limit:
            bucket.append(value)

    def get_context(self) -> str:
        """Return the current session notes, or empty string.

        Applies R2 dedup: returns "" if the content hash hasn't changed since
        the last injection, or if the per-session injection cap was reached.
        This prevents the Magic Doc from being re-injected verbatim every turn
        (observed 39x in a single engagement, 24% of context = noise).
        """
        try:
            if not self._path.exists():
                return ""
            content = self._path.read_text(encoding="utf-8")
        except Exception:
            return ""

        if not content.strip():
            return ""

        # Hard cap — after N injections the model has seen enough.
        if self._injection_count >= _MAX_INJECTIONS:
            logger.debug(
                "session_memory: injection cap reached (%d), skipping",
                _MAX_INJECTIONS,
            )
            return ""

        # Hash dedup — only re-inject if content actually changed.
        current_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if current_hash == self._last_injected_hash:
            logger.debug("session_memory: content unchanged, skipping re-inject")
            return ""

        self._last_injected_hash = current_hash
        self._injection_count += 1
        return content

    def reset_injection_state(self) -> None:
        """Reset the injection cap + hash (e.g. on /flush or new engagement)."""
        self._last_injected_hash = None
        self._injection_count = 0

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

        # Credentials & loot — the foothold that must survive compaction.
        if self._creds or self._loot:
            lines.append("## Credentials & Loot")
            lines.append("")
            for c in self._creds:
                lines.append(f"- **cred:** `{c}`")
            for h in self._loot:
                lines.append(f"- **loot:** `{h}`")
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
        if (
            any(p in port_numbers for p in [110, 143, 993, 995, 25, 465, 587])
            or "pop3" in all_services
            or "imap" in all_services
            or "smtp" in all_services
        ):
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
