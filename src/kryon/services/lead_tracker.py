"""
Lead Tracker — pending-lead detection and persistence.

Fix R4 from ZERO_DAY_ROADMAP. In the baseline session (example.com,
session 74732376) Kryon found `/config -> 301` and `error_log -> 403` and
simply dropped them. A "lead" is any tool output that implies a follow-up
action but doesn't conclusively close the attack surface.

After each turn, `scan_for_leads()` inspects assistant tool calls + results
and extracts leads. `get_pending_summary()` renders them into a block that
is injected into the next system prompt, forcing the model to attend to
them. Once a lead is addressed (a follow-up tool call targeted it), it is
marked resolved.

No LLM calls. Pure regex + heuristics.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Lead:
    """A pending investigation target surfaced by heuristics."""

    kind: str  # "forbidden_path" | "redirect" | "banner" | "hidden_file" | "error_leak"
    target: str  # URL, path, file, or identifier
    hint: str  # Suggested next action
    source_tool: str = ""  # Tool call that surfaced this lead
    resolved: bool = False  # True once a later turn touched this target

    def as_line(self) -> str:
        return f"- [{self.kind}] {self.target} — {self.hint}"


# ---------------------------------------------------------------------------
# Extractors — regex + patterns that identify each lead kind
# ---------------------------------------------------------------------------

# Interesting path names (when 403'd they're high-signal leads)
_INTERESTING_PATHS = {
    "admin",
    "administrator",
    "wp-admin",
    "manager",
    "console",
    "api",
    "graphql",
    "rest",
    "swagger",
    "api-docs",
    "uploads",
    "files",
    "upload",
    "media",
    "attachments",
    "config",
    "configuration",
    "settings",
    ".env",
    "env",
    "backup",
    "bak",
    "old",
    "dump",
    "sql",
    ".git",
    ".svn",
    ".hg",
    ".DS_Store",
    "private",
    "internal",
    "debug",
    "dev",
    "phpmyadmin",
    "pma",
    "adminer",
    "error_log",
    "errors.log",
    "access.log",
    "debug.log",
    "test",
    "staging",
    "beta",
    ".htaccess",
    ".htpasswd",
    "robots.txt",
}

# HTTP status code from curl -I / -v output
_HTTP_STATUS_RE = re.compile(r"HTTP/\d\.?\d?\s+(\d{3})\s*(.*?)(?:\r?\n|$)", re.I)
# Full URL + code patterns (e.g. "/admin => 403", "GET /foo 301")
_PATH_CODE_RE = re.compile(r"(?:GET\s+)?([/\w.\-]+?)\s*(?:=>|\-\-?>|\s+)\s*(200|201|301|302|307|401|403|500|502)\b")
# Location header (redirect targets)
_LOCATION_RE = re.compile(r"^Location:\s*(\S+)", re.I | re.M)
# Server banner
_SERVER_RE = re.compile(r"^Server:\s*(.+?)\r?$", re.I | re.M)
_X_POWERED_BY_RE = re.compile(r"^X-Powered-By:\s*(.+?)\r?$", re.I | re.M)
# Gobuster / dirb / feroxbuster line format: "/path (Status: 403)" or "200 /path"
_GOBUSTER_LINE_RE = re.compile(r"^(?:/?\S+?)\s+\(Status:\s*(\d{3})\)", re.M)
_GOBUSTER_PATH_RE = re.compile(r"(/\S+?)\s+\(Status:\s*(\d{3})\)", re.M)
# Error / stack trace leaks
_ERROR_LEAK_RE = re.compile(
    r"(Fatal error|Warning:|Notice:|Traceback|Exception in|PHP Warning|at line \d+)",
    re.I,
)
# Hidden file / directory discovered by extension brute
_HIDDEN_EXT_RE = re.compile(
    r"/(\S+?\.(bak|old|backup|sql|zip|tar\.gz|env|git|swp|orig|save))\b",
    re.I,
)


class LeadTracker:
    """Accumulates pending leads across turns and exposes them to the prompt."""

    MAX_LEADS = 15  # cap to avoid prompt bloat
    MAX_SUMMARY_CHARS = 1500

    def __init__(self) -> None:
        self._leads: list[Lead] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_for_leads(self, recent_messages: list[dict[str, Any]]) -> int:
        """Inspect recent messages; add new leads; mark touched ones resolved.

        Returns the number of new leads added.
        """
        # First pass: mark resolved any existing lead whose target appears
        # in a recent tool CALL (model actively investigating it).
        touched_targets = self._collect_tool_call_targets(recent_messages)
        for lead in self._leads:
            if lead.resolved:
                continue
            if any(lead.target in t or t in lead.target for t in touched_targets):
                lead.resolved = True

        # Second pass: extract new leads from tool RESULTS.
        before = len(self._leads)
        for msg in recent_messages:
            role = msg.get("role")
            if role != "tool":
                continue
            content = self._extract_content(msg)
            if not content:
                continue
            for lead in self._detect(content, source_tool=msg.get("name", "")):
                if not self._is_duplicate(lead):
                    self._leads.append(lead)
                    if len(self._leads) >= self.MAX_LEADS:
                        return len(self._leads) - before
        return len(self._leads) - before

    def get_pending_summary(self) -> str:
        """Render unresolved leads as a prompt block (or empty string)."""
        pending = [ld for ld in self._leads if not ld.resolved]
        if not pending:
            return ""
        lines = [
            "## PENDING LEADS (follow up before finalize)",
            "",
            "These were surfaced by prior tool calls and have NOT been",
            "investigated. Call tools to resolve them in this turn:",
            "",
        ]
        for ld in pending[: self.MAX_LEADS]:
            lines.append(ld.as_line())
        summary = "\n".join(lines)
        if len(summary) > self.MAX_SUMMARY_CHARS:
            summary = summary[: self.MAX_SUMMARY_CHARS] + "\n... (truncated)"
        return summary

    def pending_count(self) -> int:
        return sum(1 for ld in self._leads if not ld.resolved)

    def clear(self) -> None:
        self._leads = []

    def all_leads(self) -> list[Lead]:
        return list(self._leads)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_content(msg: dict[str, Any]) -> str:
        c = msg.get("content")
        if isinstance(c, str):
            return c
        if isinstance(c, list):
            parts: list[str] = []
            for item in c:
                if isinstance(item, dict):
                    parts.append(item.get("text") or item.get("content") or "")
                elif isinstance(item, str):
                    parts.append(item)
            return "\n".join(parts)
        return ""

    @staticmethod
    def _collect_tool_call_targets(messages: list[dict[str, Any]]) -> set[str]:
        """Extract strings that look like targets from tool call arguments."""
        targets: set[str] = set()
        for msg in messages:
            if msg.get("role") != "assistant":
                continue
            for tc in msg.get("tool_calls") or []:
                args = (tc.get("function") or {}).get("arguments") or ""
                if isinstance(args, str):
                    # pull URLs and path fragments
                    for m in re.finditer(r"(?:https?://[^\s\"']+|/[A-Za-z0-9._\-/]+)", args):
                        targets.add(m.group(0))
        return targets

    def _is_duplicate(self, new: Lead) -> bool:
        for existing in self._leads:
            if existing.kind == new.kind and existing.target == new.target:
                return True
        return False

    def _detect(self, content: str, *, source_tool: str = "") -> list[Lead]:
        """Run all extractors on a single tool result."""
        leads: list[Lead] = []

        # 1. Gobuster-style status line
        for m in _GOBUSTER_PATH_RE.finditer(content):
            path, code = m.group(1), int(m.group(2))
            leads.extend(self._classify_status(path, code, source_tool))

        # 2. "path => CODE" or "GET /x 301" style
        for m in _PATH_CODE_RE.finditer(content):
            path, code = m.group(1), int(m.group(2))
            leads.extend(self._classify_status(path, code, source_tool))

        # 3. Location header (redirect target always worth following)
        for m in _LOCATION_RE.finditer(content):
            target = m.group(1).strip()
            leads.append(
                Lead(
                    kind="redirect",
                    target=target,
                    hint="follow redirect with curl -L or GET the destination",
                    source_tool=source_tool,
                )
            )

        # 4. Server / X-Powered-By banners (version fingerprint → CVE lookup)
        for m in _SERVER_RE.finditer(content):
            banner = m.group(1).strip()
            if self._banner_has_version(banner):
                leads.append(
                    Lead(
                        kind="banner",
                        target=banner,
                        hint="searchsploit / nuclei this version for known CVEs",
                        source_tool=source_tool,
                    )
                )
        for m in _X_POWERED_BY_RE.finditer(content):
            banner = m.group(1).strip()
            if self._banner_has_version(banner):
                leads.append(
                    Lead(
                        kind="banner",
                        target=banner,
                        hint="check known vulns for this stack version",
                        source_tool=source_tool,
                    )
                )

        # 5. Hidden file extensions found
        for m in _HIDDEN_EXT_RE.finditer(content):
            path = "/" + m.group(1)
            leads.append(
                Lead(
                    kind="hidden_file",
                    target=path,
                    hint="download with curl; inspect for secrets/backup",
                    source_tool=source_tool,
                )
            )

        # 6. Error / stack trace leak
        if _ERROR_LEAK_RE.search(content):
            # Capture a short snippet to help the model know what to probe
            snippet = _ERROR_LEAK_RE.search(content).group(0)
            leads.append(
                Lead(
                    kind="error_leak",
                    target=snippet[:60],
                    hint="induce more errors (bad input) to map backend stack",
                    source_tool=source_tool,
                )
            )

        return leads

    @staticmethod
    def _classify_status(path: str, code: int, source_tool: str) -> list[Lead]:
        """Turn a (path, status_code) into 0-1 leads depending on significance."""
        # Strip query string for name match
        name = path.rstrip("/").split("/")[-1].lower()
        is_interesting = name in _INTERESTING_PATHS or any(p in path.lower() for p in _INTERESTING_PATHS)

        if code == 403 and is_interesting:
            return [
                Lead(
                    kind="forbidden_path",
                    target=path,
                    hint="file exists — try path traversal, verb tampering, auth bypass",
                    source_tool=source_tool,
                )
            ]
        if code in (301, 302, 307):
            return [
                Lead(
                    kind="redirect",
                    target=path,
                    hint="follow redirect; check if auth wall or leaks location",
                    source_tool=source_tool,
                )
            ]
        if code == 401:
            return [
                Lead(
                    kind="auth_wall",
                    target=path,
                    hint="try default creds, auth bypass, or look for registration",
                    source_tool=source_tool,
                )
            ]
        if code == 500 or code == 502:
            return [
                Lead(
                    kind="error_leak",
                    target=path,
                    hint="server crash — try fuzzing this endpoint for more info",
                    source_tool=source_tool,
                )
            ]
        if code == 200 and is_interesting:
            return [
                Lead(
                    kind="accessible_sensitive",
                    target=path,
                    hint="sensitive path is 200 — curl and inspect content",
                    source_tool=source_tool,
                )
            ]
        return []

    @staticmethod
    def _banner_has_version(banner: str) -> bool:
        return bool(re.search(r"\d+\.\d+", banner))


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_instance: LeadTracker | None = None


def get_lead_tracker() -> LeadTracker:
    global _instance
    if _instance is None:
        _instance = LeadTracker()
    return _instance


def reset_lead_tracker() -> None:
    global _instance
    _instance = LeadTracker()
