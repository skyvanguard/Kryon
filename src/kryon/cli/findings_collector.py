"""Extracts and persists findings from CLI agent interactions."""

from __future__ import annotations

import json
import logging
import re
import uuid

from kryon.intelligence.models import Finding, Severity
from kryon.memory.models import FindingRecord

logger = logging.getLogger(__name__)

_CLI_CLIENT_ID = "cli-session"
_SEVERITY_KEYWORDS = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}
_FINDING_SIGNALS = ("vulnerability", "cve-", "exploit", "finding", "vuln")


class CLIFindingsCollector:
    """Collects findings from agent message history and persists them."""

    def __init__(self, store: object | None = None):
        self._store = store
        self._scan_id = uuid.uuid4().hex[:12]
        self._seen_ids: set[str] = set()

    @property
    def store(self):
        """Lazy-load MemoryStore."""
        if self._store is None:
            from kryon.memory.store import MemoryStore

            self._store = MemoryStore()
        return self._store

    @property
    def scan_id(self) -> str:
        return self._scan_id

    def extract_from_message_history(self, messages: list[dict]) -> list[Finding]:
        """Scan message history for tool outputs containing finding-like data."""
        findings: list[Finding] = []
        for msg in messages:
            content = msg.get("content", "")
            if not isinstance(content, str):
                continue
            if not any(kw in content.lower() for kw in _FINDING_SIGNALS):
                continue
            for finding in self._try_parse_findings(content):
                # Dedup by title+asset+description (IDs are random per parse). title+asset
                # alone collapsed DISTINCT findings whenever affected_asset defaulted to
                # "unknown" (e.g. two different issues parsed from the same blob) — the
                # description discriminates so real findings aren't lost.
                dedup_key = f"{finding.title}|{finding.affected_asset}|{(getattr(finding, 'description', '') or '')[:200]}"
                if dedup_key not in self._seen_ids:
                    findings.append(finding)
                    self._seen_ids.add(dedup_key)
        return findings

    def save_findings(self, findings: list[Finding]) -> int:
        """Persist findings to SQLite. Returns count saved."""
        saved = 0
        for f in findings:
            record = FindingRecord(
                scan_id=self._scan_id,
                client_id=_CLI_CLIENT_ID,
                finding_json=f.model_dump_json(),
                status="open",
            )
            self.store.save_finding(record)
            saved += 1
        return saved

    def _try_parse_findings(self, content: str) -> list[Finding]:
        """Best-effort parse of content into Finding objects."""
        findings: list[Finding] = []

        # Strategy 1: Try JSON — some tools output structured data
        findings.extend(self._parse_json_findings(content))
        if findings:
            return findings

        # Strategy 2: Look for CVE patterns in unstructured text
        finding = self._parse_cve_text(content)
        if finding:
            findings.append(finding)

        return findings

    def _parse_json_findings(self, content: str) -> list[Finding]:
        """Try to parse JSON objects that look like findings (supports nested objects)."""
        findings: list[Finding] = []
        # Find JSON blocks by tracking brace depth
        for start_pos in (m.start() for m in re.finditer(r"\{", content)):
            depth = 0
            for i in range(start_pos, min(start_pos + 2000, len(content))):
                if content[i] == "{":
                    depth += 1
                elif content[i] == "}":
                    depth -= 1
                    if depth == 0:
                        candidate = content[start_pos : i + 1]
                        if len(candidate) < 20:
                            break
                        try:
                            data = json.loads(candidate)
                            if isinstance(data, dict) and "title" in data and ("severity" in data or "cvss" in data):
                                finding = Finding(
                                    title=data.get("title", "Parsed Finding"),
                                    description=data.get("description", ""),
                                    severity=_SEVERITY_KEYWORDS.get(
                                        str(data.get("severity", "info")).lower(),
                                        Severity.INFO,
                                    ),
                                    cvss_score=data.get("cvss_score") or data.get("cvss"),
                                    affected_asset=data.get("affected_asset", data.get("target", "unknown")),
                                    tool_source=data.get("tool_source", "cli-parsed"),
                                    evidence=candidate[:500],
                                )
                                findings.append(finding)
                        except (json.JSONDecodeError, ValueError):
                            pass
                        break
        return findings

    def _parse_cve_text(self, content: str) -> Finding | None:
        """Extract a finding from text containing CVE references."""
        cve_match = re.search(r"(CVE-\d{4}-\d{4,7})", content, re.IGNORECASE)
        if not cve_match:
            return None

        cve_id = cve_match.group(1).upper()

        # Try to determine severity from surrounding text
        severity = Severity.INFO
        content_lower = content.lower()
        for kw, sev in _SEVERITY_KEYWORDS.items():
            if kw in content_lower:
                severity = sev
                break

        # Extract a description snippet around the CVE mention
        start = max(0, cve_match.start() - 100)
        end = min(len(content), cve_match.end() + 200)
        snippet = content[start:end].strip()

        return Finding(
            title=f"{cve_id} detected",
            description=snippet[:500],
            severity=severity,
            affected_asset="unknown",
            tool_source="cli-parsed",
            evidence=snippet[:500],
        )
