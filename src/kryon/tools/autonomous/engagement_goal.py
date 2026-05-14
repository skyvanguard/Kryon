"""F118 — Goal-directed reasoning.

Lets the operator declare *what success looks like* up front so the
orchestrator can:

  - terminate early on success (instead of running every phase blindly)
  - emit a final verdict (SATISFIED / PARTIAL / NOT_MET) with evidence

Four goal kinds are supported deterministically:

  COMPLIANCE   — "audit PCI-DSS against X". Success = at least
                 ``min_controls_evaluated`` findings tagged with the
                 framework's rule_id prefix.
  VULN_SEARCH  — "find RCE/SQLi/XSS on X". Success = at least one
                 HIGH/CRITICAL finding whose text matches the requested
                 vuln types.
  RECON        — "enumerate attack surface of X". Success = at least
                 ``min_services`` distinct service findings.
  CUSTOM       — fallback. Success = any HIGH/CRITICAL finding.

parse_objective() is a heuristic NL→goal parser. It is intentionally
narrow (regex + keyword matching) — no LLM in the parse path so the
operator can audit how their objective was interpreted before running.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class GoalKind(str, Enum):
    COMPLIANCE = "compliance"
    VULN_SEARCH = "vuln_search"
    RECON = "recon"
    CUSTOM = "custom"


class EngagementVerdict(str, Enum):
    SATISFIED = "satisfied"
    PARTIAL = "partial"
    NOT_MET = "not_met"


@dataclass(frozen=True)
class EngagementGoal:
    """Declarative goal handed to the orchestrator. ``params`` is
    kind-specific (see module docstring)."""

    kind: GoalKind
    raw: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GoalProgress:
    """Outcome of evaluating a goal against current findings."""

    verdict: EngagementVerdict
    satisfied: bool
    reasoning: str
    evidence: tuple[Any, ...] = field(default_factory=tuple)
    controls_evaluated: int = 0
    services_enumerated: int = 0

    def should_terminate_early(self) -> bool:
        return self.satisfied

    def summary(self) -> str:
        lines = [f"Goal: {self.verdict.value} ({'satisfied' if self.satisfied else 'open'})"]
        lines.append(f"  reason: {self.reasoning}")
        if self.evidence:
            evidence_ids = ", ".join(getattr(e, "rule_id", "?") for e in self.evidence[:5])
            lines.append(f"  evidence ({len(self.evidence)}): {evidence_ids}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# parse_objective
# ---------------------------------------------------------------------------


_COMPLIANCE_FRAMEWORKS = (
    "PCI-DSS",
    "PCI DSS",
    "HIPAA",
    "SOC2",
    "SOC 2",
    "NIST",
    "ISO 27001",
    "ISO27001",
    "GDPR",
    "OWASP",
    "CIS",
    "MITRE",
)

_VULN_KEYWORDS = {
    "rce": ("rce", "remote code execution", "code execution"),
    "sqli": ("sqli", "sql injection"),
    "xss": ("xss", "cross-site scripting", "cross site scripting"),
    "ssrf": ("ssrf", "server-side request forgery"),
    "xxe": ("xxe", "xml external entity"),
    "lfi": ("lfi", "local file inclusion", "path traversal"),
    "open_redirect": ("open redirect", "open-redirect"),
    "smuggling": ("smuggling", "request smuggling"),
    "csrf": ("csrf", "cross-site request forgery"),
    "auth_bypass": ("auth bypass", "authentication bypass", "authn bypass"),
}

_RECON_KEYWORDS = (
    "enumerate",
    "enumerar",
    "attack surface",
    "superficie de ataque",
    "fingerprint",
    "discover",
    "reconnaissance",
    "recon",
)


def _detect_compliance(text: str) -> dict[str, Any] | None:
    """Return params dict if text describes a compliance audit, else None."""
    text_upper = text.upper()
    if "COMPLIANCE" not in text_upper and "AUDIT" not in text_upper and "EVALUAR" not in text_upper:
        return None
    for fw in _COMPLIANCE_FRAMEWORKS:
        if fw.upper() in text_upper:
            # Normalise framework name (PCI DSS → PCI-DSS).
            normalised = fw.replace(" ", "-").upper()
            return {"framework": normalised, "min_controls_evaluated": 1}
    return None


def _detect_vuln_types(text: str) -> list[str]:
    text_lower = text.lower()
    hits: list[str] = []
    for canonical, aliases in _VULN_KEYWORDS.items():
        if any(alias in text_lower for alias in aliases):
            hits.append(canonical)
    return hits


def _detect_recon(text: str) -> bool:
    text_lower = text.lower()
    return any(kw in text_lower for kw in _RECON_KEYWORDS)


def parse_objective(text: str) -> EngagementGoal:
    """Heuristic natural-language → EngagementGoal parser.

    The order matters: a phrase like *"audit PCI-DSS to find RCE"* will
    match COMPLIANCE first, because in practice compliance scope is
    narrower than freeform vuln-hunting and operators usually pick one
    or the other up front.
    """
    raw = (text or "").strip()

    # 1) compliance — narrow, framework-bound
    compliance_params = _detect_compliance(raw)
    if compliance_params is not None:
        return EngagementGoal(kind=GoalKind.COMPLIANCE, raw=raw, params=compliance_params)

    # 2) vuln search — explicit vuln types
    vuln_types = _detect_vuln_types(raw)
    if vuln_types:
        # Find verbs imply "search" intent; nouns alone don't.
        intent_verbs = ("find", "look for", "search", "buscar", "encontrar", "hunt for")
        text_lower = raw.lower()
        if any(v in text_lower for v in intent_verbs):
            return EngagementGoal(
                kind=GoalKind.VULN_SEARCH,
                raw=raw,
                params={"vuln_types": vuln_types},
            )

    # 3) recon
    if _detect_recon(raw):
        return EngagementGoal(
            kind=GoalKind.RECON,
            raw=raw,
            params={"min_services": 3},
        )

    # 4) custom fallback
    return EngagementGoal(kind=GoalKind.CUSTOM, raw=raw, params={})


# ---------------------------------------------------------------------------
# GoalEvaluator
# ---------------------------------------------------------------------------


def _finding_text(finding: Any) -> str:
    parts: list[str] = []
    for attr in ("rule_id", "title", "description", "evidence", "message"):
        val = getattr(finding, attr, "")
        if val:
            parts.append(str(val))
    return " ".join(parts).lower()


def _severity_lower(finding: Any) -> str:
    sev = getattr(finding, "severity", None)
    if sev is None:
        return ""
    return str(getattr(sev, "value", sev)).lower()


_SEVERE = frozenset({"critical", "high"})


_SERVICE_PORT_RE = re.compile(r"\bport\s+(\d{1,5})(?:/\w+)?\b", re.IGNORECASE)


class GoalEvaluator:
    """Deterministic goal progress evaluator. Pure: no I/O, no LLM."""

    def evaluate(self, goal: EngagementGoal, findings: list[Any]) -> GoalProgress:
        if goal.kind is GoalKind.COMPLIANCE:
            return self._eval_compliance(goal, findings)
        if goal.kind is GoalKind.VULN_SEARCH:
            return self._eval_vuln_search(goal, findings)
        if goal.kind is GoalKind.RECON:
            return self._eval_recon(goal, findings)
        return self._eval_custom(goal, findings)

    # -- compliance -----------------------------------------------------------

    def _eval_compliance(self, goal: EngagementGoal, findings: list[Any]) -> GoalProgress:
        framework = str(goal.params.get("framework", "")).upper()
        min_controls = int(goal.params.get("min_controls_evaluated", 1))

        # Framework rule_id prefix: PCI-DSS → PCI-, HIPAA → HIPAA-, etc.
        # We accept either "<FW>-" or the framework name in finding text.
        prefix_short = framework.split("-")[0] if framework else ""
        matching: list[Any] = []
        for f in findings:
            rule_id = str(getattr(f, "rule_id", "")).upper()
            if framework and (rule_id.startswith(framework + "-") or rule_id.startswith(prefix_short + "-")):
                matching.append(f)
                continue
            text_upper = _finding_text(f).upper()
            if framework and framework in text_upper:
                matching.append(f)

        evaluated = len(matching)
        if evaluated >= min_controls:
            return GoalProgress(
                verdict=EngagementVerdict.SATISFIED,
                satisfied=True,
                reasoning=f"{evaluated} {framework} controls evaluated (>= {min_controls})",
                evidence=tuple(matching),
                controls_evaluated=evaluated,
            )
        if evaluated > 0:
            return GoalProgress(
                verdict=EngagementVerdict.PARTIAL,
                satisfied=False,
                reasoning=f"{evaluated}/{min_controls} {framework} controls evaluated",
                evidence=tuple(matching),
                controls_evaluated=evaluated,
            )
        return GoalProgress(
            verdict=EngagementVerdict.NOT_MET,
            satisfied=False,
            reasoning=f"no findings tagged with {framework}",
            controls_evaluated=0,
        )

    # -- vuln search ----------------------------------------------------------

    def _eval_vuln_search(self, goal: EngagementGoal, findings: list[Any]) -> GoalProgress:
        wanted = [v.lower() for v in goal.params.get("vuln_types", [])]
        if not wanted:
            return GoalProgress(
                verdict=EngagementVerdict.NOT_MET,
                satisfied=False,
                reasoning="vuln_search goal had no vuln_types specified",
            )

        # Collect all findings whose text matches at least one wanted vuln type.
        text_matches: list[Any] = []
        for f in findings:
            text = _finding_text(f)
            for vt in wanted:
                aliases = _VULN_KEYWORDS.get(vt, (vt,))
                if any(alias in text for alias in aliases):
                    text_matches.append(f)
                    break

        if not text_matches:
            return GoalProgress(
                verdict=EngagementVerdict.NOT_MET,
                satisfied=False,
                reasoning=f"no findings match requested vuln types {wanted}",
            )

        severe = [f for f in text_matches if _severity_lower(f) in _SEVERE]
        if severe:
            return GoalProgress(
                verdict=EngagementVerdict.SATISFIED,
                satisfied=True,
                reasoning=f"{len(severe)} high/critical {wanted} finding(s) confirmed",
                evidence=tuple(severe),
            )
        return GoalProgress(
            verdict=EngagementVerdict.PARTIAL,
            satisfied=False,
            reasoning=f"{len(text_matches)} match(es) but none at HIGH/CRITICAL severity",
            evidence=tuple(text_matches),
        )

    # -- recon ----------------------------------------------------------------

    def _eval_recon(self, goal: EngagementGoal, findings: list[Any]) -> GoalProgress:
        min_services = int(goal.params.get("min_services", 1))
        ports_seen: set[str] = set()
        service_findings: list[Any] = []
        for f in findings:
            text = _finding_text(f)
            for m in _SERVICE_PORT_RE.finditer(text):
                port = m.group(1)
                if port not in ports_seen:
                    ports_seen.add(port)
                    service_findings.append(f)
                    break  # only count each finding once

        count = len(ports_seen)
        if count >= min_services:
            return GoalProgress(
                verdict=EngagementVerdict.SATISFIED,
                satisfied=True,
                reasoning=f"{count} distinct services enumerated (>= {min_services})",
                evidence=tuple(service_findings),
                services_enumerated=count,
            )
        if count > 0:
            return GoalProgress(
                verdict=EngagementVerdict.PARTIAL,
                satisfied=False,
                reasoning=f"{count}/{min_services} services enumerated",
                evidence=tuple(service_findings),
                services_enumerated=count,
            )
        return GoalProgress(
            verdict=EngagementVerdict.NOT_MET,
            satisfied=False,
            reasoning="no service-bearing findings yet",
        )

    # -- custom ---------------------------------------------------------------

    def _eval_custom(self, goal: EngagementGoal, findings: list[Any]) -> GoalProgress:
        severe = [f for f in findings if _severity_lower(f) in _SEVERE]
        if severe:
            return GoalProgress(
                verdict=EngagementVerdict.SATISFIED,
                satisfied=True,
                reasoning=f"{len(severe)} high/critical finding(s) — generic success criterion",
                evidence=tuple(severe),
            )
        return GoalProgress(
            verdict=EngagementVerdict.NOT_MET,
            satisfied=False,
            reasoning="no high/critical findings; custom goal has no domain-specific criterion",
        )
