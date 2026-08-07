"""Map a Cinc Auditor JSON report → Kryon ``engage.Finding``.

Semantics:
* A Finding is a *problem*, so we emit one only for controls that have at
  least one **failed** result (passed/skipped controls are not findings).
* `impact` (0.0-1.0) → severity band (InSpec convention).
* Cinc controls are deterministic config assertions (they read the actual
  config), so confidence = 1.0 and needs_verification = False — the same
  category as Kryon's own hand-rolled checks, unlike OpenVAS remote probes.
* rule_id = ``CINC-<control-id>`` — not CVE-shaped, so it passes the CVE gate
  and is filtered by the general product gate instead.
"""

from __future__ import annotations

import json

from kryon.cli.engage import Finding, make_finding
from kryon.validation.cve_applicability import is_cve_applicable_for_finding
from kryon.validation.finding_applicability import is_finding_applicable_general


def impact_to_severity(impact: float) -> str:
    if impact >= 0.9:
        return "CRITICAL"
    if impact >= 0.7:
        return "HIGH"
    if impact >= 0.4:
        return "MEDIUM"
    if impact > 0.0:
        return "LOW"
    return "INFO"


def _cwe_of(tags: dict) -> str:
    val = (tags or {}).get("cwe")
    if isinstance(val, (list, tuple)):
        val = val[0] if val else None
    return str(val) if val else "CINC"


def parse_controls(json_str: str) -> list[dict]:
    """Flatten a Cinc JSON report into one dict per control."""
    data = json.loads(json_str)
    out: list[dict] = []
    for prof in data.get("profiles", []) or []:
        pname = prof.get("name", "") or ""
        for ctrl in prof.get("controls", []) or []:
            results = ctrl.get("results", []) or []
            failed = [r for r in results if r.get("status") == "failed"]
            try:
                impact = float(ctrl.get("impact", 0.0) or 0.0)
            except (TypeError, ValueError):
                impact = 0.0
            out.append(
                {
                    "id": ctrl.get("id", "") or "",
                    "title": ctrl.get("title", "") or "",
                    "desc": ctrl.get("desc", "") or "",
                    "impact": impact,
                    "cwe": _cwe_of(ctrl.get("tags") or {}),
                    "profile": pname,
                    "failed": failed,
                    "any_failed": bool(failed),
                }
            )
    return out


def _evidence(failed: list[dict]) -> str:
    parts = []
    for r in failed:
        desc = (r.get("code_desc", "") or "").strip()
        msg = (r.get("message", "") or "").strip()
        parts.append(f"{desc} — {msg}" if msg else desc)
    return "; ".join(p for p in parts if p)[:2000]


def results_to_findings(
    json_str: str,
    *,
    host: str = "",
    tech_stack: set[str] | None = None,
    apply_gates: bool = True,
) -> list[Finding]:
    """Cinc JSON → Findings for FAILED controls, filtered by the gates.

    The report doesn't reliably carry the connection host, so the caller
    supplies it. Gates are conservative (pass without positive evidence).
    """
    stack = tech_stack or set()
    findings: list[Finding] = []
    for c in parse_controls(json_str):
        if not c["any_failed"]:
            continue
        rule_id = f"CINC-{c['id']}" if c["id"] else "CINC-control"
        message = f"{c['title']} [{c['profile']}]" if c["profile"] else c["title"]
        finding = make_finding(
            cwe=c["cwe"],
            severity=impact_to_severity(c["impact"]),
            host=host,
            rule_id=rule_id,
            message=message or rule_id,
            evidence=_evidence(c["failed"]) or "(cinc control failed)",
            remediation=c["desc"][:1000],
            confidence=1.0,
            needs_verification=False,
            source="cinc",
        )
        if apply_gates:
            cve_ok, _ = is_cve_applicable_for_finding(finding, tech_stack=stack)
            if not cve_ok:
                continue
            gen_ok, _ = is_finding_applicable_general(finding, tech_stack=stack)
            if not gen_ok:
                continue
        findings.append(finding)
    return findings
