"""Map a Lynis report.dat → Kryon ``engage.Finding``.

The report is key=value / key[]=value. We harvest two finding sources:
* ``warning[]=`` — real config weaknesses → MEDIUM, confidence 1.0, no verify.
* ``suggestion[]=`` — hardening recommendations (advisory, often opinionated /
  context-dependent) → LOW, confidence 0.7, needs_verification=True. Optional
  (they can be numerous) — controlled by the caller.

Each entry is ``TEST-ID|description|detail|solution`` (pipe-separated, variable
tail). rule_id = ``LYNIS-<TEST-ID>`` (non-CVE → passes the CVE gate, filtered by
the general product gate). Lynis gives no CWE → cwe="LYNIS".
"""

from __future__ import annotations

from kryon.cli.engage import Finding, make_finding
from kryon.validation.cve_applicability import is_cve_applicable_for_finding
from kryon.validation.finding_applicability import is_finding_applicable_general


def parse_report(dat: str) -> dict:
    """Extract warnings, suggestions and the hardening index from report.dat."""
    warnings: list[str] = []
    suggestions: list[str] = []
    hardening_index: int | None = None
    for raw in dat.splitlines():
        line = raw.strip()
        if line.startswith("warning[]="):
            warnings.append(line[len("warning[]=") :])
        elif line.startswith("suggestion[]="):
            suggestions.append(line[len("suggestion[]=") :])
        elif line.startswith("hardening_index="):
            try:
                hardening_index = int(line.split("=", 1)[1])
            except ValueError:
                pass
    return {"warnings": warnings, "suggestions": suggestions, "hardening_index": hardening_index}


def _entry_fields(entry: str) -> tuple[str, str]:
    """(test_id, description) from a `TEST-ID|description|...` entry."""
    parts = entry.split("|")
    test_id = parts[0].strip() if parts else ""
    desc = parts[1].strip() if len(parts) > 1 and parts[1].strip() else test_id
    return test_id, desc


def _make(host: str, entry: str, *, severity: str, confidence: float, needs_verification: bool) -> Finding:
    test_id, desc = _entry_fields(entry)
    return make_finding(
        cwe="LYNIS",
        severity=severity,
        host=host,
        rule_id=f"LYNIS-{test_id}" if test_id else "LYNIS-unknown",
        message=desc,
        evidence=entry[:2000],
        remediation=desc,
        confidence=confidence,
        needs_verification=needs_verification,
        source="lynis",
    )


def report_to_findings(
    dat: str,
    *,
    host: str = "",
    tech_stack: set[str] | None = None,
    apply_gates: bool = True,
    include_suggestions: bool = True,
) -> list[Finding]:
    """Lynis report.dat → Findings, filtered by the applicability gates."""
    stack = tech_stack or set()
    parsed = parse_report(dat)
    candidates: list[Finding] = []
    for entry in parsed["warnings"]:
        candidates.append(_make(host, entry, severity="MEDIUM", confidence=1.0, needs_verification=False))
    if include_suggestions:
        for entry in parsed["suggestions"]:
            candidates.append(_make(host, entry, severity="LOW", confidence=0.7, needs_verification=True))

    findings: list[Finding] = []
    for finding in candidates:
        if apply_gates:
            cve_ok, _ = is_cve_applicable_for_finding(finding, tech_stack=stack)
            if not cve_ok:
                continue
            gen_ok, _ = is_finding_applicable_general(finding, tech_stack=stack)
            if not gen_ok:
                continue
        findings.append(finding)
    return findings
