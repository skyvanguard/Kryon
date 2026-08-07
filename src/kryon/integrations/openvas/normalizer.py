"""Map GMP ``get_results`` XML → Kryon ``engage.Finding``.

Design decisions that keep this false-positive-safe and consistent with the
rest of Kryon:

* **One Finding per CVE.** An NVT can reference 0..N CVEs. When it has CVEs we
  emit one Finding per CVE with ``rule_id = CVE-XXXX`` — exactly the shape the
  existing ``is_cve_applicable_for_finding`` gate keys on, so non-applicable
  CVEs get dropped. NVTs with no CVE get ``rule_id = OPENVAS-<oid>`` and go
  through the general product gate instead.
* **QoD → confidence.** OpenVAS reports a Quality-of-Detection score (0-100)
  per result; it maps directly to Kryon's ``confidence`` (0.0-1.0). Low-QoD
  remote checks arrive flagged, not asserted.
* **needs_verification = True.** OpenVAS remote checks can false-positive, so
  every finding is marked for verification and run through the applicability
  gates before it is trusted.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from kryon.cli.engage import Finding, make_finding
from kryon.validation.cve_applicability import is_cve_applicable_for_finding
from kryon.validation.finding_applicability import is_finding_applicable_general


def cvss_to_severity(score: float) -> str:
    """CVSS base score → Kryon severity band (standard cut points)."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def _solution_from_tags(tags: str) -> str:
    """OpenVAS NVT `tags` is pipe-separated key=value; pull `solution`."""
    for part in tags.split("|"):
        key, _, value = part.partition("=")
        if key.strip() == "solution":
            return value.strip()
    return ""


def parse_results(xml: str) -> list[dict]:
    """Parse a get_results_response into raw dicts (one per <result>)."""
    root = ET.fromstring(xml)
    out: list[dict] = []
    for result in root.iter("result"):
        nvt = result.find("nvt")
        nvt = nvt if nvt is not None else ET.Element("nvt")

        host_el = result.find("host")
        host = (host_el.text if host_el is not None and host_el.text else "").strip()

        # Severity: prefer the result-level numeric, fall back to NVT cvss_base.
        raw_sev = (result.findtext("severity") or nvt.findtext("cvss_base") or "0").strip()
        try:
            severity_num = float(raw_sev)
        except ValueError:
            severity_num = 0.0

        qod_el = result.find("qod")
        try:
            qod = int((qod_el.findtext("value") if qod_el is not None else "0") or "0")
        except ValueError:
            qod = 0

        refs = nvt.find("refs")
        cves: list[str] = []
        cwes: list[str] = []
        if refs is not None:
            for ref in refs.findall("ref"):
                rtype = (ref.get("type") or "").lower()
                rid = ref.get("id") or ""
                if rtype == "cve" and rid:
                    cves.append(rid.upper())
                elif rtype == "cwe" and rid:
                    cwes.append(rid.upper())

        solution = (nvt.findtext("solution") or "").strip() or _solution_from_tags(nvt.findtext("tags") or "")

        out.append(
            {
                "host": host,
                "port": (result.findtext("port") or "").strip(),
                "oid": nvt.get("oid") or "",
                "name": (result.findtext("name") or nvt.findtext("name") or "").strip(),
                "severity_num": severity_num,
                "qod": qod,
                "cves": cves,
                "cwe": cwes[0] if cwes else "NVT",
                "description": (result.findtext("description") or "").strip(),
                "solution": solution,
            }
        )
    return out


def _findings_from_result(r: dict) -> list[Finding]:
    severity = cvss_to_severity(r["severity_num"])
    confidence = max(0.0, min(1.0, r["qod"] / 100.0))
    port = f" ({r['port']})" if r["port"] else ""
    evidence = r["description"] or f"OpenVAS NVT {r['oid']}"

    if r["cves"]:
        findings = []
        for cve in r["cves"]:
            findings.append(
                make_finding(
                    cwe=r["cwe"],
                    severity=severity,
                    host=r["host"],
                    rule_id=cve,  # CVE-shaped → the CVE applicability gate applies
                    message=f"{r['name']} [{cve}]{port}",
                    evidence=evidence,
                    remediation=r["solution"],
                    confidence=confidence,
                    needs_verification=True,
                    source="openvas",
                )
            )
        return findings

    return [
        make_finding(
            cwe=r["cwe"],
            severity=severity,
            host=r["host"],
            rule_id=f"OPENVAS-{r['oid']}" if r["oid"] else "OPENVAS-NVT",
            message=f"{r['name']}{port}",
            evidence=evidence,
            remediation=r["solution"],
            confidence=confidence,
            needs_verification=True,
            source="openvas",
        )
    ]


def results_to_findings(
    xml: str,
    *,
    tech_stack: set[str] | None = None,
    apply_gates: bool = True,
) -> list[Finding]:
    """Convert get_results XML → Findings, dropping non-applicable ones.

    ``apply_gates=False`` skips the applicability filter (used for testing the
    raw mapping). The gates are conservative — with no tech_stack / no product
    mention they pass, so they never drop a finding without positive evidence.
    """
    stack = tech_stack or set()
    findings: list[Finding] = []
    for r in parse_results(xml):
        for finding in _findings_from_result(r):
            if apply_gates:
                cve_ok, _ = is_cve_applicable_for_finding(finding, tech_stack=stack)
                if not cve_ok:
                    continue
                gen_ok, _ = is_finding_applicable_general(finding, tech_stack=stack)
                if not gen_ok:
                    continue
            findings.append(finding)
    return findings
