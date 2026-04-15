"""@function_tool run_compliance_audit — F15.1 deterministic PCI-DSS auditor
exposed to the unified agent.

The agent invokes this when the user asks for a compliance audit, PCI check,
hardening review, etc. (See `banking/pci-dss-audit.md` skill for triggers.)

Architecture: the LLM orchestrates (decides WHEN to call this), the runner
provides DETERMINISTIC verdicts. LLM never modifies the verdict — it only
reads the structured CheckResult output to narrate findings to the user.

Returns a JSON string with:
  - hash: SHA-256 reproducibility hash
  - host: target audited
  - summary: {PASS, FAIL, N/A, ERROR} counts
  - findings: list of per-control results (verdict + parsed evidence)
"""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool


@function_tool(strict_mode=False)
def run_compliance_audit(
    host: str = "localhost",
    ssh_user: str = "",
    ssh_key_path: str = "",
    ssh_port: int = 22,
    framework: str = "pci-dss-v4",
) -> str:
    """Run the deterministic PCI-DSS v4 compliance audit (F15.1) on a target.

    Six checks across PCI sections 2/6/8/10:
      - 2.2.2 vendor default accounts (shadow + mysql + snmp)
      - 2.2.7 SSH non-console admin encryption
      - 6.3.3 security patches within 30 days
      - 6.4.1 public web app protection (HSTS/CSP/XFO/XCTO via live HTTP)
      - 8.3.6 password policy complexity
      - 10.2.1 audit trails (auditd + PCI rules)

    The verdicts are 100% deterministic (Python + shell, no LLM in detection
    path). LLM may only narrate the findings to the user; modifying verdicts
    is a regulatory boundary violation.

    Args:
        host: Target hostname or IP. Default "localhost" runs on the kryon
            container itself (useful for self-audit demos).
        ssh_user: SSH user for remote audits. Empty = run on host directly.
        ssh_key_path: Path to SSH key. Empty = default key resolution.
        ssh_port: SSH port, default 22.
        framework: Currently only "pci-dss-v4" supported. Reserved for F16
            multi-framework expansion.

    Returns:
        JSON string with hash, host, summary, findings list. The agent
        should narrate the findings honestly to the user — list FAILs first,
        then PASSes / N/As, citing the exact evidence_command for each FAIL
        so the user can reproduce manually.
    """
    if framework != "pci-dss-v4":
        return json.dumps({
            "error": f"framework {framework!r} not implemented (only pci-dss-v4 in F15.1)",
            "available": ["pci-dss-v4"],
        })

    try:
        from kryon.compliance.runner import (
            run_all,
            reproducibility_hash,
            _import_all_checks,
        )
        from kryon.compliance.checks.base import CheckContext
    except ImportError as exc:
        return json.dumps({"error": f"compliance module not loadable: {exc}"})

    _import_all_checks()
    ctx = CheckContext(
        host=host or "localhost",
        ssh_user=ssh_user,
        ssh_key_path=ssh_key_path,
        ssh_port=ssh_port,
    )
    results = run_all(ctx)
    hash_ = reproducibility_hash(results)

    summary = {v: 0 for v in ("PASS", "FAIL", "N/A", "ERROR")}
    findings: list[dict[str, Any]] = []
    for r in results:
        summary[r.verdict] = summary.get(r.verdict, 0) + 1
        findings.append({
            "control_id": r.control_id,
            "control_title": r.control_title,
            "section": r.section,
            "verdict": r.verdict,
            "severity": r.severity,
            "evidence_command": r.evidence_command,
            "evidence_parsed": r.evidence_parsed,
            "remediation_static": r.remediation_static,
        })

    return json.dumps({
        "framework": framework,
        "host": host or "localhost",
        "repro_hash": hash_,
        "summary": summary,
        "findings": findings,
        "next_step_hint": (
            "If the user wants a PDF report, suggest running "
            "`generate_compliance_pdf` next (auto-narrates context + remediation)."
        ),
    }, ensure_ascii=False)


@function_tool(strict_mode=False)
def generate_compliance_pdf(
    host: str = "localhost",
    out_path: str = "/tmp/kryon_compliance.pdf",
    skip_llm_narrative: bool = False,
) -> str:
    """Render a PDF compliance audit report (F15.1 template).

    Re-runs the audit and produces an A4 PDF with:
      - Executive summary table
      - Per-control finding cards (verdict, evidence, remediation)
      - LLM-narrated context + remediation prose (clearly watermarked,
        regulatory boundary enforced — never modifies verdicts)
      - Appendix A with raw stdout/stderr per control for reproducibility
      - SHA-256 hash footer tying the PDF to the JSON artifact

    Args:
        host: Target hostname.
        out_path: Where to write the PDF.
        skip_llm_narrative: If True, deterministic-only PDF (faster, no
            Ollama dependency). Default False = with LLM narrative.

    Returns:
        JSON with paths of generated artifacts and the repro hash.
    """
    from pathlib import Path

    try:
        from kryon.compliance.runner import (
            run_all,
            reproducibility_hash,
            _import_all_checks,
        )
        from kryon.compliance.checks.base import CheckContext
        from kryon.reporting.compliance_pdf import render_pdf
    except ImportError as exc:
        return json.dumps({"error": f"reporting module not loadable: {exc}"})

    _import_all_checks()
    ctx = CheckContext(host=host or "localhost")
    results = run_all(ctx)
    repro_h = reproducibility_hash(results)

    results_dicts = [
        {
            "control_id": r.control_id,
            "control_title": r.control_title,
            "section": r.section,
            "verdict": r.verdict,
            "severity": r.severity,
            "host": r.host,
            "evidence_command": r.evidence_command,
            "evidence_stdout": r.evidence_stdout,
            "evidence_stderr": r.evidence_stderr,
            "evidence_parsed": r.evidence_parsed,
            "remediation_static": r.remediation_static,
        }
        for r in results
    ]

    narratives: dict[str, dict[str, str]] = {}
    if not skip_llm_narrative:
        try:
            from kryon.reporting.compliance_narrator import narrate_all
            narratives = narrate_all(results_dicts)
        except Exception:
            narratives = {}

    out = Path(out_path)
    try:
        render_pdf(
            results_dicts,
            repro_hash=repro_h,
            host=host or "localhost",
            output_path=out,
            narratives=narratives,
        )
        pdf_path = str(out)
    except ImportError:
        pdf_path = ""

    return json.dumps({
        "host": host or "localhost",
        "repro_hash": repro_h,
        "pdf_path": pdf_path,
        "html_path": str(out.with_suffix(".html")),
        "narrated": bool(narratives),
    }, ensure_ascii=False)
