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

# Framework → control_id prefix mapping (used by both tools for filtering).
# "all" keeps every check. Reserved keys here stay aligned with the CLI
# wrapper scripts/kryon-audit.sh.
_FRAMEWORK_PREFIX = {
    "pci-dss": ("2.", "6.", "8.", "10."),  # F15.1 numeric PCI sections
    "pci": ("2.", "6.", "8.", "10."),
    "proxmox": ("PVE-",),  # F23
    "pve": ("PVE-",),
    "ad": ("AD-",),  # F24
    "active-directory": ("AD-",),
    "fortigate": ("FGT-",),  # F78 FortiOS hardening
    "fgt": ("FGT-",),
    "fortinet": ("FGT-",),
    "fortios": ("FGT-",),
    "unifi": ("UNF-",),  # F79 Unifi / Ubiquiti
    "ubnt": ("UNF-",),
    "ubiquiti": ("UNF-",),
    "asterisk": ("VOIP-",),  # F198 Asterisk / FreePBX VoIP
    "voip": ("VOIP-",),
    "freepbx": ("VOIP-",),
    "windows": ("WIN-",),  # F199 Windows Server + endpoint via WinRM
    "win": ("WIN-",),
    "windows-server": ("WIN-",),
    "tomcat": ("TOMCAT-",),  # F200.A Apache Tomcat audit
    "apache-tomcat": ("TOMCAT-",),
    "coyote": ("TOMCAT-",),
    "all": (),
}


def _run_cis_controls_audit(
    host: str,
    ssh_user: str,
    ssh_key_path: str,
    ssh_port: int,
) -> str:
    """CIS Controls v8.1 crosswalk audit (F-CISC).

    Runs every deterministic check once and aggregates the results onto the
    153 CIS v8.1 safeguards. Safeguards with a mapped check come back AUTO
    (PASS/FAIL/N/A); governance/process safeguards come back MANUAL — the
    agent must NOT present a MANUAL safeguard as if it were auto-verified.
    """
    try:
        from kryon.compliance.checks.base import CheckContext
        from kryon.compliance.cis.cis_controls_crosswalk import audit_cis_controls
    except ImportError as exc:
        return json.dumps({"error": f"compliance module not loadable: {exc}"})

    ctx = CheckContext(
        host=host or "localhost",
        ssh_user=ssh_user,
        ssh_key_path=ssh_key_path,
        ssh_port=ssh_port,
    )
    report = audit_cis_controls(ctx)
    # Surface AUTO findings first (FAILs lead), keep MANUAL out of the noisy list.
    auto = [s for s in report["safeguards"] if s["verdict_mode"] == "auto"]
    auto.sort(key=lambda s: {"FAIL": 0, "ERROR": 1, "N/A": 2, "PASS": 3}.get(s["verdict"], 4))
    report["auto_findings"] = auto
    report["next_step_hint"] = (
        "AUTO safeguards are machine-verified; MANUAL safeguards (governance, "
        "training, IR, service-provider mgmt) require interview/document evidence "
        "— do NOT claim they passed. For a PDF, run generate_compliance_pdf "
        "with framework='cis-controls'."
    )
    return json.dumps(report, ensure_ascii=False)


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
        framework: One of "pci-dss" | "proxmox" | "ad" | "fortigate" | "unifi"
            | "asterisk" | "windows" | "tomcat" | "all". Pass "cis-controls"
            (aka "cisc") for the CIS Controls v8.1 crosswalk audit: every
            deterministic check is aggregated onto the 153 v8.1 safeguards
            (AUTO), and governance/process safeguards are reported as MANUAL.

    Returns:
        JSON string with hash, host, summary, findings list. The agent
        should narrate the findings honestly to the user — list FAILs first,
        then PASSes / N/As, citing the exact evidence_command for each FAIL
        so the user can reproduce manually.
    """
    # Accept legacy alias + new multi-framework keys (F23/F24/F78/F79)
    fw_alias = {
        "pci-dss-v4": "pci-dss",
        "pci-dss": "pci-dss",
        "pci": "pci-dss",
        "proxmox": "proxmox",
        "pve": "proxmox",
        "ad": "ad",
        "active-directory": "ad",
        "fortigate": "fortigate",
        "fgt": "fortigate",
        "fortinet": "fortigate",
        "fortios": "fortigate",
        "unifi": "unifi",
        "ubnt": "unifi",
        "ubiquiti": "unifi",
        "asterisk": "asterisk",
        "voip": "asterisk",
        "freepbx": "asterisk",
        "windows": "windows",
        "win": "windows",
        "windows-server": "windows",
        "tomcat": "tomcat",
        "apache-tomcat": "tomcat",
        "coyote": "tomcat",
        "all": "all",
    }
    # CIS Controls v8.1 is not a prefix filter — it crosswalks ALL deterministic
    # checks onto the 153 safeguards (auto) and reports the rest as manual.
    _CIS_CONTROLS_ALIASES = {"cis-controls", "cis-controls-v8.1", "cisc", "cis8", "cis8.1", "cis-v8.1"}
    if (framework or "").lower() in _CIS_CONTROLS_ALIASES:
        return _run_cis_controls_audit(host, ssh_user, ssh_key_path, ssh_port)

    fw_key = fw_alias.get((framework or "pci-dss").lower())
    if fw_key is None:
        return json.dumps(
            {
                "error": f"unknown framework {framework!r}",
                "available": sorted(set(fw_alias) | _CIS_CONTROLS_ALIASES),
            }
        )
    prefixes = _FRAMEWORK_PREFIX.get(fw_key, ())

    try:
        from kryon.compliance.checks.base import CheckContext
        from kryon.compliance.runner import (
            _import_all_checks,
            reproducibility_hash,
            run_all,
        )
    except ImportError as exc:
        return json.dumps({"error": f"compliance module not loadable: {exc}"})

    _import_all_checks()
    ctx = CheckContext(
        host=host or "localhost",
        ssh_user=ssh_user,
        ssh_key_path=ssh_key_path,
        ssh_port=ssh_port,
    )
    all_results = run_all(ctx)
    if prefixes:
        results = [r for r in all_results if r.control_id.startswith(prefixes)]
    else:
        results = all_results
    hash_ = reproducibility_hash(results)

    summary = dict.fromkeys(("PASS", "FAIL", "N/A", "ERROR"), 0)
    findings: list[dict[str, Any]] = []
    for r in results:
        summary[r.verdict] = summary.get(r.verdict, 0) + 1
        findings.append(
            {
                "control_id": r.control_id,
                "control_title": r.control_title,
                "section": r.section,
                "verdict": r.verdict,
                "severity": r.severity,
                "evidence_command": r.evidence_command,
                "evidence_parsed": r.evidence_parsed,
                "remediation_static": r.remediation_static,
            }
        )

    return json.dumps(
        {
            "framework": framework,
            "host": host or "localhost",
            "repro_hash": hash_,
            "summary": summary,
            "findings": findings,
            "next_step_hint": (
                "If the user wants a PDF report, suggest running "
                "`generate_compliance_pdf` next (auto-narrates context + remediation)."
            ),
        },
        ensure_ascii=False,
    )


def _default_out_path(framework: str, host: str) -> str:
    """Default PDF path — lands in the bind-mounted /reports on docker,
    so the host sees it under ./reports/ immediately."""
    from datetime import datetime
    from pathlib import Path

    # Prefer /reports (bind mount). Fallback /tmp if not mounted.
    reports_dir = Path("/reports")
    if not reports_dir.is_dir():
        reports_dir = Path("/tmp")
    safe_host = host.replace("/", "_").replace(":", "_") or "localhost"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return str(reports_dir / f"kryon_{framework}_{safe_host}_{ts}.pdf")


def _cis_safeguards_to_results(safeguards: list[dict], host: str) -> list[dict]:
    """Adapt crosswalk safeguards to the compliance_pdf result-dict shape.

    MANUAL safeguards render as N/A (not auto-assessed) with an explicit
    remediation note, so the PDF never implies a governance control was
    machine-verified.
    """
    results: list[dict] = []
    for s in safeguards:
        manual = s["verdict_mode"] == "manual"
        verdict = "N/A" if manual else s["verdict"]
        ev = "; ".join(f"{e['check_id']}={e['verdict']}" for e in s["evidence_checks"])
        results.append(
            {
                "control_id": s["id"],
                "control_title": s["title"],
                "section": f"Control {s['control']} — {s['category']} [IG{s['implementation_group']}/{s['security_function']}]",
                "verdict": verdict,
                "severity": "INFO" if manual else ("HIGH" if verdict == "FAIL" else "LOW"),
                "host": host,
                "evidence_command": "" if manual else f"crosswalk: {ev}",
                "evidence_stdout": ev,
                "evidence_stderr": "",
                "evidence_parsed": {"verdict_mode": s["verdict_mode"], "asset_type": s["asset_type"]},
                "remediation_static": (
                    "Requiere evidencia manual (entrevista / revisión documental): "
                    "safeguard de gobierno/proceso, no auditable automáticamente."
                    if manual
                    else ""
                ),
            }
        )
    return results


def _run_cis_controls_pdf(
    *,
    host: str,
    out_path: str,
    skip_llm_narrative: bool,
    client_name: str,
    ssh_user: str,
    ssh_key_path: str,
    ssh_port: int,
    render_pdf,
) -> str:
    """Render the CIS Controls v8.1 crosswalk audit as a PDF."""
    import os
    from pathlib import Path

    from kryon.compliance.checks.base import CheckContext
    from kryon.compliance.cis.cis_controls_crosswalk import audit_cis_controls

    if not out_path:
        out_path = _default_out_path("cis-controls", host or "localhost")
    ctx = CheckContext(
        host=host or "localhost",
        ssh_user=ssh_user or os.environ.get("KRYON_SSH_USER", "").strip(),
        ssh_key_path=ssh_key_path or os.environ.get("KRYON_SSH_KEY", "").strip(),
        ssh_port=int(ssh_port) if ssh_port else int(os.environ.get("KRYON_SSH_PORT", "22") or 22),
    )
    report = audit_cis_controls(ctx)
    results_dicts = _cis_safeguards_to_results(report["safeguards"], ctx.host)

    narratives: dict[str, dict[str, str]] = {}
    if not skip_llm_narrative:
        try:
            from kryon.reporting.compliance_narrator import narrate_all

            # Only narrate AUTO findings — manual safeguards have nothing to narrate.
            narratives = narrate_all([r for r in results_dicts if r["verdict"] != "N/A"])
        except Exception:
            narratives = {}

    out = Path(out_path)
    effective_client = client_name or os.environ.get("KRYON_CLIENT_NAME", "").strip()
    try:
        render_pdf(
            results_dicts,
            repro_hash=report["repro_hash"],
            host=ctx.host,
            output_path=out,
            narratives=narratives,
            framework="cis-controls",
            client_name=effective_client,
        )
        pdf_path = str(out)
    except ImportError:
        pdf_path = ""

    return json.dumps(
        {
            "host": ctx.host,
            "framework": "CIS Controls v8.1",
            "checks_run": report["checks_run"],
            "summary": report["summary"],
            "repro_hash": report["repro_hash"],
            "pdf_path": pdf_path,
            "html_path": str(out.with_suffix(".html")),
            "narrated": bool(narratives),
        },
        ensure_ascii=False,
    )


def _run_compliance_pdf(
    host: str = "localhost",
    out_path: str = "",
    framework: str = "all",
    skip_llm_narrative: bool = False,
    client_name: str = "",
    ssh_user: str = "",
    ssh_key_path: str = "",
    ssh_port: int = 22,
) -> str:
    """Core implementation — plain Python, no tool decorator.

    Usable from both the `@function_tool` wrapper (agent runtime) and
    the CLI wrapper script (scripts/kryon-audit.sh) without needing to
    un-wrap decorator internals.

    Remote audit: pass host != "localhost" together with ssh_user and
    ssh_key_path. Runner will shell out to `ssh -i <key> user@host <cmd>`
    for every check invocation, using BatchMode to avoid password prompts.

    Env-var fallbacks (CLI-friendly):
      KRYON_CLIENT_NAME, KRYON_SSH_USER, KRYON_SSH_KEY, KRYON_SSH_PORT.

    client_name: banking client label shown on the report cover.
    """
    from pathlib import Path

    try:
        from kryon.compliance.checks.base import CheckContext
        from kryon.compliance.runner import (
            _import_all_checks,
            reproducibility_hash,
            run_all,
        )
        from kryon.reporting.compliance_pdf import render_pdf
    except ImportError as exc:
        return json.dumps({"error": f"reporting module not loadable: {exc}"})

    # CIS Controls v8.1: crosswalk path (not a prefix filter).
    if (framework or "").lower() in {"cis-controls", "cis-controls-v8.1", "cisc", "cis8", "cis8.1", "cis-v8.1"}:
        return _run_cis_controls_pdf(
            host=host,
            out_path=out_path,
            skip_llm_narrative=skip_llm_narrative,
            client_name=client_name,
            ssh_user=ssh_user,
            ssh_key_path=ssh_key_path,
            ssh_port=ssh_port,
            render_pdf=render_pdf,
        )

    fw_key = (framework or "all").lower()
    prefixes = _FRAMEWORK_PREFIX.get(fw_key)
    if prefixes is None:
        return json.dumps(
            {
                "error": f"unknown framework {framework!r}. Use one of: {sorted(_FRAMEWORK_PREFIX.keys())}",
            }
        )

    if not out_path:
        out_path = _default_out_path(fw_key, host or "localhost")

    # Env-var fallbacks so the CLI wrapper can pass creds via `docker exec -e`
    import os

    effective_ssh_user = ssh_user or os.environ.get("KRYON_SSH_USER", "").strip()
    effective_ssh_key = ssh_key_path or os.environ.get("KRYON_SSH_KEY", "").strip()
    try:
        effective_ssh_port = int(ssh_port) or int(os.environ.get("KRYON_SSH_PORT", "22"))
    except (TypeError, ValueError):
        effective_ssh_port = 22

    _import_all_checks()
    ctx = CheckContext(
        host=host or "localhost",
        ssh_user=effective_ssh_user,
        ssh_key_path=effective_ssh_key,
        ssh_port=effective_ssh_port,
    )
    all_results = run_all(ctx)

    # Filter by framework prefix (empty tuple = keep all).
    if prefixes:
        results = [r for r in all_results if r.control_id.startswith(prefixes)]
    else:
        results = all_results

    if not results:
        return json.dumps(
            {
                "error": f"no checks matched framework={framework!r}",
                "registered": len(all_results),
            }
        )

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

    import os

    effective_client = client_name or os.environ.get("KRYON_CLIENT_NAME", "").strip()

    out = Path(out_path)
    try:
        render_pdf(
            results_dicts,
            repro_hash=repro_h,
            host=host or "localhost",
            output_path=out,
            narratives=narratives,
            framework=fw_key,
            client_name=effective_client,
        )
        pdf_path = str(out)
    except ImportError:
        pdf_path = ""

    # Summary counts for quick stdout feedback
    verdict_counts: dict[str, int] = {}
    for r in results:
        verdict_counts[r.verdict] = verdict_counts.get(r.verdict, 0) + 1

    return json.dumps(
        {
            "host": host or "localhost",
            "framework": fw_key,
            "checks_run": len(results),
            "verdict_counts": verdict_counts,
            "repro_hash": repro_h,
            "pdf_path": pdf_path,
            "html_path": str(out.with_suffix(".html")),
            "narrated": bool(narratives),
        },
        ensure_ascii=False,
    )


@function_tool(strict_mode=False)
def generate_compliance_pdf(
    host: str = "localhost",
    out_path: str = "",
    framework: str = "all",
    skip_llm_narrative: bool = False,
    client_name: str = "",
    ssh_user: str = "",
    ssh_key_path: str = "",
    ssh_port: int = 22,
) -> str:
    """Render a compliance audit PDF report.

    Produces an A4 PDF with executive summary, per-control finding cards
    (verdict / evidence / remediation), optional LLM-narrated prose
    (clearly watermarked), and Appendix A with raw stdout/stderr per
    control for reproducibility. SHA-256 hash footer ties the PDF to
    the JSON evidence artifact.

    Args:
        host: Target hostname.
        out_path: Where to write the PDF. Default: /reports/kryon_<fw>_<host>_<ts>.pdf
            (`/reports` is bind-mounted on docker so the host sees the file).
        framework: One of "pci-dss" | "proxmox" | "ad" | "fortigate" | "unifi" | "all" (default).
        skip_llm_narrative: If True, deterministic-only PDF (faster, no Ollama).

    Returns:
        JSON with paths of generated artifacts and the repro hash.
    """
    return _run_compliance_pdf(
        host=host,
        out_path=out_path,
        framework=framework,
        skip_llm_narrative=skip_llm_narrative,
        client_name=client_name,
        ssh_user=ssh_user,
        ssh_key_path=ssh_key_path,
        ssh_port=ssh_port,
    )
