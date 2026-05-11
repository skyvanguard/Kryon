"""F15.1 end-to-end — run checks on bench target, narrate, render PDF.

Runs inside bench-target (has the checks, corpus, and ollama-reachable network
via docker-compose if connected) OR on the host against a provided JSON artifact.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import types
from pathlib import Path


def _bootstrap(root: Path) -> None:
    for name, path in [
        ("kryon", []),
        ("kryon.compliance", [str(root / "compliance")]),
        ("kryon.compliance.checks", [str(root / "compliance/checks")]),
        ("kryon.compliance.checks.section_2", [str(root / "compliance/checks/section_2")]),
        ("kryon.compliance.checks.section_6", [str(root / "compliance/checks/section_6")]),
        ("kryon.compliance.checks.section_8", [str(root / "compliance/checks/section_8")]),
        ("kryon.compliance.checks.section_10", [str(root / "compliance/checks/section_10")]),
        ("kryon.reporting", [str(root / "reporting")]),
    ]:
        mod = types.ModuleType(name)
        mod.__path__ = path
        sys.modules[name] = mod


def _load(name: str, path: str) -> None:
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)


def _checkresult_to_dict(r) -> dict:
    return {
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-root", default="/opt/kryon_src",
                    help="Dir containing compliance/ and reporting/ subdirs.")
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--out", default="/tmp/f15_compliance.pdf")
    ap.add_argument("--skip-llm", action="store_true",
                    help="Skip narrator; produce PDF with deterministic sections only.")
    ap.add_argument("--from-json", default="",
                    help="Load pre-captured check results JSON instead of re-running.")
    args = ap.parse_args()

    root = Path(args.src_root)
    _bootstrap(root)
    _load("kryon.compliance.checks.base", str(root / "compliance/checks/base.py"))
    _load("kryon.compliance.runner", str(root / "compliance/runner.py"))
    for sec, fname in [
        ("section_2", "c_2_2_2_default_accounts"),
        ("section_2", "c_2_2_7_ssh_hardening"),
        ("section_6", "c_6_3_3_patch_currency"),
        ("section_6", "c_6_4_1_web_headers"),
        ("section_8", "c_8_3_6_password_policy"),
        ("section_10", "c_10_2_1_audit_trails"),
    ]:
        _load(f"kryon.compliance.checks.{sec}.{fname}",
              str(root / f"compliance/checks/{sec}/{fname}.py"))
    _load("kryon.reporting.compliance_pdf", str(root / "reporting/compliance_pdf.py"))
    _load("kryon.reporting.compliance_narrator", str(root / "reporting/compliance_narrator.py"))

    from kryon.compliance.checks.base import CheckContext
    from kryon.compliance.runner import reproducibility_hash, run_all
    from kryon.reporting.compliance_narrator import narrate_all
    from kryon.reporting.compliance_pdf import render_pdf

    if args.from_json:
        results_dicts = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
        sev_map = {
            "2.2.2": ("CRITICAL", "Vendor default accounts"),
            "2.2.7": ("HIGH", "Non-console administrative access encryption"),
            "6.3.3": ("HIGH", "Critical security patches within 30 days"),
            "6.4.1": ("HIGH", "Public-facing web application protection"),
            "8.3.6": ("HIGH", "Minimum password complexity"),
            "10.2.1": ("HIGH", "Audit trails"),
        }
        rem_static = {
            "2.2.2": "Remove or lock any empty-password account. Set MySQL root password. Change SNMP community from 'public'.",
            "2.2.7": "Edit /etc/ssh/sshd_config: PermitRootLogin no, MaxAuthTries 4, modern Ciphers (no CBC). Reload sshd.",
            "6.3.3": "Enable unattended-upgrades and apply pending security patches.",
            "6.4.1": "Add HSTS, CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff at web server layer.",
            "8.3.6": "Set PASS_MIN_LEN 12 in /etc/login.defs. Configure pwquality.conf minlen=12, minclass=3. Enable pam_pwquality.",
            "10.2.1": "Install and enable auditd. Add PCI rules: -w /etc/passwd, /etc/shadow, /etc/sudoers; execve tracking.",
        }
        for r in results_dicts:
            cid = r.get("control_id", "")
            sev, title = sev_map.get(cid, ("INFO", cid))
            r.setdefault("severity", sev)
            r.setdefault("control_title", title)
            r.setdefault("host", args.host)
            r.setdefault("evidence_stderr", "")
            r.setdefault("remediation_static", rem_static.get(cid, ""))
        import hashlib
        payload = [
            {k: r.get(k) for k in (
                "control_id", "control_title", "section", "verdict",
                "evidence_command", "evidence_stdout", "evidence_stderr",
                "evidence_parsed", "remediation_static", "severity", "host",
            )} for r in sorted(results_dicts, key=lambda x: x["control_id"])
        ]
        blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        repro_h = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        print(f"hash (from-json): {repro_h}")
    else:
        ctx = CheckContext(host=args.host)
        results = run_all(ctx)
        results_dicts = [_checkresult_to_dict(r) for r in results]
        repro_h = reproducibility_hash(results)
        print(f"hash: {repro_h}")

    narratives: dict[str, dict] = {}
    if not args.skip_llm:
        print("Narrating findings via LLM (temp=0)...")
        narratives = narrate_all(results_dicts)
        for cid, n in narratives.items():
            ok = bool(n["context_prose"]) and bool(n["remediation_prose"])
            print(f"  {cid}: {'ok' if ok else 'empty'}")

    out_path = Path(args.out)
    try:
        render_pdf(
            results_dicts,
            repro_hash=repro_h,
            host=args.host,
            output_path=out_path,
            narratives=narratives,
        )
        print(f"PDF: {out_path}")
    except ImportError:
        html_path = out_path.with_suffix(".html")
        print(f"weasyprint unavailable; HTML only: {html_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
