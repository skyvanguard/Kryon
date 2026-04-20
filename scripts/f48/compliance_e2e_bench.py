"""Compliance end-to-end benchmark (F48 dry-run).

Runs every registered compliance framework against a target host using
the standard runner pipeline, then measures:

  * Execution time per framework
  * Verdict distribution (PASS / FAIL / N/A / ERROR)
  * Deterministic reproducibility — same framework twice should yield
    identical evidence hashes
  * End-to-end consolidated multi-framework PDF generation (via the
    F44 render)

Target defaults to ``localhost`` so the bench can exercise the full
pipeline without needing external credentials. Per-framework output is
stored as JSON under ``workspaces/bench-<timestamp>/`` so subsequent
runs can diff.

Usage:
    python scripts/f48/compliance_e2e_bench.py
    python scripts/f48/compliance_e2e_bench.py --host 10.0.0.10 --ssh-user audit
    python scripts/f48/compliance_e2e_bench.py --frameworks cis-debian-12-l1,pci-dss-4.0
    python scripts/f48/compliance_e2e_bench.py --repro-check 2    # run each framework 2x
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import uuid
from dataclasses import asdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from kryon.compliance.checks.base import CheckContext  # noqa: E402
from kryon.compliance.cis import (  # noqa: E402
    available_frameworks,
    register_framework,
)
from kryon.compliance.runner import (  # noqa: E402
    _REGISTERED_CHECKS,
    run_all,
)

# Lazy import — requires pdf deps optional
try:
    from kryon.reporting.multi_framework_pdf import (  # noqa: E402
        compute_repro_hash,
        render_multi_framework_html,
    )
    HAS_PDF = True
except ImportError:
    HAS_PDF = False


def _evidence_hash(results: list) -> str:
    """SHA-256 over reproducibility-stable fields of a result list.

    Two runs against the same target should produce the same hash,
    modulo machine-state drift. Drift is fine, but should be surfaced.
    """
    payload = json.dumps(
        [r.to_json_reproducible() for r in results],
        sort_keys=True,
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _bench_one_framework(
    framework_path: Path,
    ctx: CheckContext,
    repro_n: int = 1,
) -> dict:
    """Register + run one framework, optionally multiple times for repro.

    Clears the global registry before each framework so we isolate.
    """
    # Isolate — wipe registry before loading this framework.
    _REGISTERED_CHECKS.clear()
    checks = register_framework(framework_path)
    framework_id = framework_path.stem

    runs: list[dict] = []
    for i in range(repro_n):
        t0 = time.time()
        results = run_all(ctx, run_id=f"bench-{framework_id}-{i}")
        elapsed = time.time() - t0

        verdicts = {"PASS": 0, "FAIL": 0, "N/A": 0, "ERROR": 0}
        for r in results:
            verdicts[r.verdict] = verdicts.get(r.verdict, 0) + 1

        runs.append({
            "run": i,
            "elapsed_s": round(elapsed, 2),
            "verdicts": verdicts,
            "hash": _evidence_hash(results),
            "results": [asdict(r) for r in results],
        })

    repro_ok = None
    if repro_n > 1:
        first_hash = runs[0]["hash"]
        repro_ok = all(r["hash"] == first_hash for r in runs)

    return {
        "framework_id": framework_id,
        "total_checks": len(checks),
        "runs": runs,
        "reproducible": repro_ok,
    }


def build_context(args) -> CheckContext:
    kwargs = dict(
        host=args.host,
        ssh_user=args.ssh_user or "",
        ssh_key_path=args.ssh_key or "",
        ssh_port=args.ssh_port,
        transport=args.transport,
    )
    if args.winrm_user:
        kwargs.update(
            winrm_user=args.winrm_user,
            winrm_password=args.winrm_password or "",
            winrm_port=args.winrm_port,
            winrm_scheme=args.winrm_scheme,
            winrm_auth=args.winrm_auth,
        )
    return CheckContext(**kwargs)


def main() -> int:
    parser = argparse.ArgumentParser(description="Compliance end-to-end benchmark (F48)")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--ssh-user", default="")
    parser.add_argument("--ssh-key", default="")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument(
        "--transport",
        default="ssh",
        choices=["ssh", "winrm", "local"],
    )
    parser.add_argument("--winrm-user", default="")
    parser.add_argument("--winrm-password", default="")
    parser.add_argument("--winrm-port", type=int, default=5985)
    parser.add_argument("--winrm-scheme", default="http")
    parser.add_argument("--winrm-auth", default="ntlm")
    parser.add_argument(
        "--frameworks",
        default="",
        help="Comma-separated framework ids; empty = all",
    )
    parser.add_argument(
        "--skip",
        default="",
        help="Comma-separated framework ids to skip",
    )
    parser.add_argument(
        "--repro-check",
        type=int,
        default=1,
        help="Run each framework N times; N>1 verifies hash stability",
    )
    parser.add_argument(
        "--timeout-framework",
        type=int,
        default=300,
        help="Per-framework wall clock budget (seconds) — only informational",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Override workspace dir for artifacts",
    )
    parser.add_argument(
        "--render-pdf",
        action="store_true",
        help="Also render the consolidated multi-framework HTML/PDF",
    )
    parser.add_argument(
        "--client-name",
        default="Kryon Lab — F48 dry-run",
    )
    args = parser.parse_args()

    ctx = build_context(args)

    only = set(x.strip() for x in args.frameworks.split(",") if x.strip())
    skip = set(x.strip() for x in args.skip.split(",") if x.strip())

    all_paths = available_frameworks()
    if only:
        selected = [p for p in all_paths if p.stem in only]
    else:
        selected = [p for p in all_paths if p.stem not in skip]

    if not selected:
        print("ERROR: no frameworks selected", file=sys.stderr)
        return 2

    run_id = uuid.uuid4().hex[:8]
    ts = time.strftime("%Y%m%d-%H%M%S")
    out_dir = args.output_dir or (
        REPO / "workspaces" / f"bench-{ts}-{run_id}"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    print(
        f"F48 compliance bench — host={ctx.host} transport={ctx.transport} "
        f"frameworks={len(selected)} repro={args.repro_check}"
    )
    print(f"Output: {out_dir}")

    summary: list[dict] = []
    framework_results_for_pdf: dict = {}

    for path in selected:
        print(f"  → {path.stem}")
        t0 = time.time()
        try:
            entry = _bench_one_framework(path, ctx, repro_n=args.repro_check)
        except Exception as exc:  # noqa: BLE001
            print(f"    FATAL: {exc}", file=sys.stderr)
            summary.append({
                "framework_id": path.stem,
                "total_checks": 0,
                "error": str(exc)[:400],
            })
            continue
        entry["total_elapsed_s"] = round(time.time() - t0, 2)

        # Persist full results + hash per run
        (out_dir / f"{path.stem}.json").write_text(
            json.dumps(entry, indent=2, default=str, ensure_ascii=False),
            encoding="utf-8",
        )

        # Summary + feed PDF renderer with the first run's results
        first = entry["runs"][0]
        summary.append({
            "framework_id": path.stem,
            "total_checks": entry["total_checks"],
            "verdicts": first["verdicts"],
            "hash": first["hash"],
            "elapsed_s": first["elapsed_s"],
            "reproducible": entry["reproducible"],
        })
        # Normalize results for the PDF renderer
        framework_results_for_pdf[path.stem] = [
            {
                "control_id": r["control_id"],
                "title": r["control_title"],
                "section": r["section"],
                "verdict": r["verdict"],
                "severity": r["severity"],
                "command": r["evidence_command"],
                "stdout": r["evidence_stdout"],
                "stderr": r["evidence_stderr"],
                "exit_code": r["evidence_parsed"].get("exit_code", 0),
                "rationale": "",
                "remediation_static": r["remediation_static"],
            }
            for r in first["results"]
        ]

        v = first["verdicts"]
        print(
            f"    ✓ {entry['total_checks']} checks · "
            f"PASS={v['PASS']} FAIL={v['FAIL']} N/A={v['N/A']} ERROR={v['ERROR']} "
            f"· {first['elapsed_s']}s"
            + (f" · repro={entry['reproducible']}" if entry["reproducible"] is not None else "")
        )

    # Aggregate bench report
    totals = {"PASS": 0, "FAIL": 0, "N/A": 0, "ERROR": 0}
    total_checks = 0
    total_elapsed = 0.0
    hash_stable = 0
    hash_unstable = 0
    for entry in summary:
        if "verdicts" not in entry:
            continue
        v = entry["verdicts"]
        for k in totals:
            totals[k] += v.get(k, 0)
        total_checks += entry["total_checks"]
        total_elapsed += entry["elapsed_s"]
        if entry.get("reproducible") is True:
            hash_stable += 1
        elif entry.get("reproducible") is False:
            hash_unstable += 1

    report = {
        "run_id": run_id,
        "timestamp": ts,
        "host": ctx.host,
        "transport": ctx.transport,
        "frameworks_run": len(summary),
        "total_checks": total_checks,
        "verdict_totals": totals,
        "total_elapsed_s": round(total_elapsed, 2),
        "repro_stable": hash_stable,
        "repro_unstable": hash_unstable,
        "per_framework": summary,
    }
    (out_dir / "bench_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print()
    print("=" * 70)
    print(f"Total checks: {total_checks}")
    print(
        f"PASS={totals['PASS']}  FAIL={totals['FAIL']}  "
        f"N/A={totals['N/A']}  ERROR={totals['ERROR']}"
    )
    if args.repro_check > 1:
        print(f"Reproducibility: {hash_stable} stable, {hash_unstable} unstable")
    print(f"Wall time: {total_elapsed:.1f}s")
    print(f"Report: {out_dir / 'bench_report.json'}")

    # Optional consolidated PDF
    if args.render_pdf and HAS_PDF and framework_results_for_pdf:
        print()
        print("Rendering consolidated multi-framework report…")
        repro = compute_repro_hash(framework_results_for_pdf)
        html = render_multi_framework_html(
            framework_results_for_pdf,
            host=ctx.host,
            client_name=args.client_name,
            repro_hash=repro,
        )
        html_path = out_dir / "consolidated.html"
        html_path.write_text(html, encoding="utf-8")
        print(f"  HTML: {html_path} ({len(html)} bytes)")
        print(f"  master hash: {repro[:16]}...")

        # Try PDF too
        try:
            from weasyprint import HTML as WP  # type: ignore

            pdf_path = out_dir / "consolidated.pdf"
            WP(string=html).write_pdf(str(pdf_path))
            print(f"  PDF: {pdf_path}")
        except Exception as exc:  # noqa: BLE001
            print(f"  (PDF skipped: {exc})")

    return 0 if totals["ERROR"] < total_checks else 1


if __name__ == "__main__":
    sys.exit(main())
