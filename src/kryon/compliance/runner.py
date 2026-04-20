"""Compliance check runner with reproducibility harness.

The runner:
  1. Discovers registered checks (via explicit list for determinism).
  2. Executes them in sorted order by `control_id`.
  3. Captures each `CheckResult` into a serializable artifact.
  4. Provides a SHA-256 of the reproducibility-stable subset for gate G3.

CLI:
  python -m kryon.compliance.runner --host localhost
  python -m kryon.compliance.runner --host 192.0.2.10 --ssh-user audit --ssh-key ~/.ssh/id_ed25519
  python -m kryon.compliance.runner --repro-check 3   # run 3× and compare hashes
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Callable

from kryon.compliance.checks.base import Check, CheckContext, CheckResult


_REGISTERED_CHECKS: list[Check] = []
_NAT_SORT_SPLIT = re.compile(r"(\d+)")


def _natural_sort_key(control_id: str) -> tuple:
    """Natural-order sort key for CIS-style dotted ids.

    Lexicographic sort puts "CIS-5.2.10" before "CIS-5.2.2", which is
    wrong for CIS/PCI/BCP numbering. We split the id on digit runs and
    coerce the numeric segments to int so CIS-5.2.2 < CIS-5.2.10.
    """
    parts = _NAT_SORT_SPLIT.split(control_id)
    return tuple(int(p) if p.isdigit() else p for p in parts)


def register_check(check: Check) -> None:
    """Add a check to the global registry. Idempotent by control_id."""
    for existing in _REGISTERED_CHECKS:
        if existing.control_id == check.control_id:
            return
    _REGISTERED_CHECKS.append(check)


def registered_checks() -> list[Check]:
    """Return checks in natural-order by control_id for deterministic execution."""
    return sorted(_REGISTERED_CHECKS, key=lambda c: _natural_sort_key(c.control_id))


def run_cmd(
    ctx: CheckContext,
    cmd: list[str] | str,
    *,
    timeout_s: int = 15,
    shell: bool = False,
) -> tuple[str, str, int]:
    """Execute `cmd` locally or over SSH depending on ctx.

    Returns (stdout, stderr, returncode). Captures up to 4KB stdout and
    1KB stderr. Never raises — failures become ERROR-verdict checks
    upstream.
    """
    if ctx.host not in ("", "localhost", "127.0.0.1"):
        if isinstance(cmd, list):
            cmd_str = " ".join(_shell_quote(c) for c in cmd)
        else:
            cmd_str = cmd
        # NB: `-F /dev/null` ignores the operator's ~/.ssh/config to avoid
        # failing on "Bad owner or permissions" when the host-side ~/.ssh
        # is bind-mounted with Docker Desktop perms (mode 777). The key
        # itself we still pass explicitly via -i.
        ssh_cmd = [
            "ssh",
            "-F", "/dev/null",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=/tmp/kryon_known_hosts",
            "-o", "IdentitiesOnly=yes",
            "-p", str(ctx.ssh_port),
        ]
        if ctx.ssh_key_path:
            ssh_cmd += ["-i", ctx.ssh_key_path]
        ssh_cmd.append(f"{ctx.ssh_user}@{ctx.host}" if ctx.ssh_user else ctx.host)
        ssh_cmd.append(cmd_str)
        cmd = ssh_cmd
        shell = False

    try:
        proc = subprocess.run(
            cmd,
            shell=shell if isinstance(cmd, str) else False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        return (
            proc.stdout[:4096],
            proc.stderr[:1024],
            proc.returncode,
        )
    except subprocess.TimeoutExpired:
        return "", f"TIMEOUT after {timeout_s}s", 124
    except FileNotFoundError as exc:
        return "", f"command not found: {exc}", 127
    except Exception as exc:  # noqa: BLE001
        return "", f"exec error: {exc}"[:1024], 1


def _shell_quote(s: str) -> str:
    if not s or any(c in s for c in " \t\n'\"\\$`"):
        return "'" + s.replace("'", "'\\''") + "'"
    return s


def run_all(ctx: CheckContext, run_id: str | None = None) -> list[CheckResult]:
    """Run every registered check against `ctx`, in sorted order."""
    rid = run_id or uuid.uuid4().hex
    results: list[CheckResult] = []
    for check in registered_checks():
        t0 = time.time()
        try:
            r = check.run(ctx)
        except Exception as exc:  # noqa: BLE001
            r = CheckResult(
                control_id=check.control_id,
                control_title=getattr(check, "control_title", ""),
                section=getattr(check, "section", ""),
                verdict="ERROR",
                evidence_command="",
                evidence_stdout="",
                evidence_stderr=f"check raised: {exc}"[:1024],
                evidence_parsed={},
                remediation_static=getattr(check, "remediation_static", ""),
                severity=getattr(check, "severity", "HIGH"),
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id=rid,
            )
        results.append(r)
    return results


def reproducibility_hash(results: list[CheckResult]) -> str:
    """SHA-256 over the reproducibility-stable subset of results.

    Sorted by control_id (already enforced by run_all), JSON serialized
    with sort_keys, fed to sha256.
    """
    payload = [r.to_json_reproducible() for r in results]
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _cli() -> int:
    ap = argparse.ArgumentParser(prog="kryon-compliance-runner")
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--ssh-user", default="")
    ap.add_argument("--ssh-key", default="")
    ap.add_argument("--ssh-port", type=int, default=22)
    ap.add_argument("--deep-evidence", action="store_true")
    ap.add_argument("--out", default="compliance-report.json")
    ap.add_argument("--repro-check", type=int, default=0,
                    help="Run N consecutive times and compare hashes.")
    args = ap.parse_args()

    # Import side-effect: register all section check modules.
    _import_all_checks()

    ctx = CheckContext(
        host=args.host,
        ssh_user=args.ssh_user,
        ssh_key_path=args.ssh_key,
        ssh_port=args.ssh_port,
        deep_evidence=args.deep_evidence,
    )

    if args.repro_check >= 2:
        hashes = []
        for i in range(args.repro_check):
            results = run_all(ctx)
            h = reproducibility_hash(results)
            print(f"run {i+1}/{args.repro_check}  hash={h}")
            hashes.append(h)
        ok = len(set(hashes)) == 1
        print(f"reproducibility: {'PASS' if ok else 'FAIL'} — {len(set(hashes))} distinct hash(es)")
        return 0 if ok else 2

    results = run_all(ctx)
    h = reproducibility_hash(results)
    summary = {
        "host": args.host,
        "repro_hash": h,
        "checks": [
            {**r.to_json_reproducible(), "duration_ms": r.duration_ms, "run_id": r.run_id}
            for r in results
        ],
        "summary": {
            v: sum(1 for r in results if r.verdict == v)
            for v in ("PASS", "FAIL", "N/A", "ERROR")
        },
    }
    Path(args.out).write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {args.out}  hash={h}")
    print(f"verdicts: {summary['summary']}")
    return 0


def _import_all_checks() -> None:
    """Side-effect import: every check module registers itself on import."""
    # Explicit list — stays in sync with the F15.1 scope.
    modules = [
        # F15.1 PCI-DSS v4 baseline
        "kryon.compliance.checks.section_2.c_2_2_2_default_accounts",
        "kryon.compliance.checks.section_2.c_2_2_7_ssh_hardening",
        "kryon.compliance.checks.section_6.c_6_3_3_patch_currency",
        "kryon.compliance.checks.section_6.c_6_4_1_web_headers",
        "kryon.compliance.checks.section_8.c_8_3_6_password_policy",
        "kryon.compliance.checks.section_10.c_10_2_1_audit_trails",
        # F23 Proxmox VE hardening (banking profile)
        "kryon.compliance.checks.proxmox.c_pve_1_1_web_ssl_cert",
        "kryon.compliance.checks.proxmox.c_pve_1_2_unauth_api",
        "kryon.compliance.checks.proxmox.c_pve_2_1_ssh_hardening",
        "kryon.compliance.checks.proxmox.c_pve_3_1_2fa_enforced",
        "kryon.compliance.checks.proxmox.c_pve_3_2_api_token_hygiene",
        "kryon.compliance.checks.proxmox.c_pve_4_1_firewall_enabled",
        "kryon.compliance.checks.proxmox.c_pve_5_1_version_currency",
        # F24 Active Directory hardening (banking profile)
        "kryon.compliance.checks.active_directory.c_ad_1_1_ldap_signing",
        "kryon.compliance.checks.active_directory.c_ad_1_2_ldaps_cert",
        "kryon.compliance.checks.active_directory.c_ad_1_3_anon_bind",
        "kryon.compliance.checks.active_directory.c_ad_2_1_kerberoastable",
        "kryon.compliance.checks.active_directory.c_ad_2_2_krbtgt_rotation",
        "kryon.compliance.checks.active_directory.c_ad_3_1_domain_admins",
        "kryon.compliance.checks.active_directory.c_ad_3_2_password_policy",
        "kryon.compliance.checks.active_directory.c_ad_4_1_smb_signing",
        "kryon.compliance.checks.active_directory.c_ad_5_1_audit_policy",
    ]
    import importlib
    for m in modules:
        try:
            importlib.import_module(m)
        except ImportError:
            # Check module not yet built — skip; registered_checks()
            # will only include what exists so far.
            pass


if __name__ == "__main__":
    # Avoid double-instance gotcha: when python -m loads runner as __main__,
    # the check modules `from kryon.compliance.runner import register_check`
    # load runner AGAIN as a non-main module with its own _REGISTERED_CHECKS.
    # Dispatch to the non-main module's CLI so state is consistent.
    from kryon.compliance import runner as _r
    sys.exit(_r._cli())
