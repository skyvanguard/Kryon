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
    """Execute `cmd` locally, over SSH, or over WinRM depending on ctx.

    Returns (stdout, stderr, returncode). Captures up to 4KB stdout and
    1KB stderr. Never raises — failures become ERROR-verdict checks
    upstream.

    Transport selection follows ``ctx.transport`` when present:
      - "winrm": route through the WinRM runner (Windows hosts)
      - "ssh"   (default): SSH with the key / port in ctx
      - "local": never invokes a remote transport (host must be local)
    """
    transport = getattr(ctx, "transport", "ssh") or "ssh"
    if transport == "winrm":
        from kryon.compliance.runners.winrm_runner import run_winrm_cmd

        return run_winrm_cmd(ctx, cmd, timeout_s=timeout_s)

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
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "UserKnownHostsFile=/tmp/kryon_known_hosts",
            "-o",
            "IdentitiesOnly=yes",
            "-p",
            str(ctx.ssh_port),
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
    ap.add_argument("--repro-check", type=int, default=0, help="Run N consecutive times and compare hashes.")
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
            print(f"run {i + 1}/{args.repro_check}  hash={h}")
            hashes.append(h)
        ok = len(set(hashes)) == 1
        print(f"reproducibility: {'PASS' if ok else 'FAIL'} — {len(set(hashes))} distinct hash(es)")
        return 0 if ok else 2

    results = run_all(ctx)
    h = reproducibility_hash(results)
    summary = {
        "host": args.host,
        "repro_hash": h,
        "checks": [{**r.to_json_reproducible(), "duration_ms": r.duration_ms, "run_id": r.run_id} for r in results],
        "summary": {v: sum(1 for r in results if r.verdict == v) for v in ("PASS", "FAIL", "N/A", "ERROR")},
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
        # F78 FortiGate (FortiOS) hardening — CIS Fortinet Benchmark
        "kryon.compliance.checks.fortigate.c_fgt_1_1_default_creds",
        "kryon.compliance.checks.fortigate.c_fgt_1_2_admin_https_only",
        "kryon.compliance.checks.fortigate.c_fgt_1_3_trusthost",
        "kryon.compliance.checks.fortigate.c_fgt_1_4_2fa_enforced",
        "kryon.compliance.checks.fortigate.c_fgt_1_5_admin_idle_timeout",
        "kryon.compliance.checks.fortigate.c_fgt_1_6_super_admin_count",
        "kryon.compliance.checks.fortigate.c_fgt_2_1_iface_allowaccess",
        "kryon.compliance.checks.fortigate.c_fgt_2_2_snmp_community",
        "kryon.compliance.checks.fortigate.c_fgt_2_3_ntp_auth",
        "kryon.compliance.checks.fortigate.c_fgt_2_4_dns_servers",
        "kryon.compliance.checks.fortigate.c_fgt_3_1_sslvpn_tls_min",
        "kryon.compliance.checks.fortigate.c_fgt_3_2_sslvpn_mfa",
        "kryon.compliance.checks.fortigate.c_fgt_3_3_sslvpn_portal_exposure",
        "kryon.compliance.checks.fortigate.c_fgt_3_4_sslvpn_policy_source",
        "kryon.compliance.checks.fortigate.c_fgt_3_5_sslvpn_timeouts",
        "kryon.compliance.checks.fortigate.c_fgt_4_1_syslog_upstream",
        "kryon.compliance.checks.fortigate.c_fgt_4_2_log_storage",
        "kryon.compliance.checks.fortigate.c_fgt_4_3_log_retention",
        "kryon.compliance.checks.fortigate.c_fgt_5_1_fortios_version_currency",
        "kryon.compliance.checks.fortigate.c_fgt_5_2_fortiguard_licenses",
        "kryon.compliance.checks.fortigate.c_fgt_5_3_known_cve_exposure",
        # F84 OT/ICS — Modbus/TCP audit (Sprint 1: 2 checks)
        "kryon.compliance.checks.ot.modbus.c_mod_1_1_unauth_read",
        "kryon.compliance.checks.ot.modbus.c_mod_1_2_device_identification",
        # F84 OT/ICS — DNP3 audit (Sprint 2: 2 checks)
        "kryon.compliance.checks.ot.dnp3.c_dnp3_1_1_unauth_read",
        "kryon.compliance.checks.ot.dnp3.c_dnp3_2_1_device_health",
        # F84 OT/ICS — Siemens S7Comm audit (Sprint 3: 2 checks)
        "kryon.compliance.checks.ot.s7.c_s7_1_1_anonymous_session",
        "kryon.compliance.checks.ot.s7.c_s7_2_1_firmware_currency",
        # F84 OT/ICS — IEC 60870-5-104 audit (Sprint 4: 2 checks)
        "kryon.compliance.checks.ot.iec104.c_iec104_1_1_anonymous_session",
        "kryon.compliance.checks.ot.iec104.c_iec104_2_1_perimeter_exposure",
        # F84 OT/ICS — MQTT industrial broker audit (Sprint 5: 2 checks)
        "kryon.compliance.checks.ot.mqtt.c_mqtt_1_1_anonymous_connect",
        "kryon.compliance.checks.ot.mqtt.c_mqtt_2_1_sys_topic_disclosure",
        # F79 Unifi (Ubiquiti) controller + WiFi configuration audit
        "kryon.compliance.checks.unifi.c_unf_1_1_default_creds",
        "kryon.compliance.checks.unifi.c_unf_1_2_controller_internet_exposure",
        "kryon.compliance.checks.unifi.c_unf_1_3_admin_2fa",
        "kryon.compliance.checks.unifi.c_unf_1_4_controller_firmware",
        "kryon.compliance.checks.unifi.c_unf_1_5_auto_backup",
        "kryon.compliance.checks.unifi.c_unf_2_1_wpa_mode",
        "kryon.compliance.checks.unifi.c_unf_2_2_wpa_passphrase_strength",
        "kryon.compliance.checks.unifi.c_unf_2_3_wps_disabled",
        "kryon.compliance.checks.unifi.c_unf_2_4_wpa3_available",
        "kryon.compliance.checks.unifi.c_unf_2_5_open_ssid",
        "kryon.compliance.checks.unifi.c_unf_2_6_guest_isolation",
        "kryon.compliance.checks.unifi.c_unf_2_7_hide_ssid_only",
        "kryon.compliance.checks.unifi.c_unf_3_1_mgmt_vs_guest_vlan",
        "kryon.compliance.checks.unifi.c_unf_3_2_corp_guest_vlan_separation",
        "kryon.compliance.checks.unifi.c_unf_3_3_radius_hygiene",
        "kryon.compliance.checks.unifi.c_unf_3_4_inform_encryption",
        "kryon.compliance.checks.unifi.c_unf_4_1_remote_syslog",
        "kryon.compliance.checks.unifi.c_unf_4_2_ap_firmware_currency",
        # F198 Asterisk (VoIP) — 8 checks deterministicos
        "kryon.compliance.checks.asterisk.c_voip_1_1_anon_register",
        "kryon.compliance.checks.asterisk.c_voip_1_2_ami_default_secret",
        "kryon.compliance.checks.asterisk.c_voip_2_1_allowguest",
        "kryon.compliance.checks.asterisk.c_voip_2_2_alwaysauthreject",
        "kryon.compliance.checks.asterisk.c_voip_2_3_ami_wan_exposure",
        "kryon.compliance.checks.asterisk.c_voip_3_1_srtp_disabled",
        "kryon.compliance.checks.asterisk.c_voip_3_2_sip_tls_disabled",
        "kryon.compliance.checks.asterisk.c_voip_3_3_asterisk_version",
    ]
    import importlib

    for m in modules:
        try:
            importlib.import_module(m)
        except ImportError:
            # Check module not yet built — skip; registered_checks()
            # will only include what exists so far.
            pass

    # F39 — register YAML-based PCI-DSS 4.0 checks. Built per-call so the
    # framework gets the same `_REGISTERED_CHECKS` instance the runner
    # writes into (runner imported as __main__ vs library has separate
    # registries; see the comment at the bottom of this file).
    try:
        from pathlib import Path

        from kryon.compliance.cis import register_framework

        yaml_path = Path(__file__).resolve().parent / "cis" / "frameworks" / "pci-dss-4.0.yaml"
        if yaml_path.exists():
            register_framework(yaml_path)
    except Exception:
        # YAML framework optional — runner stays usable with hand-written
        # checks even if the loader/parsing fails for any reason.
        pass


if __name__ == "__main__":
    # Avoid double-instance gotcha: when python -m loads runner as __main__,
    # the check modules `from kryon.compliance.runner import register_check`
    # load runner AGAIN as a non-main module with its own _REGISTERED_CHECKS.
    # Dispatch to the non-main module's CLI so state is consistent.
    from kryon.compliance import runner as _r

    sys.exit(_r._cli())
