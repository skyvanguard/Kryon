"""Crosswalk: Kryon deterministic checks → CIS Controls v8.1 safeguards.

CIS Controls v8.1 is ~half governance/process. Many safeguards can only be
verified by interview or document review (``verdict_mode == "manual"``). This
module covers the *technically auditable* slice: it maps the control ids that
Kryon's deterministic check runner already emits (PCI numeric, AD-, FGT-,
PVE-, UNF-, WIN-, TOMCAT-, VOIP-, OT) onto the CIS v8.1 safeguards they
provide evidence for, then aggregates a verdict per safeguard.

Design contract (matches the project's conservative, precision-over-recall
posture):
  - A safeguard is reported ``verdict_mode == "auto"`` ONLY if at least one
    mapped check actually ran. Everything else stays ``"manual"`` and is
    surfaced as such — we never imply an automated verdict for a governance
    control.
  - Aggregation is fail-closed: any mapped FAIL ⇒ safeguard FAIL.

The mapping is intentionally one-directional and many-to-many: one check can
evidence several safeguards, and one safeguard can be evidenced by several
checks across different technologies.
"""

from __future__ import annotations

from kryon.compliance.cis_controls import CIS_CONTROLS

# control_id emitted by the runner → CIS v8.1 safeguard ids (bare, no "CIS-").
# Keep entries defensible; omit a mapping rather than force a weak one.
CHECK_TO_SAFEGUARD: dict[str, list[str]] = {
    # --- PCI numeric baseline (F15.1 / F39) ---
    "1.2.5": ["4.8"],  # only necessary services/ports
    "1.3.1": ["4.4"],  # firewall between trusted/untrusted
    "1.4.3": ["4.4"],  # anti-spoofing / rpf
    "1.4.4": ["4.4", "12.2"],  # restrict public access to CDE
    "2.2.1": ["8.4"],  # NTP / time sync
    "2.2.2": ["4.7"],  # vendor default accounts
    "2.2.4": ["4.8"],  # only necessary daemons
    "2.2.5": ["4.8"],  # insecure services (telnet/rsh) absent
    "2.2.6": ["4.1"],  # kernel hardening (secure config)
    "2.2.7": ["3.10", "12.6"],  # encrypted non-console admin
    "2.2.8": ["4.1"],  # brute-force protection (config hardening)
    "2.3.1": ["4.7"],  # wireless vendor defaults changed
    "3.5.1": ["3.11"],  # disk encryption (LUKS)
    "3.5.2": ["3.11"],  # swap encrypted
    "4.2.1": ["3.10"],  # TLS 1.2+ enforced
    "5.2.1": ["10.1"],  # anti-malware deployed
    "6.3.3": ["7.3", "7.4"],  # critical patches within 30 days
    "6.3.4": ["7.3", "7.4"],  # unattended security upgrades
    "6.4.1": ["4.1"],  # public web app hardening (HSTS/CSP/XFO)
    "6.4.3": ["16.11"],  # payment page script integrity (SRI)
    "6.5.1": ["8.3"],  # audit-log storage headroom
    "8.2.1": ["5.4"],  # no shared/generic accounts
    "8.3.1": ["5.2"],  # key-based SSH only
    "8.3.4": ["5.2"],  # password min length
    "8.3.5": ["5.2"],  # account lockout
    "8.3.6": ["5.2"],  # password complexity
    "8.3.7": ["5.2"],  # password history
    "8.3.9": ["5.2"],  # password rotation
    "8.4.1": ["6.5"],  # MFA for non-console admin
    "8.4.2": ["6.4"],  # MFA for all non-console access
    "8.4.3": ["6.5"],  # phishing-resistant MFA (admin entry)
    "8.6.1": ["5.4"],  # interactive login for service accts disabled
    "10.2.1": ["8.2", "8.5"],  # audit trails
    "10.2.1.1": ["8.5"],  # log access to CHD
    "10.2.1.2": ["8.5"],  # log privileged actions
    "10.2.1.3": ["8.5"],  # log access to audit trails
    "10.2.1.4": ["8.5"],  # log failed logins
    "10.2.2": ["8.9"],  # syslog daemon (central collection)
    "10.3.1": ["8.2"],  # protect audit logs
    "10.4.1.1": ["8.11"],  # scheduled log reviews
    "10.5.1": ["8.10"],  # log retention >= 12 months
    "10.6.1": ["8.4"],  # time sync in use
    "10.6.2": ["8.4"],  # authoritative time source
    "11.5.1": ["13.3"],  # IDS/IPS deployed (network)
    "11.5.2": ["8.5"],  # file integrity monitoring
    "11.6.1": ["16.11"],  # web page tampering detection (CSP/SRI)
    # --- Active Directory (F24) ---
    "AD-1.1": ["3.10"],  # LDAP signing (integrity in transit)
    "AD-1.2": ["3.10"],  # LDAPS available
    "AD-1.3": ["4.7"],  # anonymous bind rejected
    "AD-2.1": ["5.2"],  # no weak kerberoastable creds
    "AD-2.2": ["5.2"],  # krbtgt rotation
    "AD-3.1": ["5.4", "6.8"],  # Domain Admins <= 5
    "AD-3.2": ["5.2"],  # domain password policy
    "AD-4.1": ["3.10"],  # SMB signing (NTLM-relay mitigation)
    "AD-5.1": ["8.5"],  # AD audit events logged
    # --- FortiGate (F78) ---
    "FGT-1.1": ["4.7"],  # no default admin password
    "FGT-1.2": ["3.10", "12.6"],  # admin GUI HTTPS only
    "FGT-1.3": ["12.6"],  # admin source-IP trusthost
    "FGT-1.4": ["6.5"],  # admin MFA
    "FGT-1.5": ["4.3"],  # admin idle timeout
    "FGT-1.6": ["5.4"],  # <=2 super_admin accounts
    "FGT-2.1": ["4.8", "12.6"],  # no http/telnet in allowaccess
    "FGT-2.2": ["4.7"],  # SNMP community not trivial
    "FGT-2.3": ["8.4"],  # NTP authentication
    "FGT-2.4": ["9.2"],  # internal DNS resolvers
    "FGT-3.1": ["3.10"],  # SSL VPN refuses TLS 1.0/1.1
    "FGT-3.2": ["6.4"],  # SSL VPN MFA
    "FGT-3.3": ["12.2"],  # SSL VPN portal exposure
    "FGT-3.4": ["12.2"],  # SSL VPN scoped source policy
    "FGT-3.5": ["4.3"],  # SSL VPN timeouts
    "FGT-4.1": ["8.9"],  # logs to upstream syslog/FortiAnalyzer
    "FGT-4.2": ["8.2"],  # logs healthy (not in conserve mode)
    "FGT-4.3": ["8.10"],  # log retention >= 90d
    "FGT-5.1": ["12.1"],  # FortiOS within supported window
    "FGT-5.2": ["10.1"],  # FortiGuard AV/IPS subscriptions
    "FGT-5.3": ["7.5", "12.1"],  # not exposed to mass-exploited CVEs
    # --- Proxmox (F23) ---
    "PVE-1.1": ["3.10"],  # web UI CA-signed cert
    "PVE-1.2": ["4.7"],  # privileged API requires auth
    "PVE-2.1": ["5.4"],  # key-based non-root SSH
    "PVE-3.1": ["6.5"],  # MFA for privileged users
    "PVE-3.2": ["6.8"],  # API tokens least-privilege
    "PVE-4.1": ["4.4"],  # datacenter firewall default-deny
    "PVE-5.1": ["12.1"],  # PVE version currency
    "PVE-6.1": ["12.2"],  # cluster quorum tie-breaker
    # --- Unifi (F79) ---
    "UNF-1.1": ["4.7"],  # controller default creds
    "UNF-1.2": ["12.2"],  # controller not internet-exposed
    "UNF-1.3": ["6.5"],  # admin 2FA
    "UNF-1.4": ["12.1"],  # controller firmware currency
    "UNF-1.5": ["11.2"],  # auto backup
    "UNF-2.1": ["3.10"],  # WPA2/3 (wireless encryption)
    "UNF-2.2": ["5.2"],  # WPA passphrase strength
    "UNF-2.3": ["4.8"],  # WPS disabled
    "UNF-2.4": ["3.10"],  # WPA3 available
    "UNF-2.5": ["3.10"],  # no open SSID
    "UNF-2.6": ["12.2"],  # guest isolation
    "UNF-3.1": ["12.2"],  # mgmt vs guest VLAN
    "UNF-3.2": ["12.2"],  # corp/guest VLAN separation
    "UNF-3.3": ["6.4"],  # RADIUS hygiene
    "UNF-3.4": ["3.10"],  # inform encryption
    "UNF-4.1": ["8.9"],  # remote syslog
    "UNF-4.2": ["12.1"],  # AP firmware currency
    # --- Windows Server / endpoint (F199) ---
    "WIN-1.1": ["4.8"],  # SMBv1 disabled
    "WIN-1.2": ["4.1"],  # LSA Protection
    "WIN-1.3": ["4.8"],  # DC Print Spooler off (PrintNightmare)
    "WIN-2.1": ["10.1"],  # Defender RTP
    "WIN-2.2": ["4.5"],  # domain firewall
    "WIN-2.3": ["3.11"],  # BitLocker
    "WIN-2.4": ["4.1"],  # LLMNR disabled
    "WIN-2.5": ["7.3"],  # WSUS not over internet
    "WIN-3.1": ["4.1"],  # GPO refresh
    "WIN-3.2": ["5.2"],  # LAPS
    "WIN-3.3": ["8.5"],  # audit policy
    "WIN-3.4": ["6.4"],  # RDP NLA
    "WIN-3.5": ["4.1"],  # UAC
    "WIN-4.1": ["4.8"],  # Remote Registry disabled
    "WIN-4.2": ["10.7"],  # EDR behaviour-based detection
    # --- Apache Tomcat (F200.A) ---
    "TOMCAT-1.1": ["7.4"],  # Tomcat EOL version
    "TOMCAT-1.2": ["7.5"],  # AJP Ghostcat CVE-2020-1938
    "TOMCAT-1.3": ["4.8"],  # Manager app exposed
    "TOMCAT-1.4": ["4.8"],  # Host Manager exposed
    "TOMCAT-2.1": ["4.1"],  # error page version leak
    "TOMCAT-2.2": ["4.1"],  # Server header disclosure
    "TOMCAT-2.3": ["4.8"],  # /docs deployed
    "TOMCAT-2.4": ["4.8"],  # /examples deployed
    # --- Asterisk VoIP (F198) ---
    "VOIP-1.1": ["4.7"],  # anonymous SIP register
    "VOIP-1.2": ["4.7"],  # AMI default secret
    "VOIP-2.1": ["4.8"],  # allowguest
    "VOIP-2.2": ["4.1"],  # alwaysauthreject
    "VOIP-2.3": ["12.2"],  # AMI WAN exposure
    "VOIP-3.1": ["3.10"],  # SRTP (media encryption)
    "VOIP-3.2": ["3.10"],  # SIP-TLS
    "VOIP-3.3": ["7.4"],  # Asterisk version currency
    # --- OT/ICS (F84) ---
    "MOD-1.1": ["12.2"],  # Modbus unauth read (segmentation)
    "DNP3-1.1": ["12.2"],  # DNP3 unauth read
    "S7-1.1": ["12.2"],  # S7 anonymous session
    "IEC104-1.1": ["12.2"],  # IEC-104 anonymous activation
    "MQTT-1.1": ["4.7"],  # MQTT anonymous connect
}

# Verdict precedence for aggregation (fail-closed).
_PRECEDENCE = {"FAIL": 3, "ERROR": 2, "PASS": 1, "N/A": 0}


def _valid_safeguard_ids() -> set[str]:
    return {c.safeguard for c in CIS_CONTROLS}


def validate_crosswalk() -> list[str]:
    """Return crosswalk target ids that are NOT real v8.1 safeguards (should be empty)."""
    valid = _valid_safeguard_ids()
    bad: set[str] = set()
    for targets in CHECK_TO_SAFEGUARD.values():
        bad.update(t for t in targets if t not in valid)
    return sorted(bad)


def _aggregate(verdicts: list[str]) -> str:
    """Fail-closed aggregation of mapped check verdicts."""
    if not verdicts:
        return "N/A"
    return max(verdicts, key=lambda v: _PRECEDENCE.get(v, 0))


def map_results_to_safeguards(check_results: list) -> list[dict]:
    """Aggregate a list of ``CheckResult`` onto CIS v8.1 safeguards.

    ``check_results`` is whatever ``runner.run_all`` returned. Each object
    must expose ``.control_id`` and ``.verdict``. Returns one dict per
    safeguard (all 153), in catalog order.
    """
    # control_id -> verdict (last wins; runner ids are unique anyway)
    by_check: dict[str, str] = {r.control_id: r.verdict for r in check_results}

    # safeguard id -> list of (check_id, verdict) that evidence it
    evidence: dict[str, list[tuple[str, str]]] = {}
    for check_id, verdict in by_check.items():
        for sg in CHECK_TO_SAFEGUARD.get(check_id, []):
            evidence.setdefault(sg, []).append((check_id, verdict))

    out: list[dict] = []
    for ctrl in CIS_CONTROLS:
        sg = ctrl.safeguard
        mapped = evidence.get(sg, [])
        if mapped:
            verdict = _aggregate([v for _, v in mapped])
            mode = "auto"
        else:
            verdict = "MANUAL"
            mode = "manual"
        out.append(
            {
                "safeguard": sg,
                "id": ctrl.id,
                "control": int(sg.split(".")[0]),
                "title": ctrl.title,
                "category": ctrl.category,
                "implementation_group": ctrl.implementation_group,
                "security_function": ctrl.security_function,
                "asset_type": ctrl.asset_type,
                "verdict": verdict,
                "verdict_mode": mode,
                "evidence_checks": [{"check_id": cid, "verdict": v} for cid, v in sorted(mapped)],
            }
        )
    return out


def audit_cis_controls(ctx) -> dict:
    """Run every deterministic check against ``ctx`` and crosswalk to CIS v8.1.

    Returns a dict with the per-safeguard verdicts, an AUTO/MANUAL coverage
    breakdown, and the reproducibility hash of the underlying check run.
    """
    from kryon.compliance.runner import (
        _import_all_checks,
        reproducibility_hash,
        run_all,
    )

    _import_all_checks()
    results = run_all(ctx)
    safeguards = map_results_to_safeguards(results)

    auto = [s for s in safeguards if s["verdict_mode"] == "auto"]
    summary = {
        "total_safeguards": len(safeguards),
        "auto_covered": len(auto),
        "manual_required": len(safeguards) - len(auto),
        "auto_pass": sum(1 for s in auto if s["verdict"] == "PASS"),
        "auto_fail": sum(1 for s in auto if s["verdict"] == "FAIL"),
        "auto_error": sum(1 for s in auto if s["verdict"] == "ERROR"),
        "auto_na": sum(1 for s in auto if s["verdict"] == "N/A"),
    }
    return {
        "framework": "CIS Controls v8.1",
        "host": getattr(ctx, "host", ""),
        "repro_hash": reproducibility_hash(results),
        "checks_run": len(results),
        "summary": summary,
        "safeguards": safeguards,
    }
