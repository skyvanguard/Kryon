"""CIS Critical Security Controls **v8.1** catalog + finding→safeguard mapping.

The 18 controls / 153 safeguards are loaded from the authoritative Spanish
catalog at ``cis/catalog/cis_controls_v8.1.yaml`` (extracted from the official
CIS Controls v8.1 Spanish PDF and validated 18/18 against the per-control IG
summary tables — see ``scripts/extract_cis_controls_v81.py``).

This module is the *reporting / mapping* layer:
  - ``CIS_CONTROLS`` — every safeguard as a :class:`ComplianceControl`, with
    its Implementation Group, NIST CSF 2.0 security function (incl. the v8.1
    **Govern** function) and asset type (incl. the v8.1 **Documentation**
    class).
  - ``map_finding_to_cis_controls`` — keyword map from a :class:`Finding` to
    the safeguards it provides evidence against.

The *deterministic auditing* layer (which safeguards Kryon can actually verify
with a check, vs. which need manual/interview evidence) lives in
``cis/cis_controls_crosswalk.py`` — it flips ``verdict_mode`` to ``"auto"`` for
the safeguards it can map to a real check.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from kryon.compliance.models import ComplianceControl
from kryon.intelligence.models import Finding

FRAMEWORK_NAME = "CIS Controls v8.1"
FRAMEWORK_VERSION = "8.1"

_CATALOG_PATH = Path(__file__).resolve().parent / "cis" / "catalog" / "cis_controls_v8.1.yaml"

# Spanish security-function labels (as they appear in the PDF) → NIST CSF 2.0 EN.
_FUNCTION_ES_TO_EN = {
    "Identificar": "Identify",
    "Proteger": "Protect",
    "Detectar": "Detect",
    "Responder": "Respond",
    "Recuperar": "Recover",
    "Gobernar": "Govern",  # v8.1 addition (NIST CSF 2.0 alignment)
}


@lru_cache(maxsize=1)
def _load_catalog() -> dict:
    """Parse the v8.1 catalog YAML once."""
    with _CATALOG_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _build_controls() -> list[ComplianceControl]:
    data = _load_catalog()
    control_names = {c["id"]: c["name"] for c in data["controls"]}
    controls: list[ComplianceControl] = []
    for sg in data["safeguards"]:
        sg_id = sg["id"]  # e.g. "5.4"
        func_en = _FUNCTION_ES_TO_EN.get(sg["security_function"], sg["security_function"])
        controls.append(
            ComplianceControl(
                id=f"CIS-{sg_id}",
                title=sg["title"],
                description=sg["description"],
                category=control_names.get(sg["control"], f"Control {sg['control']}"),
                testing_procedures=[],
                expected_evidence=[],
                implementation_group=int(sg["ig"]),
                security_function=func_en,
                asset_type=sg.get("asset_type", ""),
                safeguard=sg_id,
                verdict_mode="manual",  # crosswalk flips technical safeguards to "auto"
            )
        )
    return controls


# 153 safeguards across the 18 CIS Controls v8.1.
CIS_CONTROLS: list[ComplianceControl] = _build_controls()


# Keyword → CIS Controls v8.1 safeguard id mapping (ids carry the "CIS-" prefix
# to match ComplianceControl.id). Used to attribute a finding to the
# safeguard(s) it provides evidence against, for reporting.
_CIS_KEYWORD_MAP: list[tuple[list[str], list[str]]] = [
    (
        [
            "asset inventory",
            "hardware inventory",
            "device inventory",
            "asset management",
            "cmdb",
            "rogue device",
            "unauthorized asset",
        ],
        ["CIS-1.1", "CIS-1.2"],
    ),
    (
        [
            "software inventory",
            "unauthorized software",
            "application allowlist",
            "application whitelisting",
            "shadow it",
            "unsupported software",
            "end of life",
            "eol",
        ],
        ["CIS-2.1", "CIS-2.3", "CIS-2.2"],
    ),
    (
        ["data classification", "sensitive data", "data inventory", "pii", "data leak", "dlp", "data retention"],
        ["CIS-3.1", "CIS-3.2", "CIS-3.7"],
    ),
    (
        ["encryption", "tls", "ssl", "plaintext", "unencrypted", "cipher", "certificate", "https", "data in transit"],
        ["CIS-3.10"],
    ),
    (
        ["encryption at rest", "disk encryption", "bitluffer", "bitlocker", "luks", "encrypt sensitive data at rest"],
        ["CIS-3.11"],
    ),
    (["misconfiguration", "hardening", "secure configuration", "baseline", "cis benchmark"], ["CIS-4.1", "CIS-4.2"]),
    (["default password", "default credential", "default account", "vendor default"], ["CIS-4.7"]),
    (
        ["firewall", "host firewall", "default deny", "automatic session locking", "session timeout"],
        ["CIS-4.4", "CIS-4.5", "CIS-4.3"],
    ),
    (["account inventory", "inactive account", "dormant account", "stale account"], ["CIS-5.1", "CIS-5.3"]),
    (
        [
            "privilege",
            "admin account",
            "root",
            "sudo",
            "privileged access",
            "escalation",
            "least privilege",
            "dedicated administrator",
        ],
        ["CIS-5.4", "CIS-6.8"],
    ),
    (["mfa", "multi-factor", "two-factor", "2fa"], ["CIS-6.3", "CIS-6.4", "CIS-6.5"]),
    (
        [
            "access control",
            "authorization",
            "idor",
            "permissions",
            "rbac",
            "access granting",
            "access revoking",
            "deprovision",
        ],
        ["CIS-6.1", "CIS-6.2", "CIS-6.7"],
    ),
    (
        ["vulnerability scan", "vulnerability management", "remediate vulnerabilities"],
        ["CIS-7.1", "CIS-7.5", "CIS-7.6", "CIS-7.7"],
    ),
    (["cve-", "unpatched", "outdated", "missing patch", "patch management", "automated patch"], ["CIS-7.3", "CIS-7.4"]),
    (
        ["logging", "audit log", "log management", "audit trail", "syslog", "log retention", "centralized log"],
        ["CIS-8.1", "CIS-8.2", "CIS-8.5", "CIS-8.9", "CIS-8.10"],
    ),
    (
        ["email", "dmarc", "spf", "dkim", "browser", "dns filtering", "url filtering", "email gateway"],
        ["CIS-9.1", "CIS-9.2", "CIS-9.3", "CIS-9.5", "CIS-9.7"],
    ),
    (
        ["malware", "trojan", "ransomware", "virus", "backdoor", "webshell", "antivirus", "edr", "anti-malware"],
        ["CIS-10.1", "CIS-10.2", "CIS-10.7"],
    ),
    (
        ["backup", "recovery", "disaster recovery", "restore", "data recovery", "offline backup"],
        ["CIS-11.1", "CIS-11.2", "CIS-11.3", "CIS-11.4"],
    ),
    (
        [
            "network device",
            "router",
            "switch",
            "network infrastructure",
            "firmware",
            "network architecture",
            "out of band",
        ],
        ["CIS-12.1", "CIS-12.2", "CIS-12.3", "CIS-12.8"],
    ),
    (
        [
            "siem",
            "ids",
            "ips",
            "network monitoring",
            "anomaly",
            "intrusion detection",
            "intrusion prevention",
            "netflow",
            "traffic analysis",
        ],
        ["CIS-13.1", "CIS-13.2", "CIS-13.3", "CIS-13.6", "CIS-13.11"],
    ),
    (
        ["security awareness", "phishing simulation", "social engineering training", "user training"],
        ["CIS-14.1", "CIS-14.2"],
    ),
    (
        ["service provider", "third party", "vendor management", "supply chain", "vendor inventory"],
        ["CIS-15.1", "CIS-15.2", "CIS-15.4", "CIS-15.5"],
    ),
    (
        [
            "sql injection",
            "xss",
            "injection",
            "rce",
            "ssrf",
            "csrf",
            "code review",
            "sast",
            "dast",
            "owasp",
            "secure sdlc",
            "application security",
            "insecure deserialization",
        ],
        ["CIS-16.1", "CIS-16.11", "CIS-16.12", "CIS-16.13"],
    ),
    (
        ["incident response", "incident handling", "breach", "containment", "incident reporting"],
        ["CIS-17.1", "CIS-17.2", "CIS-17.4"],
    ),
    (
        ["penetration test", "pen test", "pentest", "red team", "exploit validation"],
        ["CIS-18.1", "CIS-18.2", "CIS-18.3"],
    ),
]

# Only attribute findings to safeguards that actually exist in the catalog.
_VALID_IDS = {c.id for c in CIS_CONTROLS}


def map_finding_to_cis_controls(finding: Finding) -> list[str]:
    """Map a finding to CIS Controls v8.1 safeguard ids (``CIS-x.y``)."""
    text = f"{finding.title} {finding.description}".lower()
    matched: set[str] = set()
    for keywords, control_ids in _CIS_KEYWORD_MAP:
        if any(kw in text for kw in keywords):
            matched.update(cid for cid in control_ids if cid in _VALID_IDS)
    return sorted(matched)
