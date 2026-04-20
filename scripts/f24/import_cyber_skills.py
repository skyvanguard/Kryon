"""F24.0 — Cherry-pick 20 skills from mukul975/Anthropic-Cybersecurity-Skills.

Curated for the ASOBAN banking audit context. Each entry below has:
  - slug:     folder name on the upstream repo (skills/<slug>/SKILL.md)
  - short:    short filename we save locally (fits existing imported/ pattern)
  - triggers: YAML trigger block we ensure/override (some upstream SKILLs lack it)
  - priority: matcher priority; AD/compliance skills get higher priority
  - category: informational tag (ad, cloud, ir, email, tls, siem, api)

Workflow:
  1. Fetch SKILL.md from raw.githubusercontent.com.
  2. If upstream already has YAML frontmatter, merge our triggers in.
  3. Else, prepend our frontmatter.
  4. Write into src/kryon/skills/playbooks/imported/.
"""

from __future__ import annotations

import re
import sys
import urllib.request
from pathlib import Path


REPO_RAW = "https://raw.githubusercontent.com/mukul975/Anthropic-Cybersecurity-Skills/main/skills"

# Curated set — 20 skills relevant to ASOBAN banking audit scenarios.
# Structure: slug -> (short_name, triggers_dict, priority, category)
SKILLS: dict[str, tuple[str, dict, int, str]] = {
    # --- Active Directory (F24 plan) ---
    "analyzing-active-directory-acl-abuse": (
        "ad-acl-abuse",
        {"tech": ["active-directory", "ldap", "samba"], "ports": [389, 636, 3268, 3269],
         "keywords": ["ad acl", "active directory acl", "dacl", "bloodhound", "acl abuse"]},
        25, "ad",
    ),
    "configuring-active-directory-tiered-model": (
        "ad-tiered-model",
        {"tech": ["active-directory", "windows-server"], "ports": [389, 445, 88],
         "keywords": ["ad tiered", "tiered admin", "pam ad", "tier 0", "red forest"]},
        20, "ad",
    ),
    "configuring-ldap-security-hardening": (
        "ldap-hardening",
        {"tech": ["ldap", "openldap", "active-directory"], "ports": [389, 636],
         "keywords": ["ldap hardening", "ldap signing", "ldaps", "ldap secure"]},
        20, "ad",
    ),
    "detecting-kerberoasting-attacks": (
        "detect-kerberoasting",
        {"tech": ["kerberos", "active-directory"], "ports": [88],
         "keywords": ["kerberoast", "spn", "tgs", "kerberos hash"]},
        25, "ad",
    ),
    "detecting-dcsync-attack-in-active-directory": (
        "detect-dcsync",
        {"tech": ["active-directory"], "ports": [389, 445, 88],
         "keywords": ["dcsync", "drsuapi", "replicate changes", "krbtgt"]},
        30, "ad",
    ),
    "detecting-golden-ticket-attacks-in-kerberos-logs": (
        "detect-golden-ticket",
        {"tech": ["kerberos", "active-directory"], "ports": [88],
         "keywords": ["golden ticket", "krbtgt", "forged tgt", "kerberos abuse"]},
        25, "ad",
    ),
    "deploying-active-directory-honeytokens": (
        "ad-honeytokens",
        {"tech": ["active-directory"], "ports": [389, 445],
         "keywords": ["honeytoken", "ad deception", "canary account", "deceptive tripwire"]},
        15, "ad",
    ),
    "auditing-azure-active-directory-configuration": (
        "azure-ad-audit",
        {"tech": ["azure", "entra", "aad"], "ports": [],
         "keywords": ["azure ad", "entra", "aad audit", "m365 identity", "conditional access"]},
        25, "cloud",
    ),
    # --- Cloud (bancos LATAM usan Azure/AWS) ---
    "auditing-aws-s3-bucket-permissions": (
        "aws-s3-permissions",
        {"tech": ["aws", "s3"], "ports": [443],
         "keywords": ["s3 permissions", "bucket policy", "s3 public", "aws storage audit"]},
        20, "cloud",
    ),
    "detecting-aws-iam-privilege-escalation": (
        "aws-iam-privesc",
        {"tech": ["aws", "iam"], "ports": [],
         "keywords": ["aws privesc", "iam escalation", "sts assume", "iam passrole", "cloudtrail"]},
        25, "cloud",
    ),
    "detecting-azure-service-principal-abuse": (
        "azure-sp-abuse",
        {"tech": ["azure", "entra"], "ports": [],
         "keywords": ["service principal", "azure app registration", "sp abuse", "oauth azure"]},
        25, "cloud",
    ),
    "analyzing-azure-activity-logs-for-threats": (
        "azure-activity-log-threats",
        {"tech": ["azure", "log-analytics"], "ports": [],
         "keywords": ["azure activity log", "resource logs", "azure monitor", "sentinel"]},
        20, "cloud",
    ),
    # --- Incident Response (SIB requires) ---
    "building-incident-response-playbook": (
        "ir-playbook-build",
        {"tech": [], "ports": [],
         "keywords": ["incident response", "ir playbook", "csirt", "playbook ir", "respuesta incidente"]},
        20, "ir",
    ),
    "building-ransomware-playbook-with-cisa-framework": (
        "ransomware-playbook-cisa",
        {"tech": [], "ports": [],
         "keywords": ["ransomware", "cisa", "ransomware playbook", "lockbit", "conti"]},
        25, "ir",
    ),
    "conducting-phishing-incident-response": (
        "phishing-ir",
        {"tech": ["email"], "ports": [25, 465, 587, 993, 995],
         "keywords": ["phishing ir", "phishing response", "bec response", "email compromise"]},
        20, "ir",
    ),
    # --- Email / Phishing ---
    "analyzing-email-headers-for-phishing-investigation": (
        "email-header-analysis",
        {"tech": ["email", "smtp"], "ports": [25, 465, 587],
         "keywords": ["email headers", "spf", "dkim", "dmarc", "phishing header", "received"]},
        15, "email",
    ),
    # --- TLS / certs ---
    "configuring-tls-1-3-for-secure-communications": (
        "tls13-config",
        {"tech": ["nginx", "apache", "tls"], "ports": [443, 8443],
         "keywords": ["tls 1.3", "tls config", "ssl hardening", "cipher suite", "hsts"]},
        15, "tls",
    ),
    # --- SIEM ---
    "analyzing-security-logs-with-splunk": (
        "splunk-log-analysis",
        {"tech": ["splunk"], "ports": [8000, 8089],
         "keywords": ["splunk", "spl", "siem query", "threat hunt splunk"]},
        15, "siem",
    ),
    # --- API security / OAuth ---
    "conducting-api-security-testing": (
        "api-security-test",
        {"tech": ["rest", "graphql", "openapi"], "ports": [443, 8443],
         "keywords": ["api security", "owasp api", "bola", "api test", "open banking"]},
        20, "api",
    ),
    "configuring-oauth2-authorization-flow": (
        "oauth2-flow",
        {"tech": ["oauth", "oidc"], "ports": [443, 8443],
         "keywords": ["oauth2", "oidc", "pkce", "authorization code", "token exchange"]},
        15, "api",
    ),
}


def fetch(slug: str) -> str:
    url = f"{REPO_RAW}/{slug}/SKILL.md"
    req = urllib.request.Request(url, headers={"User-Agent": "kryon-f24"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode("utf-8", errors="replace")


def merge_frontmatter(body: str, name: str, triggers: dict, priority: int, category: str) -> str:
    """Ensure body starts with a Kryon-compatible YAML frontmatter block.

    If upstream already has `---...---`, we rewrite it with our triggers
    (keeping existing `description`). Otherwise we prepend one.
    """
    fm_re = re.compile(r"^---\n(.*?)\n---\n", re.S)
    m = fm_re.match(body)
    description = ""

    if m:
        for line in m.group(1).splitlines():
            if line.lower().startswith("description:"):
                description = line.split(":", 1)[1].strip().strip('"').strip("'")
                break
        body = body[m.end():]

    if not description:
        # Use first H1/H2 of body as description fallback
        m2 = re.search(r"^#{1,2}\s+(.+)$", body, re.M)
        description = (m2.group(1) if m2 else name).strip()[:140]

    # Build triggers YAML
    tech = ", ".join(f'"{t}"' for t in triggers.get("tech", [])) or ""
    ports = ", ".join(str(p) for p in triggers.get("ports", [])) or ""
    kw_lines = "\n".join(f"    - \"{k}\"" for k in triggers.get("keywords", []))

    new_fm = (
        f"---\n"
        f"name: {name}\n"
        f"description: \"{description}\"\n"
        f"triggers:\n"
        f"  tech: [{tech}]\n"
        f"  ports: [{ports}]\n"
        f"  keywords:\n{kw_lines}\n"
        f"priority: {priority}\n"
        f"category: {category}\n"
        f"source: mukul975/Anthropic-Cybersecurity-Skills\n"
        f"---\n\n"
    )
    return new_fm + body.lstrip("\n")


def main() -> int:
    out_dir = Path("src/kryon/skills/playbooks/imported")
    if not out_dir.exists():
        print(f"!! {out_dir} does not exist")
        return 2

    existing = {p.stem for p in out_dir.glob("*.md")}
    ok, skipped, failed = 0, 0, 0
    for slug, (short, triggers, priority, category) in SKILLS.items():
        dest = out_dir / f"{short}.md"
        if dest.exists():
            print(f"  SKIP  {short:<32} (already present)")
            skipped += 1
            continue
        try:
            body = fetch(slug)
            merged = merge_frontmatter(body, short, triggers, priority, category)
            dest.write_text(merged, encoding="utf-8")
            size = len(merged)
            print(f"  OK    {short:<32} ({category:<5} prio={priority})  {size}B")
            ok += 1
        except Exception as exc:
            print(f"  FAIL  {short:<32} {exc!r}"[:120])
            failed += 1

    print()
    print(f"imported: {ok}  skipped: {skipped}  failed: {failed}  total imported now: "
          f"{len(list(out_dir.glob('*.md')))}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
