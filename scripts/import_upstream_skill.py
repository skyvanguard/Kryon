"""F202.AF — Transform upstream Anthropic-Cybersecurity-Skills SKILL.md to Kryon format.

Maps:
  upstream `tags[]` -> Kryon `triggers.keywords[]` (auto-extended with
                                                   common synonyms)
  upstream `subdomain` -> additional triggers keyword
  Priority assigned per skill name (banking-critical = 5,
                                    generic = 15)
  Apache-2.0 license + author + nist_csf preserved at top of body.

Uso:
    python scripts/import_upstream_skill.py \
        --upstream /tmp/upstream-skills/Anthropic-Cybersecurity-Skills \
        --out src/kryon/skills/playbooks/imported \
        --slug testing-api-security-with-owasp-top-10 \
        --priority 5

    # Batch (all candidates from F202.AE):
    python scripts/import_upstream_skill.py --upstream ... --batch
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml


# Banking-critical candidates (priority=5)
BANKING_CRITICAL_PRIORITY_5: dict[str, str] = {
    "testing-api-security-with-owasp-top-10": "api-security-owasp-top-10",
    "implementing-pci-dss-compliance-controls": "pci-dss-controls-impl-v2",
    "auditing-kubernetes-cluster-rbac": "k8s-rbac-audit",
    "building-identity-federation-with-saml-azure-ad": "saml-federation-azure-ad",
    "implementing-saml-sso-with-okta": "saml-sso-okta",
    "securing-api-gateway-with-aws-waf": "api-gateway-aws-waf",
    "detecting-business-email-compromise": "bec-detection-v2",
}

# Useful-but-not-critical (priority=15)
USEFUL_PRIORITY_15: dict[str, str] = {
    "implementing-semgrep-for-custom-sast-rules": "semgrep-custom-sast",
    "integrating-sast-into-github-actions-pipeline": "sast-github-actions",
    "implementing-devsecops-security-scanning": "devsecops-scanning",
}


# Subdomain → extra keyword expansion (broadens trigger match).
_SUBDOMAIN_KEYWORDS = {
    "web-application-security": ["webapp", "web vulnerability", "http"],
    "cloud-security": ["cloud", "aws", "azure", "gcp"],
    "identity-and-access-management": ["iam", "sso", "auth", "authentication"],
    "compliance": ["compliance", "audit"],
    "container-security": ["container", "kubernetes", "docker"],
    "incident-response": ["incident", "ir", "dfir"],
    "malware-analysis": ["malware", "reverse-engineering"],
    "network-security": ["network", "firewall", "vpn"],
    "data-security": ["data", "encryption", "dlp"],
    "application-security": ["appsec", "code review"],
}


def parse_upstream_frontmatter(skill_md: Path) -> tuple[dict, str]:
    """Read upstream SKILL.md, return (frontmatter dict, body string)."""
    text = skill_md.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
    if not m:
        raise ValueError(f"No YAML frontmatter in {skill_md}")
    fm = yaml.safe_load(m.group(1))
    body = m.group(2).lstrip()
    return fm, body


def build_kryon_skill(upstream_fm: dict, body: str, *,
                     output_name: str, priority: int) -> str:
    """Compose Kryon-format playbook (frontmatter + body)."""
    upstream_name = upstream_fm.get("name", output_name)
    desc = (upstream_fm.get("description") or "").strip()
    if isinstance(desc, list):
        desc = " ".join(desc).strip()

    subdomain = upstream_fm.get("subdomain", "").strip()
    upstream_tags = upstream_fm.get("tags") or []

    # Build keyword list: original name + tags + subdomain expansion.
    keywords: list[str] = []
    keywords.append(upstream_name.replace("-", " "))  # e.g. "testing api security with owasp top 10"
    # Add tag keywords
    for tag in upstream_tags:
        keywords.append(str(tag))
    # Subdomain expansion
    if subdomain in _SUBDOMAIN_KEYWORDS:
        keywords.extend(_SUBDOMAIN_KEYWORDS[subdomain])
    # Always add the upstream short slug as keyword
    keywords.append(upstream_name)

    # Dedup preserving order
    seen: set[str] = set()
    uniq_kw = [k for k in keywords if not (k.lower() in seen or seen.add(k.lower()))]

    # Author + license + NIST-CSF attribution block
    author = upstream_fm.get("author", "unknown")
    license_ = upstream_fm.get("license", "Apache-2.0")
    nist_csf = upstream_fm.get("nist_csf") or []
    version = upstream_fm.get("version", "1.0")

    attribution = (
        f"> **Source**: Anthropic-Cybersecurity-Skills "
        f"`{upstream_name}` v{version} ({author}, {license_})\n"
        f"> **Upstream**: https://github.com/mukul975/Anthropic-Cybersecurity-Skills\n"
    )
    if nist_csf:
        attribution += f"> **NIST CSF**: {', '.join(nist_csf)}\n"

    # YAML frontmatter for Kryon
    fm_lines = [
        "---",
        f"name: {output_name}",
        f"description: \"{desc[:200]}\"",
        "triggers:",
        "  tech: []",
        "  ports: []",
        "  keywords:",
    ]
    for kw in uniq_kw:
        # Clean: lowercase, strip extras, quote
        cleaned = kw.strip().lower().replace('"', "'")
        if cleaned:
            fm_lines.append(f"    - \"{cleaned}\"")
    fm_lines.append(f"priority: {priority}")
    fm_lines.append("required_tools:")
    fm_lines.append("  - run_command")
    fm_lines.append("---")

    return "\n".join(fm_lines) + "\n\n" + attribution + "\n" + body.rstrip() + "\n"


def transform_one(upstream_dir: Path, slug: str, output_dir: Path,
                  output_name: str, priority: int) -> Path:
    skill_md = upstream_dir / "skills" / slug / "SKILL.md"
    if not skill_md.exists():
        raise FileNotFoundError(f"Upstream skill not found: {skill_md}")
    fm, body = parse_upstream_frontmatter(skill_md)
    kryon_skill = build_kryon_skill(fm, body, output_name=output_name, priority=priority)
    out_path = output_dir / f"{output_name}.md"
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path.write_text(kryon_skill, encoding="utf-8")
    return out_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", required=True, help="path to upstream repo clone")
    ap.add_argument("--out", default="src/kryon/skills/playbooks/imported")
    ap.add_argument("--slug", help="single upstream skill slug to import")
    ap.add_argument("--output-name", help="Kryon skill name (default: derived)")
    ap.add_argument("--priority", type=int, default=15)
    ap.add_argument("--batch", action="store_true",
                    help="import all F202.AE top-10 candidates")
    args = ap.parse_args()

    upstream = Path(args.upstream)
    out_dir = Path(args.out)

    if args.batch:
        all_targets = list(BANKING_CRITICAL_PRIORITY_5.items()) + list(USEFUL_PRIORITY_15.items())
        priorities = {
            **{k: 5 for k in BANKING_CRITICAL_PRIORITY_5},
            **{k: 15 for k in USEFUL_PRIORITY_15},
        }
        ok, fail = 0, 0
        for slug, output_name in all_targets:
            try:
                p = transform_one(upstream, slug, out_dir, output_name, priorities[slug])
                print(f"  OK   {slug} -> {p.name}")
                ok += 1
            except Exception as e:  # noqa: BLE001
                print(f"  FAIL {slug}: {e}")
                fail += 1
        print(f"\n{ok} imported, {fail} failed")
        return

    if not args.slug:
        ap.error("--slug required when not --batch")
    output_name = args.output_name or args.slug.replace("_", "-")
    p = transform_one(upstream, args.slug, out_dir, output_name, args.priority)
    print(f"Imported -> {p}")


if __name__ == "__main__":
    main()
