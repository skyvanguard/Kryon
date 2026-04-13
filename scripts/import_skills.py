"""Import selected skills from the upstream mukul975 repo to Kryon's format.

Downloads SKILL.md for each curated skill, strips original frontmatter,
and writes to src/kryon/skills/playbooks/imported/ with Kryon-adapted
frontmatter (triggers + priority + required_tools).
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# -------- Curated picks with Kryon-adapted frontmatter --------
# (upstream_name, kryon_name, frontmatter_yaml)
SKILLS: list[tuple[str, str, str]] = [
    # --- Web Offensive ---
    (
        "conducting-api-security-testing",
        "api-security-testing",
        """name: api-security-testing
description: "API pentesting — REST/GraphQL, auth bypass, BOLA/IDOR, rate limiting"
triggers:
  tech: []
  ports: [8080, 8443, 3000, 5000, 8000]
  keywords: ["api", "rest", "graphql", "bola", "idor", "broken auth", "api security", "postman"]
priority: 18
required_tools:
  - run_command
  - nuclei_scan""",
    ),
    (
        "detecting-api-enumeration-attacks",
        "detect-api-enum",
        """name: detect-api-enum
description: "Detección de enumeración de APIs — scraping, token theft, brute force"
triggers:
  tech: []
  keywords: ["api enum", "token theft", "rate limit", "api abuse"]
priority: 30
required_tools:
  - run_command
  - query_knowledge_base""",
    ),
    # --- Network Offensive ---
    (
        "conducting-domain-persistence-with-dcsync",
        "dcsync-attack",
        """name: dcsync-attack
description: "DCSync — replicación de credenciales desde Domain Controller"
triggers:
  tech: ["active-directory", "windows"]
  keywords: ["dcsync", "domain replication", "krbtgt", "golden ticket"]
priority: 22
required_tools:
  - run_command
  - execute_code""",
    ),
    (
        "detecting-kerberoasting-attacks",
        "detect-kerberoast",
        """name: detect-kerberoast
description: "Detección de Kerberoasting — SPN abuse, TGS-REQ anomalies"
triggers:
  tech: ["active-directory", "kerberos"]
  ports: [88]
  keywords: ["kerberoast", "spn", "tgs", "service ticket"]
priority: 25
required_tools:
  - run_command""",
    ),
    # --- AD Windows ---
    (
        "exploiting-active-directory-certificate-services-esc1",
        "ad-cs-esc1",
        """name: ad-cs-esc1
description: "AD Certificate Services ESC1 exploitation — vulnerable cert templates"
triggers:
  tech: ["active-directory", "windows"]
  ports: [80, 443]
  keywords: ["adcs", "certificate services", "esc1", "esc8", "certifried"]
priority: 22
required_tools:
  - run_command""",
    ),
    # --- Credentials ---
    (
        "performing-hash-cracking-with-hashcat",
        "hash-cracking",
        """name: hash-cracking
description: "Password cracking con hashcat — MD5, NTLM, bcrypt, wpa handshakes"
triggers:
  tech: []
  keywords: ["hashcat", "crack password", "hash crack", "password spray", "john the ripper"]
priority: 20
required_tools:
  - run_command""",
    ),
    # --- Cloud Offensive ---
    (
        "auditing-aws-s3-bucket-permissions",
        "aws-s3-audit",
        """name: aws-s3-audit
description: "AWS S3 bucket security audit — ACLs, policies, public access"
triggers:
  tech: ["aws"]
  keywords: ["s3", "aws bucket", "bucket audit", "s3 misconfig"]
priority: 20
required_tools:
  - run_command""",
    ),
    (
        "performing-aws-privilege-escalation-assessment",
        "aws-privesc",
        """name: aws-privesc
description: "AWS privilege escalation assessment — IAM, Lambda, EC2 instance roles"
triggers:
  tech: ["aws"]
  keywords: ["aws privesc", "iam privilege", "aws lateral", "ec2 role", "lambda privesc"]
priority: 22
required_tools:
  - run_command""",
    ),
    # --- Malware Analysis ---
    (
        "analyzing-cobalt-strike-beacon-configuration",
        "cobalt-strike-beacon",
        """name: cobalt-strike-beacon
description: "Análisis de Cobalt Strike beacons — extracción de config, C2, profiles"
triggers:
  tech: []
  keywords: ["cobalt strike", "beacon config", "malleable c2", "red team c2"]
priority: 30
required_tools:
  - run_command
  - execute_code""",
    ),
    (
        "analyzing-linux-elf-malware",
        "linux-malware-analysis",
        """name: linux-malware-analysis
description: "Análisis estático/dinámico de malware Linux ELF"
triggers:
  tech: ["linux"]
  keywords: ["elf malware", "linux malware", "ghidra", "radare2", "strings analysis"]
priority: 30
required_tools:
  - run_command
  - execute_code""",
    ),
    # --- Forensics DFIR ---
    (
        "acquiring-disk-image-with-dd-and-dcfldd",
        "disk-imaging",
        """name: disk-imaging
description: "Imagen forense bit-a-bit con dd/dcfldd — chain of custody, hashing"
triggers:
  tech: []
  keywords: ["disk image", "dd", "dcfldd", "forensic image", "chain of custody"]
priority: 28
required_tools:
  - run_command""",
    ),
    (
        "analyzing-browser-forensics-with-hindsight",
        "browser-forensics",
        """name: browser-forensics
description: "Browser forensics — historial, cookies, caches con Hindsight"
triggers:
  tech: []
  keywords: ["browser forensic", "chrome history", "firefox forensic", "hindsight"]
priority: 28
required_tools:
  - run_command
  - execute_code""",
    ),
    # --- Email Phishing ---
    (
        "conducting-spearphishing-simulation-campaign",
        "spearphishing-sim",
        """name: spearphishing-sim
description: "Campaña de spearphishing autorizada — gophish, payloads, landing pages"
triggers:
  tech: []
  keywords: ["phishing", "spearphish", "gophish", "social engineering", "email campaign"]
priority: 25
required_tools:
  - run_command
  - execute_code""",
    ),
    # --- Exploitation ---
    (
        "deobfuscating-javascript-malware",
        "js-deobfuscation",
        """name: js-deobfuscation
description: "Deobfuscación de malware JavaScript — eval unpacking, AST analysis"
triggers:
  tech: []
  keywords: ["javascript malware", "js deobfusc", "unpack js", "obfuscated"]
priority: 30
required_tools:
  - run_command
  - execute_code""",
    ),
    # --- Detect / SIEM ---
    (
        "detecting-lateral-movement-in-network",
        "detect-lateral-movement",
        """name: detect-lateral-movement
description: "Detección de lateral movement en red — WMI, PsExec, SMB abuse patterns"
triggers:
  tech: []
  keywords: ["lateral movement", "wmi abuse", "psexec", "smb lateral", "detection"]
priority: 25
required_tools:
  - run_command
  - query_knowledge_base""",
    ),
]


def fetch_skill(upstream_name: str) -> str | None:
    """Download SKILL.md from upstream via gh CLI."""
    result = subprocess.run(
        [
            "gh",
            "api",
            f"repos/mukul975/Anthropic-Cybersecurity-Skills/contents/skills/{upstream_name}/SKILL.md",
            "--jq",
            ".content",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"  ❌ fetch failed: {result.stderr[:100]}")
        return None
    try:
        decoded = base64.b64decode(result.stdout.strip()).decode("utf-8")
        return decoded
    except Exception as e:
        print(f"  ❌ decode failed: {e}")
        return None


def strip_frontmatter(content: str) -> str:
    """Remove original YAML frontmatter (between the first two --- lines)."""
    match = re.match(r"^---\s*\n.*?\n---\s*\n", content, re.DOTALL)
    if match:
        return content[match.end():]
    return content


def main():
    output_dir = Path(__file__).parent.parent / "src" / "kryon" / "skills" / "playbooks" / "imported"
    output_dir.mkdir(parents=True, exist_ok=True)

    imported = 0
    for upstream, kryon_name, frontmatter in SKILLS:
        target = output_dir / f"{kryon_name}.md"
        if target.exists():
            print(f"⏭️  {kryon_name}: already exists, skipping")
            continue
        print(f"⬇️  {kryon_name} (from {upstream})")
        content = fetch_skill(upstream)
        if not content:
            continue
        body = strip_frontmatter(content)
        full = f"---\n{frontmatter}\n---\n\n{body}"
        target.write_text(full, encoding="utf-8")
        print(f"   ✅ {target.name} ({len(body)} chars body)")
        imported += 1

    print(f"\nDone: {imported} skills imported.")


if __name__ == "__main__":
    main()
