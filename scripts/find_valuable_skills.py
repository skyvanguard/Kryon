"""Find the most valuable skills we haven't imported yet."""
import json
import base64
import re
import sys

with open(sys.argv[1]) as f:
    raw = json.load(f)

content = base64.b64decode(raw["content"]).decode()
data = json.loads(content)
skills = data.get("skills", [])

# Already imported (from both batches)
already = {
    "collecting-open-source-intelligence",
    "conducting-internal-reconnaissance-with-bloodhound-ce",
    "analyzing-memory-dumps-with-volatility",
    "analyzing-network-traffic-with-wireshark",
    "bypassing-authentication-with-forced-browsing",
    "detecting-credential-dumping-techniques",
    "conducting-api-security-testing",
    "detecting-api-enumeration-attacks",
    "conducting-domain-persistence-with-dcsync",
    "detecting-kerberoasting-attacks",
    "exploiting-active-directory-certificate-services-esc1",
    "performing-hash-cracking-with-hashcat",
    "auditing-aws-s3-bucket-permissions",
    "performing-aws-privilege-escalation-assessment",
    "analyzing-cobalt-strike-beacon-configuration",
    "analyzing-linux-elf-malware",
    "acquiring-disk-image-with-dd-and-dcfldd",
    "analyzing-browser-forensics-with-hindsight",
    "conducting-spearphishing-simulation-campaign",
    "deobfuscating-javascript-malware",
    "detecting-lateral-movement-in-network",
}

# High-value patterns by theme for what remains
valuable_patterns = {
    "IMMEDIATE — Common attacks": [
        r"sqli|sql-injection",
        r"cross-site-script|\bxss\b",
        r"server-side-request-forge|\bssrf\b",
        r"xml-external-entity|\bxxe\b",
        r"command-injection",
        r"insecure-deserialization",
        r"path-traversal",
        r"\bldap.*injection\b",
    ],
    "IMMEDIATE — Web app specific": [
        r"jwt.*attack|jwt.*vulnerab",
        r"oauth.*attack|oauth.*vulnerab",
        r"graphql-introspection",
        r"webhook.*abuse",
        r"http-request-smuggling",
        r"open-redirect",
        r"subdomain-takeover",
        r"\brace-condition\b",
    ],
    "IMMEDIATE — Privilege escalation": [
        r"linux.*priv.*esc",
        r"windows.*priv.*esc",
        r"sudo.*misconfig",
        r"suid.*exploit",
        r"kernel.*exploit",
        r"dirty.*cow|dirty.*pipe",
    ],
    "HIGH — SIEM and hunting": [
        r"splunk-search|splunk-query",
        r"elastic-search-query",
        r"threat-hunting",
        r"yara-rule",
        r"sigma-rule",
        r"anomaly-detection",
    ],
    "HIGH — Incident Response": [
        r"incident-response-playbook",
        r"triage",
        r"containment",
        r"eradication",
        r"recovery",
        r"ransomware-response",
    ],
    "HIGH — Container / Cloud": [
        r"docker-container-escape|docker-forensic",
        r"kubernetes-audit|k8s-security",
        r"cloud-metadata",
        r"terraform-misconfig",
        r"s3-misconfigur",
        r"gcp|google-cloud",
        r"azure-.*exploit|azure-.*privilege",
    ],
    "HIGH — Network forensics": [
        r"dns-tunneling|dns-exfiltration",
        r"icmp-tunneling",
        r"zeek",
        r"suricata-rule",
        r"netflow-analysis",
        r"packet-capture-analy",
    ],
    "HIGH — Memory/Binary": [
        r"volatility-plugin",
        r"ghidra-script",
        r"radare2|r2pipe",
        r"frida-hook",
        r"pe-file-analy|elf-analysis",
        r"buffer-overflow",
    ],
    "MEDIUM — Mobile": [
        r"android-.*analy|android-.*malware",
        r"ios-.*analy|ios-.*app",
        r"apk-.*",
        r"frida-hook",
        r"mobsf",
    ],
    "MEDIUM — Specialized": [
        r"ransomware.*encrypt|ransomware.*behav",
        r"rootkit.*analy|rootkit.*detect",
        r"bootkit",
        r"firmware-analysis",
        r"iot-device-analy",
        r"ics|scada|modbus",
    ],
    "MEDIUM — Hardening": [
        r"linux-.*harden|linux-.*secur",
        r"windows-.*harden|windows-.*secur",
        r"docker-.*harden|docker-.*secur",
        r"web-server-harden|nginx-secur|apache-secur",
        r"database-harden|mysql-secur|postgres-secur",
    ],
    "MEDIUM — OSINT variants": [
        r"github-.*enumerat|github-.*search",
        r"social-media-.*intel",
        r"dark-web-",
        r"breach-data-",
        r"whois-.*enumer",
    ],
}

results = {theme: [] for theme in valuable_patterns}

for skill in skills:
    name = skill["name"]
    if name in already:
        continue
    text = f"{name} {skill.get('description','')}".lower()
    for theme, patterns in valuable_patterns.items():
        for p in patterns:
            if re.search(p, text):
                results[theme].append(name)
                break
        if name in results[theme]:
            break

for theme, items in results.items():
    if not items:
        continue
    print(f"\n=== {theme} ({len(items)}) ===")
    for n in items[:8]:
        print(f"  - {n}")
