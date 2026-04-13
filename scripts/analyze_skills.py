"""Analyze the 754 skills from mukul975 repo, categorize them for Kryon."""
import json
import re
import sys
import base64
from collections import defaultdict

with open(sys.argv[1]) as f:
    raw = json.load(f)

content = base64.b64decode(raw["content"]).decode()
data = json.loads(content)
skills = data.get("skills", [])
print(f"Total skills: {len(skills)}")

categories = defaultdict(list)

patterns = {
    "web_offensive": r"(sqli|xss|ssrf|xxe|csrf|\brce\b|\blfi\b|\brfi\b|idor|forced-brows|jwt-attack|oauth-token|graphql|api-gateway|waf-bypass|web-exploit|web-shell|sqlmap|burp|zap-scan|nikto|param-pollut|template-inject|http-request-smugg)",
    "network_offensive": r"(nmap|masscan|rustscan|bloodhound|kerberoast|asreproast|dcsync|dcshadow|ntlm-relay|mimikatz|lsass|sam-dump|pass-the-hash|lateral-move|pivot)",
    "cloud_offensive": r"(aws-privilege|azure-lateral|gcp-compromise|cloud-metadata|s3-bucket|iam-enum|lambda-exploit|ec2-metadata|cloud-storage-access|cloud-shell-escape)",
    "exploitation": r"(exploit-kit|payload-encoding|shellcode|rop-chain|buffer-overflow|heap-spray|use-after-free|format-string|binary-exploit|ghidra|radare|frida|ropper|pwntools|reverse-engineer)",
    "defense_detect": r"(detect|hunting|threat-hunt|siem|splunk|elastic|sigma|yara|suricata|zeek|snort|edr|xdr|soar-playbook)",
    "forensics_dfir": r"(forensic|volatility|autopsy|sleuthkit|disk-imag|memory-dump|timeline|usnjrnl|\bmft\b|prefetch|windows-registry|evidence|incident-response)",
    "malware_analysis": r"(malware|ransomware|unpack|deobfusc|cuckoo|sandbox|static-analy|dynamic-analy|cobalt-strike-beacon|malware-beacon)",
    "osint_intel": r"(osint|shodan|maltego|spiderfoot|recon-ng|certificate-transparency|threat-intel|apt-group|campaign-attrib)",
    "container_k8s": r"(docker-forensic|container-escape|kubernetes-audit|k8s|pod-security|kube-audit)",
    "credentials": r"(credential-dump|password-spray|hashcat|hydra-brute|credential-stuffing|mimikatz-dump|credential-harvest)",
    "hardening": r"(hardening|stig|cis-benchmark|secure-baseline|misconfiguration)",
    "mobile": r"(android|ios-app|apk|frida|objection|mobsf)",
    "ad_windows": r"(active-directory|windows-event|powershell-attack|wmi-attack|smb-attack|gpo-abuse)",
    "api_auth": r"(api-auth|\boauth\b|jwt|saml|oidc|token-theft|session-fix|session-hijack)",
    "network_traffic": r"(wireshark|tshark|pcap|packet-analy|netflow|tcpdump)",
    "vuln_mgmt": r"(cve-|patch-manage|vuln-assess|risk-scor|vulnerability-intel)",
    "email_phish": r"(phishing|spearphish|email-gateway|dmarc|\bspf\b|\bdkim\b|business-email)",
    "network_monitoring": r"(network-monitor|network-flow|dns-tunnel|dns-exfil|icmp-tunnel|covert-channel)",
    "iot_ot": r"(\biot\b|\bics\b|scada|modbus|industrial-control|smart-home)",
    "crypto_tls": r"(tls-analy|ssl-scan|cipher-|certificate-analy|cryptograph)",
}

uncategorized = []
for s in skills:
    text = f"{s['name']} {s.get('description', '')}".lower()
    matched = False
    for cat, pat in patterns.items():
        if re.search(pat, text):
            categories[cat].append(s["name"])
            matched = True
            break
    if not matched:
        uncategorized.append(s["name"])

print()
for cat, items in sorted(categories.items(), key=lambda x: -len(x[1])):
    print(f"{cat}: {len(items)}")
print(f"uncategorized: {len(uncategorized)}")

# Top picks per category (the most valuable 2-3 per category for Kryon)
print("\n=== RECOMMENDED IMPORTS ===")
priority_cats = [
    "web_offensive",
    "network_offensive",
    "exploitation",
    "forensics_dfir",
    "malware_analysis",
    "credentials",
    "ad_windows",
    "cloud_offensive",
    "email_phish",
    "network_traffic",
]
for cat in priority_cats:
    items = categories.get(cat, [])
    print(f"\n{cat}:")
    for name in items[:5]:
        print(f"  - {name}")
