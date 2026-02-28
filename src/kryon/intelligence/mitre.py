"""MITRE ATT&CK mapping engine — keyword + pattern matching (no LLM required)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from kryon.intelligence.models import MITREMapping

_DATA_DIR = Path(__file__).parent / "data"

# ---------------------------------------------------------------------------
# Keyword → technique mapping table (~100 rules)
# ---------------------------------------------------------------------------
_TOOL_TECHNIQUE_MAP: dict[str, list[dict]] = {
    # Reconnaissance (TA0043)
    "whois": [
        {
            "tactic": "Reconnaissance",
            "tactic_id": "TA0043",
            "technique": "Gather Victim Network Information",
            "technique_id": "T1590",
            "confidence": 0.8,
        }
    ],
    "amass": [
        {
            "tactic": "Reconnaissance",
            "tactic_id": "TA0043",
            "technique": "Gather Victim Domain Properties",
            "technique_id": "T1590.001",
            "confidence": 0.85,
        }
    ],
    "theHarvester": [
        {
            "tactic": "Reconnaissance",
            "tactic_id": "TA0043",
            "technique": "Gather Victim Identity Information",
            "technique_id": "T1589",
            "confidence": 0.8,
        }
    ],
    "subfinder": [
        {
            "tactic": "Reconnaissance",
            "tactic_id": "TA0043",
            "technique": "Gather Victim Domain Properties",
            "technique_id": "T1590.001",
            "confidence": 0.85,
        }
    ],
    "dnsrecon": [
        {
            "tactic": "Reconnaissance",
            "tactic_id": "TA0043",
            "technique": "Gather Victim Network Information: DNS",
            "technique_id": "T1590.002",
            "confidence": 0.85,
        }
    ],
    "shodan": [
        {
            "tactic": "Reconnaissance",
            "tactic_id": "TA0043",
            "technique": "Search Open Technical Databases",
            "technique_id": "T1596",
            "confidence": 0.9,
        }
    ],
    # Discovery (TA0007)
    "nmap": [
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "Network Service Discovery",
            "technique_id": "T1046",
            "confidence": 0.95,
        }
    ],
    "masscan": [
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "Network Service Discovery",
            "technique_id": "T1046",
            "confidence": 0.9,
        }
    ],
    "whatweb": [
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "Software Discovery",
            "technique_id": "T1518",
            "confidence": 0.8,
        }
    ],
    "wappalyzer": [
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "Software Discovery",
            "technique_id": "T1518",
            "confidence": 0.8,
        }
    ],
    "enum4linux": [
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "Network Share Discovery",
            "technique_id": "T1135",
            "confidence": 0.85,
        }
    ],
    "snmpwalk": [
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "System Network Configuration Discovery",
            "technique_id": "T1016",
            "confidence": 0.8,
        }
    ],
    # Initial Access (TA0001)
    "sqlmap": [
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.95,
        }
    ],
    "nuclei": [
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.85,
        }
    ],
    "nikto": [
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.8,
        }
    ],
    "hydra": [
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Brute Force",
            "technique_id": "T1110",
            "confidence": 0.95,
        }
    ],
    "medusa": [
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Brute Force",
            "technique_id": "T1110",
            "confidence": 0.9,
        }
    ],
    "john": [
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Brute Force: Password Cracking",
            "technique_id": "T1110.002",
            "confidence": 0.95,
        }
    ],
    "hashcat": [
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Brute Force: Password Cracking",
            "technique_id": "T1110.002",
            "confidence": 0.95,
        }
    ],
    # Execution (TA0002)
    "metasploit": [
        {
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "technique": "Exploitation for Client Execution",
            "technique_id": "T1203",
            "confidence": 0.9,
        }
    ],
    "msfconsole": [
        {
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "technique": "Exploitation for Client Execution",
            "technique_id": "T1203",
            "confidence": 0.9,
        }
    ],
    # Privilege Escalation (TA0004)
    "linpeas": [
        {
            "tactic": "Privilege Escalation",
            "tactic_id": "TA0004",
            "technique": "Exploitation for Privilege Escalation",
            "technique_id": "T1068",
            "confidence": 0.85,
        }
    ],
    "winpeas": [
        {
            "tactic": "Privilege Escalation",
            "tactic_id": "TA0004",
            "technique": "Exploitation for Privilege Escalation",
            "technique_id": "T1068",
            "confidence": 0.85,
        }
    ],
    "sudo": [
        {
            "tactic": "Privilege Escalation",
            "tactic_id": "TA0004",
            "technique": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
            "technique_id": "T1548.003",
            "confidence": 0.8,
        }
    ],
    # Lateral Movement (TA0008)
    "crackmapexec": [
        {
            "tactic": "Lateral Movement",
            "tactic_id": "TA0008",
            "technique": "Remote Services: SMB/Windows Admin Shares",
            "technique_id": "T1021.002",
            "confidence": 0.9,
        }
    ],
    "evil-winrm": [
        {
            "tactic": "Lateral Movement",
            "tactic_id": "TA0008",
            "technique": "Remote Services: Windows Remote Management",
            "technique_id": "T1021.006",
            "confidence": 0.9,
        }
    ],
    "psexec": [
        {
            "tactic": "Lateral Movement",
            "tactic_id": "TA0008",
            "technique": "Remote Services: SMB/Windows Admin Shares",
            "technique_id": "T1021.002",
            "confidence": 0.9,
        }
    ],
    "impacket": [
        {
            "tactic": "Lateral Movement",
            "tactic_id": "TA0008",
            "technique": "Remote Services",
            "technique_id": "T1021",
            "confidence": 0.85,
        }
    ],
    # Collection (TA0009)
    "bloodhound": [
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "Domain Trust Discovery",
            "technique_id": "T1482",
            "confidence": 0.9,
        }
    ],
    # Defense Evasion (TA0005)
    "gobuster": [
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "File and Directory Discovery",
            "technique_id": "T1083",
            "confidence": 0.8,
        }
    ],
    "dirb": [
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "File and Directory Discovery",
            "technique_id": "T1083",
            "confidence": 0.8,
        }
    ],
    "ffuf": [
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "File and Directory Discovery",
            "technique_id": "T1083",
            "confidence": 0.85,
        }
    ],
    "dirsearch": [
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "File and Directory Discovery",
            "technique_id": "T1083",
            "confidence": 0.8,
        }
    ],
    "wfuzz": [
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "File and Directory Discovery",
            "technique_id": "T1083",
            "confidence": 0.8,
        }
    ],
    "burpsuite": [
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.75,
        }
    ],
    "zap": [
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.75,
        }
    ],
    # AppSec tools
    "semgrep": [
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.7,
        }
    ],
    "syft": [
        {
            "tactic": "Reconnaissance",
            "tactic_id": "TA0043",
            "technique": "Gather Victim Host Information: Software",
            "technique_id": "T1592.002",
            "confidence": 0.7,
        }
    ],
    "grype": [
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.75,
        }
    ],
    # Credential tools
    "fofa": [
        {
            "tactic": "Reconnaissance",
            "tactic_id": "TA0043",
            "technique": "Search Open Technical Databases",
            "technique_id": "T1596",
            "confidence": 0.85,
        }
    ],
    "credential_spray": [
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Brute Force: Password Spraying",
            "technique_id": "T1110.003",
            "confidence": 0.9,
        }
    ],
    "honeypot": [
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "Network Service Discovery",
            "technique_id": "T1046",
            "confidence": 0.6,
        }
    ],
    # LLM Security
    "garak": [
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.7,
        }
    ],
    # Cloud tools
    "prowler": [
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "Cloud Infrastructure Discovery",
            "technique_id": "T1580",
            "confidence": 0.85,
        }
    ],
    "scoutsuite": [
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "Cloud Infrastructure Discovery",
            "technique_id": "T1580",
            "confidence": 0.85,
        }
    ],
    "pacu": [
        {
            "tactic": "Privilege Escalation",
            "tactic_id": "TA0004",
            "technique": "Valid Accounts: Cloud Accounts",
            "technique_id": "T1078.004",
            "confidence": 0.85,
        }
    ],
    # Network tools
    "wireshark": [
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Network Sniffing",
            "technique_id": "T1040",
            "confidence": 0.85,
        }
    ],
    "tcpdump": [
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Network Sniffing",
            "technique_id": "T1040",
            "confidence": 0.8,
        }
    ],
    "chisel": [
        {
            "tactic": "Command and Control",
            "tactic_id": "TA0011",
            "technique": "Protocol Tunneling",
            "technique_id": "T1572",
            "confidence": 0.85,
        }
    ],
    "socat": [
        {
            "tactic": "Command and Control",
            "tactic_id": "TA0011",
            "technique": "Protocol Tunneling",
            "technique_id": "T1572",
            "confidence": 0.75,
        }
    ],
    "ligolo": [
        {
            "tactic": "Command and Control",
            "tactic_id": "TA0011",
            "technique": "Protocol Tunneling",
            "technique_id": "T1572",
            "confidence": 0.85,
        }
    ],
    # Persistence tools
    "crontab": [
        {
            "tactic": "Persistence",
            "tactic_id": "TA0003",
            "technique": "Scheduled Task/Job: Cron",
            "technique_id": "T1053.003",
            "confidence": 0.8,
        }
    ],
    # Additional recon
    "censys": [
        {
            "tactic": "Reconnaissance",
            "tactic_id": "TA0043",
            "technique": "Search Open Technical Databases",
            "technique_id": "T1596",
            "confidence": 0.85,
        }
    ],
    "spiderfoot": [
        {
            "tactic": "Reconnaissance",
            "tactic_id": "TA0043",
            "technique": "Gather Victim Identity Information",
            "technique_id": "T1589",
            "confidence": 0.8,
        }
    ],
    # Wireless
    "aircrack": [
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Rogue Access Point",
            "technique_id": "T1583.008",
            "confidence": 0.85,
        }
    ],
    "wifite": [
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Rogue Access Point",
            "technique_id": "T1583.008",
            "confidence": 0.85,
        }
    ],
    # Exfiltration / Impact
    "responder": [
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "LLMNR/NBT-NS Poisoning",
            "technique_id": "T1557.001",
            "confidence": 0.9,
        }
    ],
    "mimikatz": [
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "OS Credential Dumping",
            "technique_id": "T1003",
            "confidence": 0.95,
        }
    ],
    "secretsdump": [
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "OS Credential Dumping",
            "technique_id": "T1003",
            "confidence": 0.9,
        }
    ],
}

# Keyword patterns matched against finding text
_FINDING_KEYWORD_MAP: list[tuple[re.Pattern, dict]] = [
    (
        re.compile(r"port\s+scan|open\s+port|service\s+discover", re.I),
        {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "Network Service Discovery",
            "technique_id": "T1046",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"sql\s*injection|sqli|sql\s+error|union\s+select", re.I),
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.9,
        },
    ),
    (
        re.compile(r"xss|cross.site\s+script", re.I),
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"command\s+injection|rce|remote\s+code\s+exec", re.I),
        {
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "technique": "Command and Scripting Interpreter",
            "technique_id": "T1059",
            "confidence": 0.9,
        },
    ),
    (
        re.compile(r"privilege\s+escalat|privesc|suid|setuid", re.I),
        {
            "tactic": "Privilege Escalation",
            "tactic_id": "TA0004",
            "technique": "Exploitation for Privilege Escalation",
            "technique_id": "T1068",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"lateral\s+movement|pass.the.hash|pth|pass.the.ticket", re.I),
        {
            "tactic": "Lateral Movement",
            "tactic_id": "TA0008",
            "technique": "Use Alternate Authentication Material",
            "technique_id": "T1550",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"brute\s*force|password\s+spray|credential\s+stuff", re.I),
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Brute Force",
            "technique_id": "T1110",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"default\s+(credential|password)|admin[:/]admin|root[:/]root", re.I),
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Valid Accounts: Default Accounts",
            "technique_id": "T1078.001",
            "confidence": 0.9,
        },
    ),
    (
        re.compile(r"weak\s+ssl|ssl.*expired|tls\s*1\.[01]|self.signed\s+cert", re.I),
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Steal Application Access Token",
            "technique_id": "T1528",
            "confidence": 0.6,
        },
    ),
    (
        re.compile(r"directory\s+travers|path\s+travers|\.\.\/", re.I),
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"buffer\s+overflow|bof|stack\s+overflow", re.I),
        {
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "technique": "Exploitation for Client Execution",
            "technique_id": "T1203",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"dns\s+zone\s+transfer|axfr", re.I),
        {
            "tactic": "Reconnaissance",
            "tactic_id": "TA0043",
            "technique": "Gather Victim Network Information: DNS",
            "technique_id": "T1590.002",
            "confidence": 0.9,
        },
    ),
    (
        re.compile(r"smb\s+sign|null\s+session|anonymous\s+smb", re.I),
        {
            "tactic": "Lateral Movement",
            "tactic_id": "TA0008",
            "technique": "Remote Services: SMB/Windows Admin Shares",
            "technique_id": "T1021.002",
            "confidence": 0.8,
        },
    ),
    (
        re.compile(r"ssrf|server.side\s+request", re.I),
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"lfi|local\s+file\s+inclus", re.I),
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"rfi|remote\s+file\s+inclus", re.I),
        {
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "technique": "Command and Scripting Interpreter",
            "technique_id": "T1059",
            "confidence": 0.8,
        },
    ),
    (
        re.compile(r"ldap\s+injection|ldapi", re.I),
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.8,
        },
    ),
    (
        re.compile(r"xxe|xml\s+external\s+entit", re.I),
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"insecure\s+deseri", re.I),
        {
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "technique": "Exploitation for Client Execution",
            "technique_id": "T1203",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"misconfigur|security\s+header|cors\s+misconfigur", re.I),
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 0.6,
        },
    ),
    (
        re.compile(r"phishing|spear.phish|social\s+engineer", re.I),
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Phishing",
            "technique_id": "T1566",
            "confidence": 0.8,
        },
    ),
    (
        re.compile(r"data\s+exfiltrat|sensitive\s+data\s+expos", re.I),
        {
            "tactic": "Exfiltration",
            "tactic_id": "TA0010",
            "technique": "Exfiltration Over Web Service",
            "technique_id": "T1567",
            "confidence": 0.7,
        },
    ),
    (
        re.compile(r"ransomware|encrypt.*file|data\s+destruct", re.I),
        {
            "tactic": "Impact",
            "tactic_id": "TA0040",
            "technique": "Data Encrypted for Impact",
            "technique_id": "T1486",
            "confidence": 0.9,
        },
    ),
    (
        re.compile(r"denial.of.service|dos|ddos", re.I),
        {
            "tactic": "Impact",
            "tactic_id": "TA0040",
            "technique": "Network Denial of Service",
            "technique_id": "T1498",
            "confidence": 0.8,
        },
    ),
    # Additional patterns for expanded coverage
    (
        re.compile(r"supply.chain|dependency.confusion|typosquat", re.I),
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Supply Chain Compromise: Software Dependencies",
            "technique_id": "T1195.001",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"container.escape|docker.breakout|k8s.exploit", re.I),
        {
            "tactic": "Privilege Escalation",
            "tactic_id": "TA0004",
            "technique": "Escape to Host",
            "technique_id": "T1611",
            "confidence": 0.9,
        },
    ),
    (
        re.compile(r"cloud.metadata|169\.254\.169\.254|imds", re.I),
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Unsecured Credentials: Cloud Instance Metadata API",
            "technique_id": "T1552.005",
            "confidence": 0.9,
        },
    ),
    (
        re.compile(r"api.key.expos|token.leak|secret.expos|hardcoded.secret", re.I),
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Unsecured Credentials",
            "technique_id": "T1552",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"jwt.attack|token.forgery|jwt.none|jwt.weak", re.I),
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Forge Web Credentials",
            "technique_id": "T1606",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"prompt.inject|jailbreak|llm.attack|ai.safety", re.I),
        {
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "technique": "Command and Scripting Interpreter",
            "technique_id": "T1059",
            "confidence": 0.7,
        },
    ),
    (
        re.compile(r"kerberoast|as.rep.roast|golden.ticket|silver.ticket", re.I),
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Steal or Forge Kerberos Tickets",
            "technique_id": "T1558",
            "confidence": 0.9,
        },
    ),
    (
        re.compile(r"tunnel|proxy|pivot|port.forward|socks", re.I),
        {
            "tactic": "Command and Control",
            "tactic_id": "TA0011",
            "technique": "Protocol Tunneling",
            "technique_id": "T1572",
            "confidence": 0.75,
        },
    ),
    (
        re.compile(r"persistence|backdoor|webshell|implant|rootkit", re.I),
        {
            "tactic": "Persistence",
            "tactic_id": "TA0003",
            "technique": "Server Software Component: Web Shell",
            "technique_id": "T1505.003",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"cloud.misconfigur|s3.public|storage.open|bucket.public", re.I),
        {
            "tactic": "Collection",
            "tactic_id": "TA0009",
            "technique": "Data from Cloud Storage",
            "technique_id": "T1530",
            "confidence": 0.85,
        },
    ),
    (
        re.compile(r"sbom|software.composition|vulnerable.depend|outdated.lib", re.I),
        {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Supply Chain Compromise",
            "technique_id": "T1195",
            "confidence": 0.7,
        },
    ),
    (
        re.compile(r"cred.dump|sam.database|lsass|ntds\.dit", re.I),
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "OS Credential Dumping",
            "technique_id": "T1003",
            "confidence": 0.9,
        },
    ),
    (
        re.compile(r"dcsync|domain.replication|drsuapi", re.I),
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "OS Credential Dumping: DCSync",
            "technique_id": "T1003.006",
            "confidence": 0.95,
        },
    ),
    (
        re.compile(r"scheduled.task|cron.job|at.command", re.I),
        {
            "tactic": "Persistence",
            "tactic_id": "TA0003",
            "technique": "Scheduled Task/Job",
            "technique_id": "T1053",
            "confidence": 0.8,
        },
    ),
    (
        re.compile(r"dll.inject|process.inject|code.inject|hollowing", re.I),
        {
            "tactic": "Defense Evasion",
            "tactic_id": "TA0005",
            "technique": "Process Injection",
            "technique_id": "T1055",
            "confidence": 0.9,
        },
    ),
    (
        re.compile(r"wmi|windows.management.instrument", re.I),
        {
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "technique": "Windows Management Instrumentation",
            "technique_id": "T1047",
            "confidence": 0.8,
        },
    ),
    (
        re.compile(r"network.sniff|packet.capture|wireshark|tcpdump", re.I),
        {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Network Sniffing",
            "technique_id": "T1040",
            "confidence": 0.8,
        },
    ),
]


class MITREMapper:
    """Maps security findings to MITRE ATT&CK techniques."""

    def __init__(self, data_path: Path | None = None):
        self._data_path = data_path or (_DATA_DIR / "mitre_attack.json")
        self._attack_data: dict | None = None

    def _load_data(self) -> dict:
        if self._attack_data is None:
            if self._data_path.exists():
                with open(self._data_path, encoding="utf-8") as f:
                    self._attack_data = json.load(f)
            else:
                self._attack_data = {"techniques": {}, "tactics": {}}
        return self._attack_data

    def map_finding(self, finding_text: str, tool_name: str = "") -> list[MITREMapping]:
        """Map a finding description + tool name to ATT&CK techniques."""
        results: list[MITREMapping] = []
        seen: set[str] = set()

        # 1. Check tool name mapping
        if tool_name:
            tool_lower = tool_name.lower().strip()
            for key, mappings in _TOOL_TECHNIQUE_MAP.items():
                if key in tool_lower:
                    for m in mappings:
                        tid = m["technique_id"]
                        if tid not in seen:
                            seen.add(tid)
                            results.append(MITREMapping(**m))

        # 2. Check keyword patterns against finding text
        for pattern, mapping in _FINDING_KEYWORD_MAP:
            if pattern.search(finding_text):
                tid = mapping["technique_id"]
                if tid not in seen:
                    seen.add(tid)
                    results.append(MITREMapping(**mapping))

        return results

    def map_tool(self, tool_name: str) -> list[MITREMapping]:
        """Map a security tool to its typical ATT&CK techniques."""
        return self.map_finding("", tool_name=tool_name)

    def get_tactic_summary(self, mappings: list[MITREMapping]) -> dict[str, int]:
        """Count findings per tactic for executive overview."""
        summary: dict[str, int] = {}
        for m in mappings:
            summary[m.tactic] = summary.get(m.tactic, 0) + 1
        return dict(sorted(summary.items(), key=lambda x: x[1], reverse=True))

    def get_technique_detail(self, technique_id: str) -> dict:
        """Get full ATT&CK technique info by ID."""
        data = self._load_data()
        return data.get("techniques", {}).get(technique_id, {})

    def get_all_tactics(self) -> list[dict]:
        """Return all 14 ATT&CK Enterprise tactics."""
        return [
            {"id": "TA0043", "name": "Reconnaissance"},
            {"id": "TA0042", "name": "Resource Development"},
            {"id": "TA0001", "name": "Initial Access"},
            {"id": "TA0002", "name": "Execution"},
            {"id": "TA0003", "name": "Persistence"},
            {"id": "TA0004", "name": "Privilege Escalation"},
            {"id": "TA0005", "name": "Defense Evasion"},
            {"id": "TA0006", "name": "Credential Access"},
            {"id": "TA0007", "name": "Discovery"},
            {"id": "TA0008", "name": "Lateral Movement"},
            {"id": "TA0009", "name": "Collection"},
            {"id": "TA0011", "name": "Command and Control"},
            {"id": "TA0010", "name": "Exfiltration"},
            {"id": "TA0040", "name": "Impact"},
        ]
