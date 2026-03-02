"""Detection rule generators — Sigma, YARA, and Suricata rule creation."""

import json
from datetime import datetime, timezone

from kryon.sdk.agents import function_tool

# Sigma rule templates for common ATT&CK techniques
_SIGMA_TEMPLATES: dict[str, dict] = {
    "T1046": {
        "title": "Network Service Discovery via Port Scan",
        "logsource": {"category": "firewall"},
        "detection": {
            "selection": {"action": "blocked", "dst_port|count|gt": 10},
            "timeframe": "5m",
            "condition": "selection",
        },
    },
    "T1190": {
        "title": "Exploit Attempt on Public-Facing Application",
        "logsource": {"category": "webserver", "product": "apache"},
        "detection": {
            "selection": {"cs-uri-query|contains": ["SELECT", "UNION", "../", "<script"]},
            "condition": "selection",
        },
    },
    "T1110": {
        "title": "Brute Force Authentication Attempt",
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {"EventID": [4625]},
            "timeframe": "5m",
            "condition": "selection | count(TargetUserName) by SourceIP > 5",
        },
    },
    "T1059.001": {
        "title": "Suspicious PowerShell Execution",
        "logsource": {"product": "windows", "category": "ps_script"},
        "detection": {
            "selection": {"ScriptBlockText|contains": ["-enc", "bypass", "hidden", "downloadstring"]},
            "condition": "selection",
        },
    },
    "T1021.002": {
        "title": "Lateral Movement via SMB",
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {"EventID": [5140, 5145], "ShareName|contains": ["$", "ADMIN$", "C$"]},
            "condition": "selection",
        },
    },
}


@function_tool
def generate_sigma_rule(
    technique_id: str,
    finding_title: str = "",
    log_source: str = "",
    severity: str = "high",
    ctf=None,
) -> str:
    """
    Generate a Sigma detection rule for a MITRE ATT&CK technique.

    Sigma is a generic and open signature format for SIEM systems,
    convertible to Splunk SPL, Elasticsearch DSL, QRadar AQL, etc.

    Args:
        technique_id: MITRE ATT&CK technique ID (e.g. T1046)
        finding_title: Optional finding title for custom rules
        log_source: Override log source (e.g. windows/sysmon)
        severity: Rule severity (critical, high, medium, low, informational)
        ctf: CTF context

    Returns:
        str: Sigma rule in YAML format
    """
    template = _SIGMA_TEMPLATES.get(technique_id)

    if template:
        logsource = template["logsource"]
        if log_source:
            parts = log_source.split("/")
            logsource = {"product": parts[0]}
            if len(parts) > 1:
                logsource["service"] = parts[1]

        rule = {
            "title": template["title"],
            "id": f"kryon-{technique_id.lower()}-{datetime.now(timezone.utc).strftime('%Y%m%d')}",
            "status": "experimental",
            "description": f"Detects {template['title']} (MITRE ATT&CK {technique_id})",
            "references": [f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"],
            "author": "KRYON",
            "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            "tags": [f"attack.{technique_id.lower()}"],
            "logsource": logsource,
            "detection": template["detection"],
            "level": severity,
            "falsepositives": ["Legitimate administrative activity"],
        }
    else:
        rule = {
            "title": finding_title or f"Detection for {technique_id}",
            "id": f"kryon-custom-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "status": "experimental",
            "description": f"Custom detection rule for {technique_id}",
            "references": [f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"],
            "author": "KRYON",
            "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            "tags": [f"attack.{technique_id.lower()}"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {"CommandLine|contains": ["TODO: customize"]},
                "condition": "selection",
            },
            "level": severity,
            "falsepositives": ["Customize for your environment"],
        }

    # Format as YAML-like output
    import yaml

    try:
        return yaml.dump(rule, default_flow_style=False, sort_keys=False)
    except ImportError:
        return json.dumps(rule, indent=2)


@function_tool
def generate_yara_rule(
    ioc_type: str,
    ioc_value: str,
    rule_name: str = "",
    description: str = "",
    ctf=None,
) -> str:
    """
    Generate a YARA rule for threat detection.

    YARA rules identify and classify malware samples based on
    textual or binary patterns.

    Args:
        ioc_type: IOC type (hash, string, ip, domain, url, regex)
        ioc_value: The IOC value to detect
        rule_name: Custom rule name (auto-generated if empty)
        description: Rule description
        ctf: CTF context

    Returns:
        str: YARA rule
    """
    if not rule_name:
        safe_value = "".join(c if c.isalnum() else "_" for c in ioc_value[:30])
        rule_name = f"kryon_{ioc_type}_{safe_value}"

    meta = [
        f'        description = "{description or f"Detects {ioc_type}: {ioc_value}"}"',
        '        author = "KRYON"',
        f'        date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"',
        f'        ioc_type = "{ioc_type}"',
    ]

    if ioc_type == "hash":
        condition = f'        hash.md5(0, filesize) == "{ioc_value}" or hash.sha256(0, filesize) == "{ioc_value}"'
        strings_section = ""
        imports = 'import "hash"\n\n'
    elif ioc_type in ("string", "domain", "url", "ip"):
        strings_section = f'    strings:\n        $ioc = "{ioc_value}" ascii wide nocase\n'
        condition = "        $ioc"
        imports = ""
    elif ioc_type == "regex":
        strings_section = f"    strings:\n        $ioc = /{ioc_value}/ ascii wide\n"
        condition = "        $ioc"
        imports = ""
    else:
        return f"Error: Unknown IOC type '{ioc_type}'. Supported: hash, string, ip, domain, url, regex"

    rule = f"""{imports}rule {rule_name}
{{
    meta:
{chr(10).join(meta)}
{("    " + strings_section) if strings_section else ""}
    condition:
{condition}
}}"""

    return rule


@function_tool
def generate_suricata_rule(
    ioc_type: str,
    ioc_value: str,
    sid: int = 0,
    severity: int = 1,
    ctf=None,
) -> str:
    """
    Generate a Suricata/Snort IDS rule.

    Args:
        ioc_type: IOC type (ip, domain, url, content, user-agent)
        ioc_value: The IOC value to detect
        sid: Suricata rule ID (auto-generated if 0)
        severity: Rule severity/priority (1=high, 2=medium, 3=low)
        ctf: CTF context

    Returns:
        str: Suricata rule
    """
    if sid == 0:
        import hashlib

        sid = int(hashlib.md5(f"{ioc_type}{ioc_value}".encode()).hexdigest()[:7], 16) % 9000000 + 1000000

    if ioc_type == "ip":
        rule = (
            f"alert ip {ioc_value} any -> $HOME_NET any "
            f'(msg:"KRYON - Suspicious IP {ioc_value}"; '
            f"sid:{sid}; rev:1; priority:{severity}; "
            f"classtype:trojan-activity;)"
        )
    elif ioc_type == "domain":
        rule = (
            f"alert dns $HOME_NET any -> any any "
            f'(msg:"KRYON - Suspicious domain {ioc_value}"; '
            f'dns.query; content:"{ioc_value}"; nocase; '
            f"sid:{sid}; rev:1; priority:{severity}; "
            f"classtype:trojan-activity;)"
        )
    elif ioc_type == "url":
        rule = (
            f"alert http $HOME_NET any -> $EXTERNAL_NET any "
            f'(msg:"KRYON - Suspicious URL {ioc_value}"; '
            f'http.uri; content:"{ioc_value}"; nocase; '
            f"sid:{sid}; rev:1; priority:{severity}; "
            f"classtype:trojan-activity;)"
        )
    elif ioc_type == "content":
        rule = (
            f"alert tcp $HOME_NET any -> $EXTERNAL_NET any "
            f'(msg:"KRYON - Suspicious content pattern"; '
            f'content:"{ioc_value}"; nocase; '
            f"sid:{sid}; rev:1; priority:{severity}; "
            f"classtype:trojan-activity;)"
        )
    elif ioc_type == "user-agent":
        rule = (
            f"alert http $HOME_NET any -> $EXTERNAL_NET any "
            f'(msg:"KRYON - Suspicious User-Agent {ioc_value}"; '
            f'http.user_agent; content:"{ioc_value}"; nocase; '
            f"sid:{sid}; rev:1; priority:{severity}; "
            f"classtype:trojan-activity;)"
        )
    else:
        return f"Error: Unknown IOC type '{ioc_type}'. Supported: ip, domain, url, content, user-agent"

    return rule
