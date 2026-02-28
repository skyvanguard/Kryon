"""Attack simulation engine — safe MITRE ATT&CK technique simulation for BAS."""

import json

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command

# Safe simulation commands mapped to ATT&CK techniques
_TECHNIQUE_SIMULATIONS: dict[str, dict] = {
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "safe_cmd": "nmap -sT -p 80,443,22,3389 --max-retries 1 {target}",
        "description": "Port scan for common services",
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "safe_cmd": "net user 2>/dev/null || cat /etc/passwd 2>/dev/null || echo 'N/A'",
        "description": "Enumerate local user accounts",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "safe_cmd": "ls -la /tmp /var/log /etc 2>/dev/null | head -50",
        "description": "List files in common directories",
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "safe_cmd": "ip addr 2>/dev/null || ifconfig 2>/dev/null; ip route 2>/dev/null || route 2>/dev/null",
        "description": "Enumerate network configuration",
    },
    "T1057": {
        "name": "Process Discovery",
        "tactic": "Discovery",
        "safe_cmd": "ps aux 2>/dev/null || tasklist 2>/dev/null | head -50",
        "description": "List running processes",
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "safe_cmd": "arp -a 2>/dev/null || ip neigh 2>/dev/null | head -30",
        "description": "Discover systems on the network via ARP",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "safe_cmd": "echo 'Test: PowerShell execution simulation - whoami'",
        "description": "Simulate PowerShell command execution",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "safe_cmd": "nuclei -target {target} -severity critical,high -limit 10 -jsonl",
        "description": "Scan for exploitable vulnerabilities",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "safe_cmd": "echo 'Simulation: brute force test with 3 attempts against {target}'",
        "description": "Simulate brute force (dry run)",
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "safe_cmd": "smbclient -L {target} -N 2>/dev/null || echo 'SMB enumeration'",
        "description": "Enumerate SMB shares",
    },
}


@function_tool
def simulate_attack(
    technique_id: str,
    target: str,
    mode: str = "safe",
    variant: str = "",
    timeout: int = 60,
    ctf=None,
) -> str:
    """
    Simulate a MITRE ATT&CK technique against a target for validation.

    Executes a safe simulation of the specified technique to test
    whether defensive controls can detect the activity.

    Args:
        technique_id: MITRE ATT&CK technique ID (e.g. T1046, T1190)
        target: Target IP, hostname, or URL
        mode: Execution mode (safe=detection-only, full=authorized pentest)
        variant: Technique variant or sub-technique
        timeout: Maximum execution time in seconds
        ctf: CTF context for execution

    Returns:
        str: Simulation results including commands executed and output
    """
    technique = _TECHNIQUE_SIMULATIONS.get(technique_id)
    if not technique:
        available = ", ".join(sorted(_TECHNIQUE_SIMULATIONS.keys()))
        return f"Error: Unknown technique '{technique_id}'. Available: {available}"

    if mode != "safe" and mode != "full":
        return "Error: mode must be 'safe' or 'full'"

    cmd = technique["safe_cmd"].format(target=target)

    result_parts = [
        f"Technique: {technique_id} — {technique['name']}",
        f"Tactic: {technique['tactic']}",
        f"Target: {target}",
        f"Mode: {mode}",
        f"Command: {cmd}",
        "---",
    ]

    output = run_command(cmd, ctf=ctf)
    result_parts.append(f"Output:\n{output}")

    return "\n".join(result_parts)


@function_tool
def list_attack_techniques(
    tactic: str = "",
    has_simulation: bool = True,
    ctf=None,
) -> str:
    """
    List available MITRE ATT&CK techniques for simulation.

    Args:
        tactic: Filter by tactic name (Discovery, Execution, etc.)
        has_simulation: Only show techniques with safe simulations
        ctf: CTF context

    Returns:
        str: JSON list of available techniques
    """
    results = []
    for tid, info in _TECHNIQUE_SIMULATIONS.items():
        if tactic and info["tactic"].lower() != tactic.lower():
            continue
        results.append({
            "technique_id": tid,
            "name": info["name"],
            "tactic": info["tactic"],
            "description": info["description"],
        })

    return json.dumps(results, indent=2)
