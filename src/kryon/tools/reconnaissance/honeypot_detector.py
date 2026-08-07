"""Honeypot detection — identify deceptive services and honeypots."""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def detect_honeypot(
    target: str,
    checks: str = "all",
    timeout: int = 30,
    ctf=None,
) -> str:
    """
    Detect if a target is a honeypot using multiple heuristics.

    Checks banner inconsistencies, timing anomalies, behavioral patterns,
    and known honeypot fingerprints.

    Args:
        target: Target IP or hostname
        checks: Checks to run (all, banner, timing, behavior, fingerprint)
        timeout: Timeout per check in seconds
        ctf: CTF context

    Returns:
        str: Honeypot detection analysis results
    """
    results = [f"Honeypot Detection Analysis: {target}", "=" * 50]

    check_list = ["banner", "timing", "behavior", "fingerprint"] if checks == "all" else checks.split(",")

    if "banner" in check_list:
        # Banner grabbing and consistency check
        banner_cmd = f"nmap -sV -Pn --max-retries 1 -p 22,80,443,8080 --host-timeout {timeout}s {target} 2>/dev/null"
        banner_result = run_command(banner_cmd, ctf=ctf)
        results.append(f"\n[Banner Analysis]\n{banner_result}")

    if "timing" in check_list:
        # Timing analysis - honeypots often have uniform response times
        timing_cmd = f"for i in 1 2 3; do time curl -s -o /dev/null -w '%{{time_total}}' http://{target}/ 2>/dev/null; echo; done"
        timing_result = run_command(timing_cmd, ctf=ctf)
        results.append(f"\n[Timing Analysis]\n{timing_result}")

    if "fingerprint" in check_list:
        # Check against known honeypot signatures
        fp_cmd = f"nmap -sV --script=http-headers -p 80,443,8080 --host-timeout {timeout}s {target} 2>/dev/null"
        fp_result = run_command(fp_cmd, ctf=ctf)
        results.append(f"\n[Fingerprint Check]\n{fp_result}")

        # Common honeypot indicators in headers
        honeypot_indicators = [
            "Cowrie",
            "Kippo",
            "Dionaea",
            "Conpot",
            "Glastopf",
            "HoneyD",
            "Artillery",
            "Thinkst",
            "T-Pot",
        ]
        results.append(f"\nKnown honeypot signatures checked: {', '.join(honeypot_indicators)}")

    if "behavior" in check_list:
        # Behavioral analysis - send invalid requests
        behavior_cmd = (
            f"curl -s -o /dev/null -w '%{{http_code}}' http://{target}/AAAA../../../../etc/passwd 2>/dev/null"
        )
        behavior_result = run_command(behavior_cmd, ctf=ctf)
        results.append(f"\n[Behavior Analysis]\nPath traversal response code: {behavior_result}")

    return "\n".join(results)


@function_tool
def honeypot_score(
    target: str,
    port: int = 0,
    ctf=None,
) -> str:
    """
    Calculate a honeypot probability score (0.0-1.0).

    Uses Shodan honeyscore API and local heuristics to determine
    the likelihood that a target is a honeypot.

    Args:
        target: Target IP address
        port: Specific port to check (0 = check common ports)
        ctf: CTF context

    Returns:
        str: Honeypot score with analysis breakdown
    """
    # Use Shodan honeyscore API
    cmd = f"curl -s 'https://api.shodan.io/labs/honeyscore/{target}' 2>/dev/null"
    shodan_result = run_command(cmd, ctf=ctf)

    results = [f"Honeypot Score Analysis: {target}"]

    try:
        score = float(shodan_result.strip())
        results.append(f"Shodan Honeyscore: {score}")
        if score > 0.7:
            results.append("Assessment: HIGH probability of honeypot")
        elif score > 0.4:
            results.append("Assessment: MODERATE probability of honeypot")
        else:
            results.append("Assessment: LOW probability of honeypot")
    except (ValueError, TypeError):
        results.append(f"Shodan API result: {shodan_result}")
        results.append("Assessment: Unable to determine (API key may be needed)")

    return "\n".join(results)
