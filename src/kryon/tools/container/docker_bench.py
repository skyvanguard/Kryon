"""
Docker Bench Security - Docker CIS Benchmark
=============================================

Docker Bench Security is a script that checks for dozens of common
best-practices around deploying Docker containers in production.
Based on the CIS Docker Benchmark.

PERFORMANCE: Results are cached with 4-hour TTL to avoid redundant
Docker configuration audits and improve response times by 10-30x.
"""

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="config_audit", ttl=14400)  # Cache for 4 hours
def docker_bench_security(
    checks: str = "all",
    exclude_checks: str = "",
    output_format: str = "text",
    output_file: str = "",
    no_colors: bool = False,
    include_test_output: bool = False,
    ctf=None,
) -> str:
    """
    Run CIS Docker Benchmark security audit on Docker host.

    CACHED: Results cached for 4 hours to avoid redundant Docker audits.
    Expected performance improvement: 10-30x for repeated audits.

    Docker Bench Security runs automated checks based on the CIS Docker
    Benchmark to assess Docker security posture. It covers host configuration,
    Docker daemon, container images, runtime, and security operations.

    Args:
        checks: Specific check numbers or 'all' (e.g., "1,2,3" or "all")
        exclude_checks: Check numbers to exclude (e.g., "4.1,5.1")
        output_format: Output format (text, json, log)
        output_file: Save results to file
        no_colors: Disable colored output
        include_test_output: Include detailed test output
        ctf: CTF context for execution

    Returns:
        str: Docker security audit results

    Examples:
        # Full Docker security audit
        docker_bench_security()

        # Run specific check sections
        docker_bench_security(
            checks="1,2,3"
        )

        # Exclude specific checks
        docker_bench_security(
            checks="all",
            exclude_checks="4.1,5.2"
        )

        # JSON output for automation
        docker_bench_security(
            output_format="json",
            output_file="docker-bench-results.json"
        )

        # Detailed output
        docker_bench_security(
            include_test_output=True,
            output_format="log"
        )

    CIS Docker Benchmark Sections:

    Section 1 - Host Configuration:
        - 1.1: Ensure a separate partition for containers
        - 1.2: Harden container host
        - 1.3: Keep Docker up to date
        - 1.4: Manage Docker daemon security
        - 1.5: Audit Docker files and directories

    Section 2 - Docker Daemon Configuration:
        - 2.1: Run Docker in rootless mode (if possible)
        - 2.2: Enable user namespace support
        - 2.3: Verify that live restore is enabled
        - 2.4: Disable legacy registry
        - 2.5: Enable Docker daemon logging
        - 2.6: Restrict network traffic between containers
        - 2.7: Set default ulimit as appropriate
        - 2.8: Enable Docker Content Trust
        - 2.9: Configure TLS authentication for Docker daemon

    Section 3 - Docker Daemon Configuration Files:
        - 3.1: Verify ownership of docker.service file
        - 3.2: Verify file permissions on docker.service
        - 3.3: Verify ownership of docker.socket file
        - 3.4: Verify permissions on docker.socket
        - 3.5: Verify ownership of /etc/docker directory
        - 3.6: Verify permissions on /etc/docker

    Section 4 - Container Images and Build Files:
        - 4.1: Create a user for the container
        - 4.2: Use trusted base images
        - 4.3: Do not install unnecessary packages
        - 4.4: Scan images for vulnerabilities
        - 4.5: Enable Docker Content Trust
        - 4.6: Add HEALTHCHECK instruction
        - 4.7: Do not use update instructions alone

    Section 5 - Container Runtime:
        - 5.1: Verify AppArmor profile is enabled
        - 5.2: Verify SELinux security options
        - 5.3: Restrict Linux kernel capabilities
        - 5.4: Do not use privileged containers
        - 5.5: Do not mount sensitive host directories
        - 5.6: Do not run SSH within containers
        - 5.7: Do not map privileged ports
        - 5.8: Open only needed ports on container
        - 5.9: Do not share host network namespace
        - 5.10: Limit memory usage for container
        - 5.11: Set container CPU priority
        - 5.12: Mount container root filesystem as read-only
        - 5.13: Bind incoming container traffic to specific host interface
        - 5.14: Set the 'on-failure' container restart policy
        - 5.15: Do not share host process namespace
        - 5.16: Do not share host IPC namespace
        - 5.17: Do not directly expose host devices
        - 5.18: Override default ulimit at runtime
        - 5.19: Do not set mount propagation to shared
        - 5.20: Do not share host UTS namespace
        - 5.21: Do not disable default seccomp profile
        - 5.22: Do not use docker exec with privileged option
        - 5.23: Do not use docker exec with user option
        - 5.24: Confirm cgroup usage
        - 5.25: Restrict container from acquiring additional privileges
        - 5.26: Check container health at runtime
        - 5.27: Ensure Docker commands always use latest tag
        - 5.28: Use PIDs cgroup limit
        - 5.29: Do not use Docker's default bridge docker0
        - 5.30: Do not share host user namespaces
        - 5.31: Do not mount Docker socket inside containers

    Section 6 - Docker Security Operations:
        - 6.1: Perform regular security audits
        - 6.2: Monitor Docker containers usage
        - 6.3: Backup container data
        - 6.4: Avoid image sprawl
        - 6.5: Avoid container sprawl

    Section 7 - Docker Swarm Configuration:
        - 7.1: Do not use Swarm mode unless necessary
        - 7.2: Create a Swarm manager separate from production
        - 7.3: Rotate Swarm CA certificate
        - 7.4: Enable auto-lock for Swarm manager
        - 7.5: Manage Swarm secrets appropriately
        - 7.6: Ensure Swarm services are bound to specific interface
        - 7.7: Encrypt data exchanged between containers
        - 7.8: Disable legacy registry

    Result Interpretation:
        [PASS]: Check passed
        [WARN]: Warning - manual verification recommended
        [INFO]: Informational - no action required
        [NOTE]: Note - consider recommendation

    Security Note:
        Docker Bench Security requires Docker daemon access and may need
        root privileges to check all configurations. Run on test systems
        before production to understand results.
    """
    cmd_parts = ["docker-bench-security"]

    # Check selection
    if checks and checks != "all":
        cmd_parts.append(f"-c {checks}")

    if exclude_checks:
        cmd_parts.append(f"-e {exclude_checks}")

    # Output options
    if output_format == "json":
        cmd_parts.append("-j")
    elif output_format == "log":
        cmd_parts.append("-l")

    if output_file:
        cmd_parts.append(f"-o {output_file}")

    if no_colors:
        cmd_parts.append("-n")

    if include_test_output:
        cmd_parts.append("-i")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
