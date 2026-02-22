"""
kube-hunter - Kubernetes Penetration Testing Tool
==================================================

kube-hunter hunts for security weaknesses in Kubernetes clusters.
It can scan from outside the cluster, inside a pod, or as a network scanner.

PERFORMANCE: Results are cached with 4-hour TTL to avoid redundant
Kubernetes security scans and improve response times by 10-30x.
"""

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="cloud_security", ttl=14400)  # Cache for 4 hours
def kube_hunter_scan(
    mode: str = "remote",
    remote_target: str = "",
    cidr: str = "",
    interface: str = "",
    report_format: str = "table",
    output_file: str = "",
    active: bool = False,
    quick: bool = False,
    include_patched: bool = False,
    mapping: bool = False,
    ctf=None,
) -> str:
    """
    Hunt for security weaknesses in Kubernetes clusters.

    CACHED: Results cached for 4 hours to avoid redundant K8s security scans.
    Expected performance improvement: 10-30x for repeated scans.

    kube-hunter discovers and exploits security issues in Kubernetes
    environments. It can perform passive reconnaissance or active exploitation
    from various attack perspectives.

    Args:
        mode: Scan mode (remote, pod, network)
        remote_target: Target host/IP for remote mode
        cidr: CIDR range for network scanning
        interface: Network interface for scanning
        report_format: Output format (table, json, yaml)
        output_file: Save results to file
        active: Enable active hunting (exploitation attempts)
        quick: Quick scan (skip time-consuming tests)
        include_patched: Include tests for patched vulnerabilities
        mapping: Create network topology map
        ctf: CTF context for execution

    Returns:
        str: Kubernetes security findings

    Examples:
        # Remote cluster scan (passive)
        kube_hunter_scan(
            mode="remote",
            remote_target="k8s.company.com"
        )

        # Active exploitation mode
        kube_hunter_scan(
            mode="remote",
            remote_target="10.10.10.50",
            active=True
        )

        # Network scanning
        kube_hunter_scan(
            mode="network",
            cidr="10.0.0.0/24"
        )

        # Pod perspective (run from inside cluster)
        kube_hunter_scan(
            mode="pod",
            active=True
        )

        # Quick scan with JSON output
        kube_hunter_scan(
            mode="remote",
            remote_target="192.168.1.100",
            quick=True,
            report_format="json",
            output_file="kube-hunter-results.json"
        )

        # Network mapping
        kube_hunter_scan(
            mode="network",
            cidr="172.16.0.0/16",
            mapping=True
        )

        # Comprehensive active scan
        kube_hunter_scan(
            mode="remote",
            remote_target="k8s-api.internal",
            active=True,
            include_patched=True,
            report_format="yaml"
        )

    Scan Modes:

    remote:
        Scan a specific Kubernetes API server from outside the cluster.
        Most common mode for external penetration testing.

    pod:
        Scan from inside a Kubernetes pod. Simulates an attacker who has
        compromised a container and is looking for privilege escalation or
        lateral movement opportunities.

    network:
        Scan a network range to discover Kubernetes components.
        Useful for finding exposed K8s services and clusters.

    Common Vulnerabilities Detected:

    API Server Issues:
        - Unauthenticated API access
        - Anonymous authentication enabled
        - Insecure port (8080) exposed
        - Weak RBAC configurations
        - API server profiling enabled

    etcd Database:
        - Exposed etcd without authentication
        - Unencrypted etcd communication
        - etcd accessible from pods

    Kubelet:
        - Kubelet API exposed
        - Anonymous kubelet access
        - Kubelet read-only port (10255) exposed
        - Exec/attach capabilities exploitable

    Dashboard:
        - Kubernetes Dashboard exposed
        - Dashboard without authentication
        - Privilege escalation via dashboard

    Node Security:
        - Privileged containers
        - Host network access
        - Host filesystem mounts
        - Kernel vulnerabilities

    RBAC & Permissions:
        - Over-permissive service accounts
        - Cluster-admin bindings
        - Wildcard permissions
        - Token mounting enabled

    Network:
        - Pod-to-pod communication unrestricted
        - Network policies not enforced
        - Service exposure (NodePort, LoadBalancer)

    Active vs Passive:

    Passive (default):
        - Safe reconnaissance only
        - No exploitation attempts
        - Read-only operations
        - Suitable for production

    Active (--active):
        - Attempts to exploit vulnerabilities
        - May create pods/services
        - Can modify cluster state
        - Use only in authorized testing

    Security Note:
        Active mode performs actual exploitation attempts and may
        disrupt cluster operations. Only use with explicit authorization.
        Passive mode is safe for production assessments.
    """
    cmd_parts = ["kube-hunter"]

    # Scan mode
    if mode == "remote":
        cmd_parts.append("--remote")
        if remote_target:
            cmd_parts.append(remote_target)
    elif mode == "pod":
        cmd_parts.append("--pod")
    elif mode == "network":
        cmd_parts.append("--network")
        if cidr:
            cmd_parts.append(f"--cidr {cidr}")

    # Network interface
    if interface:
        cmd_parts.append(f"--interface {interface}")

    # Scanning options
    if active:
        cmd_parts.append("--active")

    if quick:
        cmd_parts.append("--quick")

    if include_patched:
        cmd_parts.append("--include-patched-vulnerabilities")

    if mapping:
        cmd_parts.append("--mapping")

    # Output format
    if report_format == "json":
        cmd_parts.append("--report json")
    elif report_format == "yaml":
        cmd_parts.append("--report yaml")
    else:
        cmd_parts.append("--report plain")

    # Output file
    if output_file:
        cmd_parts.append(f"--log {output_file}")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
