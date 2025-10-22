"""
kube-bench - Kubernetes CIS Benchmark Checker
==============================================

kube-bench checks whether Kubernetes is deployed securely by running
the checks documented in the CIS Kubernetes Benchmark.

PERFORMANCE: Results are cached with 4-hour TTL to avoid redundant
CIS benchmark audits and improve response times by 10-30x.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool
from skynet.cache import cache_scan_result


@function_tool
@cache_scan_result(scan_type="config_audit", ttl=14400)  # Cache for 4 hours
def kube_bench_scan(
    target: str = "node",
    benchmark: str = "cis-1.8",
    check: str = "",
    group: str = "",
    output_format: str = "text",
    output_file: str = "",
    config_dir: str = "",
    verbose: bool = False,
    scored_only: bool = False,
    skip_checks: str = "",
    ctf=None
) -> str:
    """
    Run CIS Kubernetes Benchmark security checks.

    CACHED: Results cached for 4 hours to avoid redundant CIS audits.
    Expected performance improvement: 10-30x for repeated audits.

    kube-bench runs automated security checks based on the CIS Kubernetes
    Benchmark to assess cluster security posture. It can audit masters,
    nodes, etcd, and policies.

    Args:
        target: Target to check (node, master, etcd, controlplane, policies)
        benchmark: CIS benchmark version (cis-1.8, cis-1.7, cis-1.6, etc.)
        check: Specific check ID to run (e.g., "1.2.3")
        group: Specific group to run (e.g., "1.2")
        output_format: Output format (text, json, yaml, junit)
        output_file: Save results to file
        config_dir: Custom config directory
        verbose: Verbose output
        scored_only: Run only scored checks
        skip_checks: Comma-separated check IDs to skip
        ctf: CTF context for execution

    Returns:
        str: CIS benchmark audit results

    Examples:
        # Check worker node
        kube_bench_scan(
            target="node"
        )

        # Check master/control plane
        kube_bench_scan(
            target="master"
        )

        # Full cluster audit
        kube_bench_scan(
            target="master",
            benchmark="cis-1.8",
            output_format="json",
            output_file="cis-audit.json"
        )

        # Check specific section
        kube_bench_scan(
            target="master",
            group="1.2"
        )

        # Check single control
        kube_bench_scan(
            target="node",
            check="4.2.1"
        )

        # etcd security audit
        kube_bench_scan(
            target="etcd",
            output_format="yaml"
        )

        # Scored checks only
        kube_bench_scan(
            target="master",
            scored_only=True
        )

        # Skip specific checks
        kube_bench_scan(
            target="node",
            skip_checks="4.2.9,4.2.13"
        )

    Targets:

    master (control plane):
        Audits Kubernetes master node components including API server,
        scheduler, controller manager, and configuration files.

    node (worker):
        Audits Kubernetes worker node components including kubelet,
        proxy, and configuration files.

    etcd:
        Audits etcd database security including authentication,
        encryption, and access controls.

    controlplane:
        Comprehensive control plane audit combining master and etcd checks.

    policies:
        Audits Kubernetes policies including Pod Security Policies,
        Network Policies, and RBAC configurations.

    CIS Kubernetes Benchmark Sections:

    Section 1 - Control Plane Components:
        1.1 Master Node Configuration Files
        1.2 API Server
        1.3 Controller Manager
        1.4 Scheduler

    Section 2 - etcd:
        2.1 etcd Configuration
        2.2 etcd Data Directory
        2.3 etcd Certificates

    Section 3 - Control Plane Configuration:
        3.1 Authentication and Authorization
        3.2 Logging
        3.3 Admission Controllers
        3.4 General Security Primitives

    Section 4 - Worker Nodes:
        4.1 Worker Node Configuration Files
        4.2 Kubelet
        4.3 Container Runtime (Docker/containerd)

    Section 5 - Policies:
        5.1 RBAC and Service Accounts
        5.2 Pod Security Policies/Standards
        5.3 Network Policies and CNI
        5.4 Secrets Management
        5.5 Extensible Admission Control

    Common Issues Detected:

    API Server:
        - Anonymous authentication enabled
        - Insecure port (8080) enabled
        - AlwaysAllow authorization mode
        - Profiling enabled
        - Audit logging disabled

    Controller Manager:
        - service-account-private-key-file not set
        - root-ca-file not set
        - RotateKubeletServerCertificate not enabled

    Scheduler:
        - Profiling enabled
        - Bind address not set to localhost

    etcd:
        - Client authentication not configured
        - Peer authentication not configured
        - Encryption at rest not enabled
        - Auto TLS enabled

    Kubelet:
        - Anonymous authentication enabled
        - Authorization mode set to AlwaysAllow
        - Read-only port enabled (10255)
        - Protect kernel defaults not set
        - Certificate rotation not enabled

    Policies:
        - Pod Security Policy not enabled
        - Network policies not enforced
        - Service account tokens auto-mounted
        - Default namespace in use

    Result Interpretation:
        [PASS]: Check passed
        [FAIL]: Check failed - action required
        [WARN]: Warning - manual verification needed
        [INFO]: Informational only

    Scored vs Not Scored:
        Scored: Impacts compliance score (critical for compliance)
        Not Scored: Best practice recommendations (advisory)

    Security Note:
        kube-bench should be run on each cluster node type (master, worker).
        For managed Kubernetes (EKS, GKE, AKS), some checks may not apply
        as the provider manages control plane security.
    """
    cmd_parts = ["kube-bench"]

    # Target
    cmd_parts.append(target)

    # Benchmark version
    if benchmark:
        cmd_parts.append(f"--benchmark {benchmark}")

    # Check/group selection
    if check:
        cmd_parts.append(f"--check {check}")
    elif group:
        cmd_parts.append(f"--group {group}")

    # Skip checks
    if skip_checks:
        cmd_parts.append(f"--skip {skip_checks}")

    # Scored only
    if scored_only:
        cmd_parts.append("--scored")

    # Output format
    if output_format == "json":
        cmd_parts.append("--json")
    elif output_format == "yaml":
        cmd_parts.append("--yaml")
    elif output_format == "junit":
        cmd_parts.append("--junit")

    # Output file
    if output_file:
        cmd_parts.append(f"--outputfile {output_file}")

    # Config directory
    if config_dir:
        cmd_parts.append(f"--config-dir {config_dir}")

    # Verbose
    if verbose:
        cmd_parts.append("--verbose")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
