"""
CloudMapper - AWS Network Visualization and Security Analysis
==============================================================

CloudMapper helps analyze AWS environments by creating network diagrams
and identifying security issues in AWS account configurations.

PERFORMANCE: Results are cached with 6-hour TTL to avoid redundant
AWS environment collections and improve response times by 10-30x.
"""

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="cloud_security", ttl=21600)  # Cache for 6 hours
def cloudmapper_collect(
    account_name: str,
    profile: str = "",
    regions: str = "all",
    services: str = "all",
    output_dir: str = "./cloudmapper-data",
    ctf=None,
) -> str:
    """
    Collect AWS account configuration data for analysis.

    CACHED: Results cached for 6 hours to avoid redundant data collection.
    Expected performance improvement: 10-30x for repeated collections.

    CloudMapper collects data about your AWS account including EC2, VPCs,
    Security Groups, IAM, S3, and other services for visualization and
    security analysis.

    Args:
        account_name: Name to identify this AWS account
        profile: AWS profile to use (from ~/.aws/credentials)
        regions: Regions to collect from (comma-separated or 'all')
        services: Services to collect (ec2,iam,s3,etc or 'all')
        output_dir: Directory to store collected data
        ctf: CTF context for execution

    Returns:
        str: Collection status and summary

    Examples:
        # Collect all data from account
        cloudmapper_collect(
            account_name="production",
            profile="prod-readonly"
        )

        # Collect specific regions
        cloudmapper_collect(
            account_name="staging",
            profile="staging",
            regions="us-east-1,us-west-2"
        )

        # Collect specific services
        cloudmapper_collect(
            account_name="security-audit",
            services="ec2,vpc,iam,s3,rds"
        )

    Collected Data:
        - EC2 instances and their configurations
        - VPC network topology
        - Security groups and NACLs
        - IAM users, roles, and policies
        - S3 buckets and permissions
        - RDS databases
        - Load balancers
        - CloudFront distributions
        - Route53 zones

    Security Note:
        Requires read-only access to AWS services. Recommended to use
        SecurityAudit or ViewOnlyAccess managed policies.
    """
    # Build cloudmapper collect command
    cmd_parts = ["cloudmapper", "collect", f"--account {account_name}"]

    if profile:
        cmd_parts.append(f"--profile {profile}")

    if regions and regions != "all":
        cmd_parts.append(f"--regions {regions}")

    if services and services != "all":
        cmd_parts.append(f"--services {services}")

    if output_dir:
        cmd_parts.append(f"--output {output_dir}")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def cloudmapper_report(
    account_name: str,
    report_type: str = "security",
    output_file: str = "",
    data_dir: str = "./cloudmapper-data",
    ctf=None,
) -> str:
    """
    Generate security and configuration reports from collected data.

    Analyzes collected AWS data and generates reports on security
    findings, compliance issues, and configuration recommendations.

    Args:
        account_name: AWS account name (must match collect command)
        report_type: Type of report (security, network, iam, public, stats)
        output_file: Output file path (default: stdout)
        data_dir: Directory with collected data
        ctf: CTF context for execution

    Returns:
        str: Report content with findings and recommendations

    Examples:
        # Security findings report
        cloudmapper_report(
            account_name="production",
            report_type="security"
        )

        # Network topology report
        cloudmapper_report(
            account_name="production",
            report_type="network",
            output_file="network-report.html"
        )

        # IAM analysis
        cloudmapper_report(
            account_name="production",
            report_type="iam"
        )

        # Public exposure report
        cloudmapper_report(
            account_name="production",
            report_type="public",
            output_file="public-resources.json"
        )

        # Account statistics
        cloudmapper_report(
            account_name="production",
            report_type="stats"
        )

    Report Types:

    security:
        - Security group misconfigurations
        - Overly permissive rules
        - Unused security groups
        - Public access risks
        - Encryption issues

    network:
        - VPC topology visualization
        - Subnet configurations
        - Internet gateway exposure
        - Network ACL analysis
        - Routing tables

    iam:
        - IAM permission analysis
        - Overly privileged roles
        - Unused credentials
        - Cross-account access
        - Policy recommendations

    public:
        - Internet-facing resources
        - Public S3 buckets
        - Public RDS instances
        - Exposed EC2 instances
        - CloudFront distributions

    stats:
        - Resource counts by region
        - Service usage statistics
        - Cost center analysis
        - Compliance metrics
    """
    cmd_parts = [
        "cloudmapper",
        "report",
        f"--account {account_name}",
        f"--report-type {report_type}",
    ]

    if data_dir:
        cmd_parts.append(f"--data-dir {data_dir}")

    if output_file:
        cmd_parts.append(f"--output {output_file}")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def cloudmapper_visualize(
    account_name: str,
    output_file: str = "network-diagram.html",
    data_dir: str = "./cloudmapper-data",
    layout: str = "auto",
    regions: str = "all",
    ctf=None,
) -> str:
    """
    Create interactive network topology visualization.

    Generates HTML visualization showing AWS network architecture,
    resources, and their relationships.

    Args:
        account_name: AWS account name
        output_file: Output HTML file path
        data_dir: Directory with collected data
        layout: Diagram layout (auto, hierarchical, force)
        regions: Regions to include (comma-separated or 'all')
        ctf: CTF context for execution

    Returns:
        str: Path to generated visualization

    Examples:
        # Full network diagram
        cloudmapper_visualize(
            account_name="production",
            output_file="aws-network.html"
        )

        # Specific regions
        cloudmapper_visualize(
            account_name="production",
            regions="us-east-1,us-west-2",
            layout="hierarchical"
        )

        # Force-directed layout
        cloudmapper_visualize(
            account_name="production",
            layout="force",
            output_file="network-force.html"
        )

    Visualization Features:
        - Interactive network diagram
        - Color-coded by service type
        - Zoom and pan capabilities
        - Resource details on click
        - Security group relationships
        - Internet gateway highlighting
        - Subnet boundaries
        - Cross-AZ connections
    """
    cmd_parts = ["cloudmapper", "visualize", f"--account {account_name}", f"--output {output_file}"]

    if data_dir:
        cmd_parts.append(f"--data-dir {data_dir}")

    if layout != "auto":
        cmd_parts.append(f"--layout {layout}")

    if regions and regions != "all":
        cmd_parts.append(f"--regions {regions}")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def cloudmapper_audit(
    account_name: str,
    audit_type: str = "all",
    severity: str = "all",
    output_file: str = "",
    data_dir: str = "./cloudmapper-data",
    ctf=None,
) -> str:
    """
    Perform security audit on AWS account configuration.

    Runs comprehensive security checks against AWS best practices
    and compliance frameworks.

    Args:
        account_name: AWS account name
        audit_type: Audit type (all, cis, security, network)
        severity: Filter by severity (critical, high, medium, low, all)
        output_file: Output file for results
        data_dir: Directory with collected data
        ctf: CTF context for execution

    Returns:
        str: Audit findings and recommendations

    Examples:
        # Full security audit
        cloudmapper_audit(
            account_name="production",
            audit_type="all"
        )

        # CIS benchmark audit
        cloudmapper_audit(
            account_name="production",
            audit_type="cis",
            output_file="cis-audit.json"
        )

        # Critical findings only
        cloudmapper_audit(
            account_name="production",
            severity="critical,high"
        )

        # Network security audit
        cloudmapper_audit(
            account_name="production",
            audit_type="network"
        )

    Audit Checks:
        - CIS AWS Foundations Benchmark
        - Security group violations
        - IAM misconfigurations
        - S3 bucket policies
        - Encryption compliance
        - Logging and monitoring
        - Network exposure
        - Resource tagging
    """
    cmd_parts = ["cloudmapper", "audit", f"--account {account_name}", f"--audit-type {audit_type}"]

    if data_dir:
        cmd_parts.append(f"--data-dir {data_dir}")

    if severity != "all":
        cmd_parts.append(f"--severity {severity}")

    if output_file:
        cmd_parts.append(f"--output {output_file}")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
