"""
Prowler - Cloud Security Assessment Tool
=========================================

Prowler is an open-source security tool for AWS, Azure, and GCP security
assessments, audits, incident response, compliance, continuous monitoring,
hardening, and forensics readiness.

PERFORMANCE: Results are cached with 6-hour TTL to avoid redundant
cloud security assessments and improve response times by 10-30x for repeated audits.
"""

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="cloud_security", ttl=21600)  # Cache for 6 hours
def prowler_scan(
    provider: str = "aws",
    profile: str = "",
    region: str = "all",
    services: str = "",
    severity: str = "",
    compliance: str = "",
    categories: str = "",
    checks: str = "",
    excluded_checks: str = "",
    output_formats: str = "json,html",
    output_directory: str = "./prowler-output",
    list_services: bool = False,
    list_checks: bool = False,
    quiet: bool = False,
    ctf=None,
) -> str:
    """
    Comprehensive cloud security assessment and compliance audit.

    CACHED: Results cached for 6 hours to avoid redundant cloud security scans.
    Expected performance improvement: 10-30x for repeated assessments.

    Prowler performs security best practices assessments, audits, incident
    response, continuous monitoring, hardening, and forensics readiness.
    Supports 400+ checks across AWS, Azure, and GCP.

    Args:
        provider: Cloud provider (aws, azure, gcp) - default: aws
        profile: AWS/Azure/GCP profile to use
        region: Regions to audit (comma-separated or 'all')
        services: Specific services to audit (comma-separated)
        severity: Filter by severity (critical, high, medium, low)
        compliance: Compliance frameworks (cis, hipaa, gdpr, pci, etc.)
        categories: Categories to check (forensics-ready, internet-exposed, etc.)
        checks: Specific check IDs to run (comma-separated)
        excluded_checks: Check IDs to exclude (comma-separated)
        output_formats: Output formats (json, html, csv, json-asff, etc.)
        output_directory: Directory for output files
        list_services: List available services and exit
        list_checks: List available checks and exit
        quiet: Minimal output mode
        ctf: CTF context for execution

    Returns:
        str: Security assessment results with findings and compliance status

    Examples:
        # Quick AWS security assessment
        prowler_scan(provider="aws")

        # AWS with specific profile and region
        prowler_scan(
            provider="aws",
            profile="production",
            region="us-east-1,us-west-2"
        )

        # CIS AWS Foundations Benchmark
        prowler_scan(
            provider="aws",
            compliance="cis_1.5_aws"
        )

        # Critical and high severity findings only
        prowler_scan(
            provider="aws",
            severity="critical,high"
        )

        # Specific services audit
        prowler_scan(
            provider="aws",
            services="s3,iam,ec2,rds"
        )

        # HIPAA compliance check
        prowler_scan(
            provider="aws",
            compliance="hipaa_aws"
        )

        # Azure security assessment
        prowler_scan(
            provider="azure",
            profile="azure-subscription"
        )

        # GCP security assessment
        prowler_scan(
            provider="gcp",
            profile="my-gcp-project"
        )

        # Internet-exposed resources
        prowler_scan(
            provider="aws",
            categories="internet-exposed"
        )

        # Forensics readiness check
        prowler_scan(
            provider="aws",
            categories="forensics-ready"
        )

        # List available services
        prowler_scan(list_services=True)

        # List available checks for a service
        prowler_scan(services="s3", list_checks=True)

    Supported Compliance Frameworks:
        - cis_1.5_aws: CIS AWS Foundations Benchmark v1.5
        - cis_2.0_aws: CIS AWS Foundations Benchmark v2.0
        - pci_3.2.1_aws: PCI-DSS v3.2.1
        - hipaa_aws: HIPAA compliance
        - gdpr_aws: GDPR compliance
        - iso27001_2013_aws: ISO 27001:2013
        - soc2_aws: SOC 2
        - nist_800_53_r5_aws: NIST 800-53 Rev. 5
        - fedramp_moderate_aws: FedRAMP Moderate
        - fedramp_low_aws: FedRAMP Low

    Check Categories:
        - forensics-ready: Forensics readiness
        - internet-exposed: Internet-facing resources
        - secrets: Secret management
        - encryption: Encryption at rest/transit
        - logging: Logging and monitoring
        - iam: Identity and access management

    Security Note:
        Prowler requires appropriate cloud credentials and permissions.
        Ensure AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY are set for AWS,
        or appropriate authentication for Azure/GCP.
    """
    # Handle info requests
    if list_services:
        return run_command(f"prowler {provider} --list-services", ctf=ctf)

    if list_checks:
        cmd = f"prowler {provider} --list-checks"
        if services:
            cmd += f" --services {services}"
        return run_command(cmd, ctf=ctf)

    # Build prowler command
    cmd_parts = ["prowler", provider]

    # Authentication
    if profile:
        if provider == "aws":
            cmd_parts.append(f"--profile {profile}")
        elif provider == "azure":
            cmd_parts.append("--sp-env-auth")  # Service principal
        elif provider == "gcp":
            cmd_parts.append(f"--credentials-file {profile}")

    # Scope configuration
    if region and region != "all":
        cmd_parts.append(f"--region {region}")

    if services:
        cmd_parts.append(f"--services {services}")

    # Filtering
    if severity:
        cmd_parts.append(f"--severity {severity}")

    if compliance:
        cmd_parts.append(f"--compliance {compliance}")

    if categories:
        cmd_parts.append(f"--categories {categories}")

    if checks:
        cmd_parts.append(f"--checks {checks}")

    if excluded_checks:
        cmd_parts.append(f"--excluded-checks {excluded_checks}")

    # Output configuration
    if output_formats:
        for fmt in output_formats.split(","):
            cmd_parts.append(f"--output {fmt.strip()}")

    if output_directory:
        cmd_parts.append(f"--output-directory {output_directory}")

    # Output mode
    if quiet:
        cmd_parts.append("--quiet")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
