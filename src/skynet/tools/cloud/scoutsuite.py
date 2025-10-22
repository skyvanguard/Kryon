"""
ScoutSuite - Multi-Cloud Security Auditing Tool
================================================

ScoutSuite is an open-source multi-cloud security auditing tool that enables
security posture assessment of cloud environments. It supports AWS, Azure,
GCP, Alibaba Cloud, and Oracle Cloud.

PERFORMANCE: Results are cached with 6-hour TTL to avoid redundant
cloud security audits and improve response times by 10-30x.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool
from skynet.cache import cache_scan_result


@function_tool
@cache_scan_result(scan_type="cloud_security", ttl=21600)  # Cache for 6 hours
def scoutsuite_scan(
    provider: str = "aws",
    profile: str = "",
    regions: str = "all",
    services: str = "all",
    excluded_services: str = "",
    ruleset: str = "default",
    exceptions: str = "",
    output_dir: str = "./scoutsuite-report",
    report_name: str = "",
    no_browser: bool = True,
    force: bool = False,
    debug: bool = False,
    ctf=None
) -> str:
    """
    Multi-cloud security posture assessment and auditing.

    CACHED: Results cached for 6 hours to avoid redundant cloud audits.
    Expected performance improvement: 10-30x for repeated assessments.

    ScoutSuite performs comprehensive security audits across multiple cloud
    providers, generating detailed HTML reports with findings, compliance
    status, and remediation guidance.

    Args:
        provider: Cloud provider (aws, azure, gcp, aliyun, oci)
        profile: Cloud profile/credentials to use
        regions: Regions to audit (comma-separated or 'all')
        services: Services to audit (comma-separated or 'all')
        excluded_services: Services to exclude
        ruleset: Ruleset to use (default, cis, hipaa, pci, etc.)
        exceptions: Exceptions file path (JSON)
        output_dir: Output directory for reports
        report_name: Custom report name
        no_browser: Don't open browser automatically
        force: Overwrite existing report
        debug: Enable debug output
        ctf: CTF context for execution

    Returns:
        str: Audit summary and report location

    Examples:
        # AWS security audit
        scoutsuite_scan(
            provider="aws",
            profile="production"
        )

        # AWS with specific regions and services
        scoutsuite_scan(
            provider="aws",
            regions="us-east-1,us-west-2",
            services="s3,iam,ec2,rds"
        )

        # Azure security audit
        scoutsuite_scan(
            provider="azure",
            profile="azure-subscription"
        )

        # GCP security audit
        scoutsuite_scan(
            provider="gcp",
            profile="my-gcp-project"
        )

        # CIS benchmark audit
        scoutsuite_scan(
            provider="aws",
            ruleset="cis",
            output_dir="./cis-audit-report"
        )

        # HIPAA compliance audit
        scoutsuite_scan(
            provider="aws",
            ruleset="hipaa",
            report_name="hipaa-compliance-2025"
        )

        # Quick IAM and S3 audit
        scoutsuite_scan(
            provider="aws",
            services="iam,s3",
            output_dir="./iam-s3-audit"
        )

        # Multi-region comprehensive audit
        scoutsuite_scan(
            provider="aws",
            regions="all",
            services="all",
            output_dir="./full-audit",
            debug=True
        )

    Supported Providers:

    aws (Amazon Web Services):
        Comprehensive AWS security audit covering 40+ services including
        IAM, EC2, S3, RDS, Lambda, CloudTrail, CloudWatch, and more.

    azure (Microsoft Azure):
        Azure security audit including Azure Active Directory, Virtual
        Machines, Storage, SQL Database, Network Security Groups, etc.

    gcp (Google Cloud Platform):
        GCP security audit covering IAM, Compute Engine, Cloud Storage,
        Cloud SQL, VPC, Cloud Functions, and more.

    aliyun (Alibaba Cloud):
        Alibaba Cloud security audit for ECS, OSS, RDS, and other services.

    oci (Oracle Cloud Infrastructure):
        Oracle Cloud security audit for compute, storage, and networking.

    AWS Services Audited:
        - IAM: Users, roles, policies, password policy
        - S3: Buckets, ACLs, encryption, public access
        - EC2: Instances, security groups, network ACLs, snapshots
        - RDS: Databases, snapshots, encryption, backups
        - Lambda: Functions, permissions, environment variables
        - CloudTrail: Logging, configuration, multi-region
        - CloudWatch: Alarms, log groups, metrics
        - VPC: Subnets, route tables, internet gateways, VPN
        - KMS: Keys, key policies, rotation
        - ELB: Load balancers, listeners, SSL/TLS
        - CloudFront: Distributions, origins, certificates
        - Route53: Hosted zones, record sets, query logging
        - SNS: Topics, subscriptions, encryption
        - SQS: Queues, policies, encryption
        - EBS: Volumes, snapshots, encryption
        - ACM: Certificates, validation, expiration
        - Config: Configuration recorder, rules
        - Secrets Manager: Secrets, rotation, encryption
        - And 20+ more services...

    Azure Services Audited:
        - Azure AD: Users, groups, roles, conditional access
        - Virtual Machines: Instances, disks, security
        - Storage Accounts: Blob, file, queue, table storage
        - SQL Database: Servers, databases, firewall rules
        - Network Security Groups: Rules, associations
        - Key Vault: Secrets, keys, certificates
        - Application Gateway: WAF configuration
        - And more...

    GCP Services Audited:
        - IAM: Members, roles, bindings, service accounts
        - Compute Engine: Instances, disks, firewalls
        - Cloud Storage: Buckets, objects, IAM policies
        - Cloud SQL: Instances, databases, users
        - VPC: Networks, subnets, firewall rules
        - Cloud Functions: Functions, triggers, IAM
        - KMS: Key rings, keys, permissions
        - And more...

    Rulesets:

    default:
        Standard security best practices across all services.

    cis:
        CIS (Center for Internet Security) Benchmark rules for
        cloud platform security hardening.

    hipaa:
        HIPAA (Health Insurance Portability and Accountability Act)
        compliance checks for healthcare data protection.

    pci:
        PCI-DSS (Payment Card Industry Data Security Standard)
        compliance for payment card data security.

    Finding Categories:
        - Danger: Critical security issues requiring immediate action
        - Warning: Significant issues requiring attention
        - Info: Informational findings and recommendations

    Report Features:
        - Interactive HTML dashboard
        - Service-by-service breakdown
        - Finding severity classification
        - Compliance framework mapping
        - Remediation guidance
        - Historical comparison
        - Export to JSON/CSV

    Security Note:
        ScoutSuite requires read-only access to cloud resources.
        Use appropriate credentials with SecurityAudit, ReadOnlyAccess,
        or Viewer roles. Never use credentials with write permissions.
    """
    cmd_parts = [
        "scout",
        provider
    ]

    # Authentication
    if profile:
        if provider == "aws":
            cmd_parts.append(f"--profile {profile}")
        elif provider == "azure":
            cmd_parts.append(f"--cli")  # Use Azure CLI auth
        elif provider == "gcp":
            cmd_parts.append(f"--project-id {profile}")

    # Scope
    if regions and regions != "all":
        cmd_parts.append(f"--regions {regions}")

    if services and services != "all":
        cmd_parts.append(f"--services {services}")

    if excluded_services:
        cmd_parts.append(f"--excluded-services {excluded_services}")

    # Ruleset
    if ruleset and ruleset != "default":
        cmd_parts.append(f"--ruleset {ruleset}")

    # Exceptions
    if exceptions:
        cmd_parts.append(f"--exceptions {exceptions}")

    # Output
    if output_dir:
        cmd_parts.append(f"--report-dir {output_dir}")

    if report_name:
        cmd_parts.append(f"--report-name {report_name}")

    # Options
    if no_browser:
        cmd_parts.append("--no-browser")

    if force:
        cmd_parts.append("--force")

    if debug:
        cmd_parts.append("--debug")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
