"""
Pacu - AWS Exploitation Framework
==================================

Pacu is an open-source AWS exploitation framework designed for offensive
security testing in AWS environments. It includes modules for reconnaissance,
privilege escalation, data exfiltration, and persistence.

PERFORMANCE: Results are cached with 4-hour TTL to avoid redundant
exploitation attempts and improve response times for repeated operations.
"""

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
@cache_scan_result(scan_type="cloud_security", ttl=14400)  # Cache for 4 hours
def pacu_run(
    module: str,
    session_name: str = "skynet-session",
    aws_profile: str = "",
    aws_keys: str = "",
    region: str = "",
    module_args: str = "",
    list_modules: bool = False,
    search_modules: str = "",
    module_info: str = "",
    ctf=None,
) -> str:
    """
    AWS exploitation framework for offensive security testing.

    CACHED: Results cached for 4 hours to avoid redundant exploitation attempts.
    Expected performance improvement: 10-30x for repeated operations.

    Pacu is a comprehensive exploitation framework specifically designed for
    AWS environments, with 50+ modules covering reconnaissance, privilege
    escalation, persistence, and data exfiltration.

    Args:
        module: Pacu module to execute
        session_name: Pacu session name (default: skynet-session)
        aws_profile: AWS profile to use
        aws_keys: AWS keys in format "access_key:secret_key:session_token"
        region: AWS region to target
        module_args: Module-specific arguments (space or comma-separated)
        list_modules: List all available modules
        search_modules: Search modules by keyword
        module_info: Get detailed info about a specific module
        ctf: CTF context for execution

    Returns:
        str: Module execution results

    Examples:
        # Reconnaissance - Enumerate IAM permissions
        pacu_run(
            module="iam__enum_permissions",
            session_name="recon-session"
        )

        # Enumerate all IAM users
        pacu_run(
            module="iam__enum_users",
            region="us-east-1"
        )

        # Enumerate EC2 instances
        pacu_run(
            module="ec2__enum",
            region="all"
        )

        # Enumerate S3 buckets
        pacu_run(
            module="s3__enum",
            session_name="s3-recon"
        )

        # Check for public S3 buckets
        pacu_run(
            module="s3__bucket_finder",
            module_args="--wordlist common-buckets.txt"
        )

        # Enumerate Lambda functions
        pacu_run(
            module="lambda__enum",
            region="us-west-2"
        )

        # Enumerate RDS instances
        pacu_run(
            module="rds__enum",
            region="all"
        )

        # Privilege escalation - Check for privesc paths
        pacu_run(
            module="iam__privesc_scan"
        )

        # Backdoor IAM user
        pacu_run(
            module="iam__backdoor_assume_role",
            module_args="--role-name target-role"
        )

        # Steal EC2 instance credentials
        pacu_run(
            module="ec2__steal_instance_credentials",
            module_args="--instance-id i-1234567890abcdef0"
        )

        # Data exfiltration - Download S3 bucket
        pacu_run(
            module="s3__download_bucket",
            module_args="--bucket-name target-bucket"
        )

        # Exfiltrate EC2 snapshots
        pacu_run(
            module="ebs__enum_snapshots_unauth",
            region="all"
        )

        # Persistence - Create backdoor user
        pacu_run(
            module="iam__backdoor_users_keys"
        )

        # Persistence - Lambda backdoor
        pacu_run(
            module="lambda__backdoor_new_roles"
        )

        # List all available modules
        pacu_run(list_modules=True)

        # Search for modules related to S3
        pacu_run(search_modules="s3")

        # Get info about a specific module
        pacu_run(module_info="iam__enum_permissions")

    Popular Modules by Category:

    Reconnaissance:
        - iam__enum_permissions: Enumerate caller's IAM permissions
        - iam__enum_users: Enumerate IAM users
        - iam__enum_roles: Enumerate IAM roles
        - ec2__enum: Enumerate EC2 instances
        - s3__enum: Enumerate S3 buckets
        - lambda__enum: Enumerate Lambda functions
        - rds__enum: Enumerate RDS databases
        - cloudtrail__download_event_history: Download CloudTrail logs

    Privilege Escalation:
        - iam__privesc_scan: Scan for privilege escalation paths
        - iam__backdoor_assume_role: Create backdoor assume role
        - iam__bruteforce_permissions: Brute force IAM permissions
        - lambda__backdoor_new_roles: Backdoor new Lambda roles

    Persistence:
        - iam__backdoor_users_keys: Create backdoor IAM credentials
        - iam__backdoor_users_password: Set backdoor password
        - lambda__backdoor_new_sec_groups: Backdoor security groups

    Data Exfiltration:
        - s3__download_bucket: Download entire S3 bucket
        - ebs__enum_snapshots_unauth: Find public EBS snapshots
        - rds__explore_snapshots: Explore RDS snapshots
        - ec2__download_userdata: Download EC2 user data

    Lateral Movement:
        - ec2__steal_instance_credentials: Steal EC2 metadata credentials
        - lambda__backdoor_new_users: Create Lambda backdoor users

    Security Note:
        Pacu is for authorized security testing only. Ensure you have
        explicit permission before running any exploitation modules.
        Many modules perform destructive actions or create backdoors.
    """
    # Handle info/list requests
    if list_modules:
        return run_command("pacu --list-modules", ctf=ctf)

    if search_modules:
        return run_command(f"pacu --search-modules {search_modules}", ctf=ctf)

    if module_info:
        return run_command(f"pacu --module-info {module_info}", ctf=ctf)

    # Build Pacu command
    # Pacu uses interactive mode by default, so we use scripting mode
    cmd_parts = ["pacu", f"--session {session_name}"]

    # Authentication
    if aws_profile:
        cmd_parts.append(f"--profile {aws_profile}")
    elif aws_keys:
        # Format: access_key:secret_key:session_token
        cmd_parts.append(f"--keys {aws_keys}")

    if region:
        cmd_parts.append(f"--region {region}")

    # Execute module
    if module:
        cmd_parts.append(f"--exec '{module}")
        if module_args:
            cmd_parts.append(module_args)
        cmd_parts.append("'")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
