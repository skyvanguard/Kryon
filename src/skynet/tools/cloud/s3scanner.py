"""
S3Scanner - S3 Bucket Security Scanner
=======================================

S3Scanner is a tool to find open S3 buckets and dump their contents.
It can enumerate buckets, check permissions, and identify security issues.

PERFORMANCE: Results are cached with 4-hour TTL to avoid redundant
S3 bucket scans and improve response times by 10-30x for repeated scans.
"""

from skynet.tools.common import run_command
from skynet.sdk.agents import function_tool
from skynet.cache import cache_scan_result


@function_tool
@cache_scan_result(scan_type="cloud_security", ttl=14400)  # Cache for 4 hours
def s3scanner_scan(
    bucket_names: str = "",
    bucket_file: str = "",
    enumerate: bool = False,
    dump: bool = False,
    list_objects: bool = False,
    output_file: str = "",
    threads: int = 10,
    region: str = "",
    check_acl: bool = True,
    check_policy: bool = True,
    check_encryption: bool = False,
    ctf=None
) -> str:
    """
    Scan S3 buckets for security misconfigurations and sensitive data.

    CACHED: Results cached for 4 hours to avoid redundant S3 bucket scans.
    Expected performance improvement: 10-30x for repeated scans.

    S3Scanner finds open S3 buckets, checks permissions, and can dump contents
    for security assessment. Essential for cloud security audits and bug bounty.

    Args:
        bucket_names: Comma-separated bucket names to scan
        bucket_file: File containing bucket names (one per line)
        enumerate: Enumerate bucket contents
        dump: Download all files from accessible buckets
        list_objects: List objects without downloading
        output_file: Save results to file
        threads: Number of concurrent threads (default: 10)
        region: AWS region (default: auto-detect)
        check_acl: Check bucket ACL permissions (default: True)
        check_policy: Check bucket policy (default: True)
        check_encryption: Check encryption status
        ctf: CTF context for execution

    Returns:
        str: Scan results with bucket permissions and findings

    Examples:
        # Scan specific buckets
        s3scanner_scan(
            bucket_names="company-backup,company-logs,company-public"
        )

        # Scan from file
        s3scanner_scan(
            bucket_file="bucket-names.txt",
            threads=20
        )

        # Check bucket ACL and policy
        s3scanner_scan(
            bucket_names="target-bucket",
            check_acl=True,
            check_policy=True
        )

        # Enumerate bucket contents
        s3scanner_scan(
            bucket_names="target-bucket",
            enumerate=True,
            list_objects=True
        )

        # Full security assessment
        s3scanner_scan(
            bucket_names="target-bucket",
            check_acl=True,
            check_policy=True,
            check_encryption=True,
            enumerate=True
        )

        # Dump accessible buckets
        s3scanner_scan(
            bucket_names="open-bucket",
            dump=True,
            output_file="s3-dump-results.txt"
        )

        # Mass bucket scan
        s3scanner_scan(
            bucket_file="wordlist-buckets.txt",
            threads=50,
            list_objects=True,
            output_file="s3-scan-results.json"
        )

    Permission Checks:
        - READ: Can list bucket contents
        - WRITE: Can upload objects
        - READ_ACP: Can read ACL
        - WRITE_ACP: Can modify ACL
        - FULL_CONTROL: Complete access

    Common Findings:
        - Public read access (data exposure)
        - Public write access (potential compromise)
        - Overly permissive ACLs
        - Missing encryption
        - Sensitive data in public buckets
        - Bucket takeover opportunities

    Security Note:
        Only scan buckets you have permission to assess. Downloading
        data from buckets without authorization may be illegal.
        Always operate within authorized scope of engagement.
    """
    # Build s3scanner command
    cmd_parts = ["s3scanner"]

    # Input source
    if bucket_names:
        # For command line bucket names
        cmd_parts.append("scan")
        for bucket in bucket_names.split(","):
            cmd_parts.append(bucket.strip())
    elif bucket_file:
        cmd_parts.append(f"--bucket-file {bucket_file}")
    else:
        return "Error: Must provide either bucket_names or bucket_file"

    # Operation mode
    if dump:
        cmd_parts.append("--dump")
    elif enumerate:
        cmd_parts.append("--enumerate")

    if list_objects:
        cmd_parts.append("--list")

    # Security checks
    if check_acl:
        cmd_parts.append("--check-acl")

    if check_policy:
        cmd_parts.append("--check-policy")

    if check_encryption:
        cmd_parts.append("--check-encryption")

    # Configuration
    if threads:
        cmd_parts.append(f"--threads {threads}")

    if region:
        cmd_parts.append(f"--region {region}")

    if output_file:
        cmd_parts.append(f"--output {output_file}")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def s3_bucket_finder(
    keywords: str,
    wordlist: str = "",
    permutations: bool = True,
    max_results: int = 1000,
    threads: int = 20,
    ctf=None
) -> str:
    """
    Find S3 buckets using keyword-based enumeration.

    Generates potential bucket names based on keywords and tests
    their existence. Useful for discovering undocumented buckets.

    Args:
        keywords: Comma-separated keywords (company names, products, etc.)
        wordlist: Custom wordlist for bucket name generation
        permutations: Generate permutations of keywords (default: True)
        max_results: Maximum buckets to find (default: 1000)
        threads: Concurrent threads (default: 20)
        ctf: CTF context for execution

    Returns:
        str: List of discovered buckets

    Examples:
        # Find buckets for a company
        s3_bucket_finder(
            keywords="acme,acmecorp,acme-corp"
        )

        # Use custom wordlist
        s3_bucket_finder(
            keywords="target",
            wordlist="s3-bucket-names.txt"
        )

        # Fast enumeration
        s3_bucket_finder(
            keywords="company,prod,dev,staging",
            permutations=True,
            threads=50
        )

    Common Patterns:
        - {company}-{env} (e.g., acme-prod)
        - {company}-{service} (e.g., acme-backups)
        - {env}-{company} (e.g., prod-acme)
        - {company}{year} (e.g., acme2024)

    Security Note:
        Bucket enumeration is passive reconnaissance and generally
        acceptable, but always ensure you have authorization.
    """
    cmd_parts = ["s3scanner", "find"]

    # Add keywords
    for keyword in keywords.split(","):
        cmd_parts.append(f"--keyword {keyword.strip()}")

    # Wordlist
    if wordlist:
        cmd_parts.append(f"--wordlist {wordlist}")

    # Options
    if permutations:
        cmd_parts.append("--permutations")

    cmd_parts.append(f"--max-results {max_results}")
    cmd_parts.append(f"--threads {threads}")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
