"""
Medusa - Parallel Network Login Brute Forcer
=============================================

Medusa is a speedy, parallel, and modular login brute-forcer supporting
many network protocols. Alternative to Hydra with different module
support and features.

PERFORMANCE: Credential attacks are NOT cached as they involve live
authentication attempts that must be executed fresh each time.
"""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def medusa_attack(
    target: str,
    service: str,
    username: str = "",
    username_file: str = "",
    password: str = "",
    password_file: str = "",
    combo_file: str = "",
    port: int = 0,
    threads: int = 4,
    retries: int = 3,
    timeout: int = 3,
    verbose: bool = False,
    module_options: str = "",
    output_file: str = "",
    ctf=None,
) -> str:
    """
    Multi-protocol parallel credential brute forcing.

    Medusa provides fast, parallel brute-force attacks against network
    services with flexible module options and credential management.

    Args:
        target: Target host (IP or hostname)
        service: Service module (ssh, ftp, http, mssql, mysql, etc.)
        username: Single username to test
        username_file: File containing usernames (one per line)
        password: Single password to test
        password_file: File containing passwords (one per line)
        combo_file: File with username:password pairs
        port: Custom port (default: service default)
        threads: Parallel tasks (default: 4, max recommended: 16)
        retries: Number of retry attempts per connection
        timeout: Overall process timeout floor in seconds (medusa has no
            per-connection timeout flag). Used to bound the run, not as -T.
        verbose: Verbose output mode
        module_options: Service-specific module options
        output_file: Save results to file
        ctf: CTF context for execution

    Returns:
        str: Valid credentials or attack results

    Examples:
        # SSH brute force
        medusa_attack(
            target="192.168.1.100",
            service="ssh",
            username="root",
            password_file="/usr/share/wordlists/rockyou.txt",
            threads=4
        )

        # FTP username enumeration
        medusa_attack(
            target="ftp.example.com",
            service="ftp",
            username_file="/usr/share/wordlists/usernames.txt",
            password="anonymous"
        )

        # MySQL brute force
        medusa_attack(
            target="db.example.com",
            service="mysql",
            username="root",
            password_file="/usr/share/wordlists/mysql-passwords.txt"
        )

        # HTTP Basic Auth
        medusa_attack(
            target="admin.example.com",
            service="http",
            username="admin",
            password_file="/usr/share/wordlists/passwords.txt",
            module_options="AUTH:0 DIR:/admin"
        )

        # SMB brute force
        medusa_attack(
            target="192.168.1.50",
            service="smbnt",
            username="Administrator",
            password_file="/usr/share/wordlists/passwords.txt",
            threads=2
        )

        # PostgreSQL attack
        medusa_attack(
            target="db.company.com",
            service="postgres",
            username="postgres",
            password_file="/usr/share/wordlists/postgres-passwords.txt",
            module_options="DATABASE:template1"
        )

        # Credential stuffing with combo file
        medusa_attack(
            target="192.168.1.100",
            service="ssh",
            combo_file="/tmp/leaked-credentials.txt",  # user:pass format
            threads=8
        )

        # VNC password cracking
        medusa_attack(
            target="192.168.1.100",
            service="vnc",
            password_file="/usr/share/wordlists/vnc-passwords.txt"
        )

        # MSSQL brute force
        medusa_attack(
            target="sqlserver.example.com",
            service="mssql",
            username="sa",
            password_file="/usr/share/wordlists/mssql-passwords.txt",
            port=1433
        )

        # Telnet brute force
        medusa_attack(
            target="192.168.1.1",
            service="telnet",
            username="admin",
            password_file="/usr/share/wordlists/router-passwords.txt"
        )

        # IMAP brute force
        medusa_attack(
            target="mail.example.com",
            service="imap",
            username="user@example.com",
            password_file="/usr/share/wordlists/passwords.txt"
        )

        # Password spraying (one password, many users)
        medusa_attack(
            target="192.168.1.100",
            service="ssh",
            username_file="/usr/share/wordlists/usernames.txt",
            password="<REDACTED>",
            threads=1  # Slow to avoid lockout
        )

    Supported Modules:

    Remote Access:
        - ssh (v2): SSH
        - telnet: Telnet
        - rlogin: Remote login
        - rsh: Remote shell
        - rexec: Remote execution

    File Transfer:
        - ftp: FTP
        - tftp: Trivial FTP

    Web:
        - http: HTTP Basic/NTLM Auth
        - https: HTTPS Basic/NTLM Auth

    Databases:
        - mysql: MySQL
        - mssql: Microsoft SQL Server
        - postgres: PostgreSQL

    Email:
        - smtp: SMTP
        - smtp-vrfy: SMTP User Verification
        - pop3: POP3
        - imap: IMAP

    Network Services:
        - smbnt: SMB/Windows shares
        - smb: SMB
        - snmp: SNMP community strings
        - vnc: VNC

    Other:
        - cvs: CVS pserver
        - nntp: NNTP
        - pcanywhere: PCAnywhere
        - svn: Subversion

    Module-Specific Options:

    HTTP/HTTPS:
        - AUTH:0 (Basic), AUTH:1 (NTLM)
        - DIR:/path/to/resource
        - USER-AGENT:custom-agent

    MySQL:
        - DATABASE:dbname

    PostgreSQL:
        - DATABASE:dbname

    MSSQL:
        - DOMAIN:domain_name

    SMTP:
        - AUTH:LOGIN, AUTH:PLAIN, AUTH:CRAM-MD5

    Attack Modes:

    Single User, Multiple Passwords:
        - Traditional brute force
        - Test one user with many passwords
        - Risk of account lockout

    Multiple Users, Single Password:
        - Password spraying
        - Test many users with one password
        - Avoids lockout mechanisms

    Combo File Attack:
        - Use leaked credentials
        - Format: username:password per line
        - Credential stuffing attack

    Performance Tuning:
        - SSH: 4-8 threads
        - HTTP: 8-16 threads
        - FTP: 4-8 threads
        - SMB: 1-4 threads (creates logs)
        - Database: 4-8 threads

    Medusa vs Hydra:
        Medusa:
            + More stable for some services
            + Better error handling
            + Module-specific options
            - Fewer modules than Hydra
            - Less active development

        Hydra:
            + More modules (50+)
            + More active development
            + Better HTTP form support
            - Can be unstable
            - Less granular module control

    Security Note:
        Credential brute forcing generates logs and triggers security
        mechanisms. Use appropriate delays and thread counts. Always
        obtain authorization and consider account lockout policies.
    """
    cmd_parts = ["medusa"]

    # Target
    cmd_parts.extend(["-h", target])

    # Service module
    cmd_parts.extend(["-M", service])

    # Port
    if port > 0:
        cmd_parts.extend(["-n", str(port)])

    # Credentials
    if combo_file:
        # Combo file (username:password format)
        cmd_parts.extend(["-C", combo_file])
    else:
        # Separate username and password files
        if username:
            cmd_parts.extend(["-u", username])
        elif username_file:
            cmd_parts.extend(["-U", username_file])

        if password:
            cmd_parts.extend(["-p", password])
        elif password_file:
            cmd_parts.extend(["-P", password_file])

    # Performance options
    cmd_parts.extend(["-t", str(threads)])
    cmd_parts.extend(["-r", str(retries)])
    # T4-M12: medusa's -T is "hosts tested concurrently", NOT a connection timeout —
    # medusa has no per-connection timeout flag. The old code emitted `-T <timeout>`,
    # so a caller passing timeout=30 (expecting seconds) silently spawned 30 concurrent
    # host threads. Drop the misuse; `timeout` bounds the process via run_command below.

    # Module-specific options
    if module_options:
        cmd_parts.extend(["-m", module_options])

    # Output options
    if verbose:
        cmd_parts.append("-v 6")  # Verbose level 6

    if output_file:
        cmd_parts.extend(["-O", output_file])

    # Show results as they're found
    cmd_parts.append("-f")  # Stop after first valid credential per host

    command = " ".join(cmd_parts)
    # A brute needs minutes; give it a generous floor so a slow run isn't killed at the
    # 300s default, while still bounding a hung process.
    return run_command(command, ctf=ctf, timeout=max(int(timeout), 900))
