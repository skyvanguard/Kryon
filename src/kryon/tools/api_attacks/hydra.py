"""
Hydra - Fast Network Logon Cracker
===================================

Hydra is a parallelized login cracker supporting numerous protocols for
attacking network authentication services. Excellent for password spraying,
credential stuffing, and brute force attacks.

PERFORMANCE: Credential attacks are NOT cached as they involve live
authentication attempts that must be executed fresh each time.
"""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def hydra_attack(
    target: str,
    service: str,
    username: str = "",
    username_list: str = "",
    password: str = "",
    password_list: str = "",
    port: int = 0,
    threads: int = 16,
    timeout: int = 30,
    verbose: bool = False,
    exit_on_success: bool = True,
    http_method: str = "POST",
    http_path: str = "/",
    http_params: str = "",
    http_success_string: str = "",
    http_failure_string: str = "",
    additional_options: str = "",
    ctf=None,
) -> str:
    """
    Multi-protocol credential brute forcing and password spraying.

    Hydra supports 50+ network protocols for testing weak credentials,
    password spraying, and credential stuffing attacks. Essential for
    penetration testing authentication mechanisms.

    Args:
        target: Target IP address or hostname
        service: Protocol/service to attack (ssh, ftp, http-post-form, etc.)
        username: Single username to test
        username_list: File with usernames (one per line)
        password: Single password to test
        password_list: File with passwords (one per line)
        port: Custom port (default: service default)
        threads: Number of parallel connections (default: 16)
        timeout: Connection timeout in seconds
        verbose: Enable verbose output
        exit_on_success: Stop after first valid credential
        http_method: HTTP method for web forms (POST/GET)
        http_path: Path for HTTP form attacks
        http_params: HTTP parameters (user=^USER^&pass=^PASS^)
        http_success_string: String indicating successful login
        http_failure_string: String indicating failed login
        additional_options: Additional Hydra options
        ctf: CTF context for execution

    Returns:
        str: Valid credentials found or attack results

    Examples:
        # SSH brute force with single username
        hydra_attack(
            target="192.168.1.100",
            service="ssh",
            username="admin",
            password_list="/usr/share/wordlists/rockyou.txt",
            threads=4
        )

        # FTP password spraying (one password, many users)
        hydra_attack(
            target="ftp.example.com",
            service="ftp",
            username_list="/usr/share/wordlists/usernames.txt",
            password="<REDACTED>",
            threads=1  # Slow to avoid account lockout
        )

        # MySQL brute force
        hydra_attack(
            target="db.example.com",
            service="mysql",
            username="root",
            password_list="/usr/share/wordlists/passwords.txt"
        )

        # HTTP POST form attack
        hydra_attack(
            target="example.com",
            service="http-post-form",
            http_path="/login.php",
            http_params="username=^USER^&password=^PASS^&submit=Login",
            http_failure_string="Invalid credentials",
            username_list="/usr/share/wordlists/usernames.txt",
            password_list="/usr/share/wordlists/passwords.txt"
        )

        # HTTP Basic Auth
        hydra_attack(
            target="admin.example.com",
            service="http-get",
            http_path="/admin",
            username="admin",
            password_list="/usr/share/wordlists/passwords.txt"
        )

        # RDP brute force
        hydra_attack(
            target="192.168.1.50",
            service="rdp",
            username="Administrator",
            password_list="/usr/share/wordlists/passwords.txt",
            threads=4
        )

        # SMB credential testing
        hydra_attack(
            target="192.168.1.100",
            service="smb",
            username_list="/usr/share/wordlists/usernames.txt",
            password_list="/usr/share/wordlists/passwords.txt"
        )

        # PostgreSQL attack
        hydra_attack(
            target="db.company.com",
            service="postgres",
            username="postgres",
            password_list="/usr/share/wordlists/postgres-passwords.txt",
            port=5432
        )

        # SMTP user enumeration
        hydra_attack(
            target="mail.example.com",
            service="smtp-enum",
            username_list="/usr/share/wordlists/usernames.txt"
        )

        # Telnet brute force
        hydra_attack(
            target="192.168.1.1",
            service="telnet",
            username="admin",
            password_list="/usr/share/wordlists/passwords.txt"
        )

        # VNC password cracking
        hydra_attack(
            target="192.168.1.100",
            service="vnc",
            password_list="/usr/share/wordlists/vnc-passwords.txt"
        )

    Supported Services (50+):

    Remote Access:
        - ssh, ssh2: SSH
        - telnet: Telnet
        - rdp: Remote Desktop Protocol
        - vnc: VNC

    File Transfer:
        - ftp, ftps: FTP/FTPS
        - sftp: SSH File Transfer
        - tftp: Trivial FTP

    Web:
        - http-get, https-get: HTTP Basic Auth
        - http-post-form, https-post-form: Form-based auth
        - http-head: HTTP HEAD method

    Databases:
        - mysql: MySQL
        - mssql: Microsoft SQL Server
        - postgres, postgresql: PostgreSQL
        - oracle-listener: Oracle DB
        - mongodb: MongoDB

    Email:
        - smtp, smtps: SMTP
        - pop3, pop3s: POP3
        - imap, imaps: IMAP

    Network Services:
        - smb, smbnt: SMB/Windows shares
        - ldap, ldaps: LDAP
        - snmp: SNMP community strings
        - rlogin: Remote login
        - rsh: Remote shell
        - rexec: Remote execution

    Proxies & VPN:
        - socks5: SOCKS5 proxy
        - cisco: Cisco devices
        - cisco-enable: Cisco enable password

    Attack Strategies:

    Password Spraying:
        - Use ONE common password
        - Test against MANY usernames
        - Avoids account lockout
        - Example: "Password123!" against all users

    Credential Stuffing:
        - Use leaked username:password pairs
        - Test known credentials
        - Format: username:password per line

    Brute Force:
        - Test multiple passwords per user
        - Use rockyou.txt or custom wordlist
        - Risk of account lockout

    Username Enumeration:
        - SMTP VRFY
        - Different error messages
        - Timing attacks

    HTTP Form Attack Format:
        Path: /login.php
        Params: username=^USER^&password=^PASS^&submit=Login
        Success: "Welcome" or "Dashboard"
        Failure: "Invalid" or "Incorrect"

    Performance Tips:
        - SSH: 4-8 threads
        - HTTP: 16-32 threads
        - FTP: 8-16 threads
        - SMB: 1-4 threads (loud, creates logs)
        - Password spraying: 1 thread (stealth)

    Security Note:
        Credential attacks trigger account lockout mechanisms,
        generate extensive logs, and can be detected by IDS/IPS.
        Always use slow speeds and obtain authorization.
        Consider account lockout policies before testing.
    """
    cmd_parts = ["hydra"]

    # Target and service
    if port > 0:
        cmd_parts.extend(["-s", str(port)])

    # Credentials
    if username:
        cmd_parts.extend(["-l", username])
    elif username_list:
        cmd_parts.extend(["-L", username_list])

    if password:
        cmd_parts.extend(["-p", password])
    elif password_list:
        cmd_parts.extend(["-P", password_list])

    # Performance options
    cmd_parts.extend(["-t", str(threads)])
    cmd_parts.extend(["-w", str(timeout)])

    # Exit options
    if exit_on_success:
        cmd_parts.append("-f")  # Exit after first valid pair

    # Verbose output
    if verbose:
        cmd_parts.append("-V")

    # HTTP-specific options
    if "http" in service:
        if http_params:
            service_str = f"{service}:{http_path}:{http_params}"

            if http_failure_string:
                service_str += f":F={http_failure_string}"
            elif http_success_string:
                service_str += f":S={http_success_string}"

            # Add target and service
            cmd_parts.append(target)
            cmd_parts.append(service_str)
        else:
            cmd_parts.append(target)
            cmd_parts.append(service)
    else:
        # Add target and service
        cmd_parts.append(target)
        cmd_parts.append(service)

    # Additional options
    if additional_options:
        cmd_parts.append(additional_options)

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
