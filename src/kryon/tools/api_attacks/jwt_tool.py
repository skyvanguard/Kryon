"""
JWT Tool - JSON Web Token Exploitation
=======================================

JWT Tool provides comprehensive JWT (JSON Web Token) security testing including
signature verification bypass, key cracking, token forging, and vulnerability
exploitation.

PERFORMANCE: JWT cracking operations are NOT cached as they involve
brute-force attempts that should be fresh for each execution.
"""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def jwt_crack(
    token: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    crack_mode: str = "hs",
    max_length: int = 12,
    alphabet: str = "",
    ctf=None,
) -> str:
    """
    Crack JWT secret keys using dictionary or brute-force attacks.

    Attempts to crack JWT HMAC secrets (HS256, HS384, HS512) using
    wordlist-based attacks or brute-force methods. Essential for
    testing weak JWT implementations.

    Args:
        token: JWT token to crack
        wordlist: Path to wordlist file (default: rockyou.txt)
        crack_mode: Cracking mode (hs, rsa, ec)
        max_length: Maximum password length for brute force
        alphabet: Custom alphabet for brute force
        ctf: CTF context for execution

    Returns:
        str: Cracked secret key or failure message

    Examples:
        # Dictionary attack on HS256 JWT
        jwt_crack(
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            wordlist="/usr/share/wordlists/rockyou.txt"
        )

        # Fast dictionary attack with common secrets
        jwt_crack(
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            wordlist="/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
        )

        # Brute force short secrets
        jwt_crack(
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            crack_mode="hs",
            max_length=6,
            alphabet="abcdefghijklmnopqrstuvwxyz0123456789"
        )

    Supported Algorithms:
        - HS256 (HMAC with SHA-256)
        - HS384 (HMAC with SHA-384)
        - HS512 (HMAC with SHA-512)

    Common Weak Secrets:
        - "secret"
        - "password"
        - "123456"
        - "your-256-bit-secret"
        - "mySecret"

    Attack Strategies:
        1. Try common weak secrets first
        2. Use application-specific wordlist
        3. Try default framework secrets
        4. Brute force short secrets (4-8 chars)

    Security Note:
        JWT cracking is computationally intensive. HS256 with
        strong secrets (32+ random characters) is resistant to
        brute force attacks. Only test on authorized systems.
    """
    cmd_parts = ["jwt_tool", token]

    # Dictionary attack
    if wordlist:
        cmd_parts.extend(["-d", wordlist])

    # Cracking mode
    if crack_mode == "hs":
        cmd_parts.append("-C")  # Crack HMAC secret

    # Brute force options
    if alphabet:
        cmd_parts.extend(["-a", alphabet])

    if max_length:
        cmd_parts.extend(["-l", str(max_length)])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def jwt_forge(
    token: str,
    secret: str = "",
    payload: str = "",
    algorithm: str = "",
    exploit: str = "",
    header_injection: str = "",
    output_file: str = "",
    ctf=None,
) -> str:
    """
    Forge JWT tokens with modified claims or exploit vulnerabilities.

    Creates forged JWT tokens by modifying payload claims, changing
    algorithms, or exploiting common JWT vulnerabilities like algorithm
    confusion, none algorithm, and key injection.

    Args:
        token: Original JWT token
        secret: Secret key for signing (if known)
        payload: New payload claims (JSON format)
        algorithm: Force algorithm (none, HS256, RS256, etc.)
        exploit: Exploit technique (none_alg, alg_confusion, key_injection)
        header_injection: Custom header injection
        output_file: Save forged token to file
        ctf: CTF context for execution

    Returns:
        str: Forged JWT token

    Examples:
        # Forge token with known secret
        jwt_forge(
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            secret="mySecret",
            payload='{"sub": "admin", "role": "administrator"}'
        )

        # None algorithm exploit
        jwt_forge(
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            exploit="none_alg"
        )

        # Algorithm confusion attack (RS256 to HS256)
        jwt_forge(
            token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
            exploit="alg_confusion",
            secret="public_key_as_hmac_secret"
        )

        # Privilege escalation
        jwt_forge(
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            secret="cracked_secret",
            payload='{"user": "hacker", "admin": true, "role": "superadmin"}'
        )

        # Expiration bypass
        jwt_forge(
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            secret="known_secret",
            payload='{"sub": "user123", "exp": 9999999999}'
        )

        # JWT header injection (kid parameter)
        jwt_forge(
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            header_injection='{"kid": "../../../dev/null"}',
            exploit="key_injection"
        )

        # Custom algorithm forcing
        jwt_forge(
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            algorithm="HS512",
            secret="secret"
        )

    Common JWT Vulnerabilities:

    1. None Algorithm:
        - Remove signature verification
        - Set "alg": "none"
        - Remove signature portion

    2. Algorithm Confusion:
        - RS256 (asymmetric) to HS256 (symmetric)
        - Use public key as HMAC secret
        - Server verifies with public key as secret

    3. Weak Secrets:
        - Default secrets
        - Short passwords
        - Common words

    4. Key Injection:
        - kid (Key ID) parameter injection
        - SQL injection in kid
        - Path traversal in kid
        - Command injection in kid

    5. JKU/X5U Header Injection:
        - Point to attacker-controlled keys
        - SSRF via JKU/X5U URLs

    6. Signature Stripping:
        - Remove signature
        - Change to "alg": "none"

    Payload Modifications:

    Privilege Escalation:
        - "admin": true
        - "role": "administrator"
        - "isAdmin": 1
        - "permissions": ["all"]

    User Impersonation:
        - "sub": "admin"
        - "user": "root"
        - "email": "admin@example.com"

    Expiration Bypass:
        - "exp": 9999999999
        - Remove "exp" claim
        - Set far future date

    Security Note:
        JWT forging requires either a cracked secret, known vulnerability,
        or misconfiguration. Always test on authorized systems only.
    """
    cmd_parts = ["jwt_tool", token]

    # Known secret
    if secret:
        cmd_parts.extend(["-S", secret])

    # Payload modification
    if payload:
        cmd_parts.extend(["-I", "-pc", payload])

    # Algorithm forcing. T4-M12: the old code appended a BARE `-T`, which in jwt_tool
    # is interactive tamper mode — with no stdin the subprocess HANGS. `-X a` already
    # performs the non-interactive alg tamper (alg:none family); jwt_tool has no clean
    # non-interactive "set arbitrary alg" flag, so the hang-inducing `-T` is dropped.
    if algorithm:
        cmd_parts.extend(["-X", "a"])  # non-interactive alg tamper

    # Exploit techniques
    if exploit == "none_alg":
        cmd_parts.extend(["-X", "n"])  # None algorithm exploit
    elif exploit == "alg_confusion":
        cmd_parts.extend(["-X", "k"])  # Key confusion
    elif exploit == "key_injection":
        cmd_parts.extend(["-X", "i"])  # Header injection

    # Header injection
    if header_injection:
        cmd_parts.extend(["-I", "-hc", header_injection])

    # Output
    if output_file:
        cmd_parts.extend(["-o", output_file])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def jwt_decode(token: str, verify: bool = False, secret: str = "", ctf=None) -> str:
    """
    Decode and analyze JWT token structure and claims.

    Decodes JWT tokens to reveal header, payload, and signature
    information. Optionally verifies signature if secret is provided.

    Args:
        token: JWT token to decode
        verify: Verify signature (requires secret)
        secret: Secret key for verification
        ctf: CTF context for execution

    Returns:
        str: Decoded JWT header and payload

    Examples:
        # Basic JWT decode
        jwt_decode(
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        )

        # Decode and verify
        jwt_decode(
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            verify=True,
            secret="mySecret"
        )

    JWT Structure:
        Header: {"alg": "HS256", "typ": "JWT"}
        Payload: {"sub": "user", "iat": 1234567890}
        Signature: HMAC-SHA256(header.payload, secret)

    Common Claims:
        - sub: Subject (user ID)
        - iss: Issuer
        - aud: Audience
        - exp: Expiration time
        - iat: Issued at
        - nbf: Not before
        - jti: JWT ID
    """
    cmd_parts = ["jwt_tool", token]

    # T4-M12: the old code appended a bare `-Q` to "just decode". In jwt_tool `-Q`
    # queries a STORED token from its DB by id and errors without one. Running jwt_tool
    # with only the token already prints the decoded header+payload, so decode needs
    # no flag at all.
    if verify and secret:
        cmd_parts.extend(["-V", "-S", secret])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
