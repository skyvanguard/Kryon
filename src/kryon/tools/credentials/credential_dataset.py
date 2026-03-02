"""Credential dataset tools — SecLists search, targeted wordlists, hash identification."""

import re

from kryon.sdk.agents import function_tool
from kryon.server.logging_config import get_logger
from kryon.tools.common import run_command

logger = get_logger(__name__)


@function_tool
def search_credential_dataset(
    query: str,
    dataset: str = "seclists",
    max_results: int = 100,
    ctf=None,
) -> str:
    """
    Search credential datasets (SecLists, custom) for passwords and usernames.

    Args:
        query: Search query (password pattern, username, or keyword)
        dataset: Dataset to search (seclists, custom)
        max_results: Maximum results to return
        ctf: CTF context

    Returns:
        str: Matching credentials/passwords from the dataset
    """
    logger.info("search_credential_dataset called query=%s dataset=%s max_results=%d", query, dataset, max_results)  # nosemgrep: python-logger-credential-disclosure
    if dataset == "seclists":
        seclists_paths = [
            "/usr/share/seclists/Passwords/Common-Credentials/",
            "/usr/share/seclists/Passwords/Default-Credentials/",
            "/usr/share/seclists/Usernames/",
        ]
        results = []
        for path in seclists_paths:
            cmd = f"grep -ri '{query}' {path} 2>/dev/null | head -{max_results}"
            output = run_command(cmd, ctf=ctf)
            if output and "No such file" not in output:
                results.append(output)
        return "\n".join(results) if results else f"No matches for '{query}' in SecLists"
    else:
        return f"Error: Unknown dataset '{dataset}'. Supported: seclists"


@function_tool
def generate_targeted_wordlist(
    target_name: str,
    keywords: str = "",
    min_length: int = 8,
    max_length: int = 20,
    include_leet: bool = True,
    include_dates: bool = True,
    ctf=None,
) -> str:
    """
    Generate an OSINT-based targeted password wordlist.

    Creates a wordlist based on target name, keywords, and common
    password patterns (leet speak, date suffixes, special chars).

    Args:
        target_name: Target organization or person name
        keywords: Additional keywords (comma-separated)
        min_length: Minimum password length
        max_length: Maximum password length
        min_length: Minimum password length
        include_leet: Include leet speak variations (a->@, e->3, etc.)
        include_dates: Include common date suffixes (2024, 2025, etc.)
        ctf: CTF context

    Returns:
        str: Generated wordlist (one password per line)
    """
    logger.info("generate_targeted_wordlist called target_name=%s min_length=%d max_length=%d", target_name, min_length, max_length)
    base_words = [target_name, target_name.lower(), target_name.upper(), target_name.capitalize()]

    if keywords:
        for kw in keywords.split(","):
            kw = kw.strip()
            if kw:
                base_words.extend([kw, kw.lower(), kw.upper(), kw.capitalize()])

    passwords: list[str] = []

    # Base variations
    suffixes = ["!", "@", "#", "$", "123", "1234", "12345", "!", "1!", "123!"]
    if include_dates:
        suffixes.extend(["2023", "2024", "2025", "2026", "@2024", "@2025", "@2026"])

    for word in base_words:
        passwords.append(word)
        for suffix in suffixes:
            pw = f"{word}{suffix}"
            if min_length <= len(pw) <= max_length:
                passwords.append(pw)

    # Leet speak
    if include_leet:
        leet_map = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}
        leet_words = []
        for word in base_words:
            leet = word
            for char, repl in leet_map.items():
                leet = leet.replace(char, repl).replace(char.upper(), repl)
            if leet != word:
                leet_words.append(leet)
                for suffix in suffixes[:5]:
                    pw = f"{leet}{suffix}"
                    if min_length <= len(pw) <= max_length:
                        leet_words.append(pw)
        passwords.extend(leet_words)

    # Deduplicate and filter by length
    seen: set[str] = set()
    filtered = []
    for pw in passwords:
        if pw not in seen and min_length <= len(pw) <= max_length:
            seen.add(pw)
            filtered.append(pw)

    return "\n".join(filtered)


# Hash identification patterns
_HASH_PATTERNS: list[tuple[str, str, int]] = [
    (r"^[a-f0-9]{32}$", "MD5", 32),
    (r"^[a-f0-9]{40}$", "SHA-1", 40),
    (r"^[a-f0-9]{64}$", "SHA-256", 64),
    (r"^[a-f0-9]{128}$", "SHA-512", 128),
    (r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt", 0),
    (r"^\$6\$", "SHA-512 (Unix crypt)", 0),
    (r"^\$5\$", "SHA-256 (Unix crypt)", 0),
    (r"^\$1\$", "MD5 (Unix crypt)", 0),
    (r"^\$apr1\$", "Apache MD5", 0),
    (r"^[a-f0-9]{32}:[a-f0-9]+$", "MD5 (salted)", 0),
    (r"^[a-f0-9]{40}:[a-f0-9]+$", "SHA-1 (salted)", 0),
    (r"^\{SHA\}", "LDAP SHA", 0),
    (r"^\{SSHA\}", "LDAP SSHA", 0),
    (r"^[a-f0-9]{16}$", "MySQL 3.x / Half MD5", 16),
    (r"^\*[A-F0-9]{40}$", "MySQL 4.1+", 0),
    (r"^[a-f0-9]{56}$", "SHA-224", 56),
    (r"^[a-f0-9]{96}$", "SHA-384", 96),
    (r"^pbkdf2", "PBKDF2", 0),
    (r"^scrypt:", "scrypt", 0),
    (r"^\$argon2", "Argon2", 0),
]


@function_tool
def identify_hash_type(
    hash_value: str,
    ctf=None,
) -> str:
    """
    Identify the type of a password hash.

    Analyzes the hash format, length, and prefix to determine the
    hashing algorithm used.

    Args:
        hash_value: The hash string to identify
        ctf: CTF context

    Returns:
        str: Identified hash type(s) with confidence levels
    """
    logger.info("identify_hash_type called hash_value=%s", hash_value[:20])
    hash_value = hash_value.strip()
    matches = []

    for pattern, name, expected_len in _HASH_PATTERNS:
        if re.match(pattern, hash_value, re.IGNORECASE):
            confidence = "high" if expected_len > 0 else "medium"
            matches.append(f"{name} (confidence: {confidence})")

    if not matches:
        length = len(hash_value)
        matches.append(f"Unknown hash (length: {length} chars)")
        if hash_value.startswith("$"):
            matches.append("Possibly a Unix crypt variant")

    return f"Hash: {hash_value[:40]}{'...' if len(hash_value) > 40 else ''}\nPossible types:\n" + "\n".join(f"  - {m}" for m in matches)
