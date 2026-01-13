"""
SKYNET Password Cracking - Hashcat Wrapper

High-performance GPU-accelerated password cracking using hashcat.

Clearance Level: Alpha-Red (Offensive Operations Authority)
Specialization: Password hash cracking and mask attacks
Mission: Break password hashes with maximum efficiency

This module provides:
- Hashcat integration for GPU-accelerated cracking
- Multi-format hash support (MD5, SHA1, NTLM, bcrypt, etc.)
- Rule-based and mask-based attacks
- Wordlist management and optimization
- Progress monitoring and session recovery
"""

import os
import subprocess
import time
from typing import Any, Optional


def hashcat_crack(
    hash_file: str,
    hash_type: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    rules: Optional[str] = None,
    use_gpu: bool = True,
    output_file: Optional[str] = None,
    session_name: str = "skynet_hashcat",
    additional_args: Optional[list[str]] = None,
) -> dict[str, Any]:
    """
    Crack password hashes using hashcat.

    Supports GPU acceleration and various attack modes including:
    - Dictionary attack (wordlist)
    - Rule-based attack (wordlist + rules)
    - Mask attack (brute force patterns)
    - Combination attack (multiple wordlists)

    Args:
        hash_file: Path to file containing hashes (one per line)
        hash_type: Hash type identifier or mode number
                   Examples: 'md5', 'sha1', 'ntlm', 'bcrypt', '1000', '5600'
        wordlist: Path to wordlist file (default: rockyou.txt)
        rules: Optional path to hashcat rules file
        use_gpu: Enable GPU acceleration (default: True)
        output_file: Path to save cracked passwords
        session_name: Session name for recovery (default: skynet_hashcat)
        additional_args: Additional hashcat arguments

    Returns:
        Dictionary containing:
        - cracked_passwords: List of cracked password:hash pairs
        - total_hashes: Total number of hashes
        - cracked_count: Number successfully cracked
        - crack_rate: Percentage cracked
        - time_elapsed: Time taken in seconds
        - speed: Hashes per second
        - session_file: Path to session file for recovery
        - success: Whether operation completed
        - error: Error message if failed

    Example:
        >>> # Crack NTLM hashes from file
        >>> result = hashcat_crack(
        ...     hash_file="ntlm_hashes.txt",
        ...     hash_type="ntlm",
        ...     wordlist="/usr/share/wordlists/rockyou.txt"
        ... )
        >>> print(f"Cracked {result['cracked_count']}/{result['total_hashes']} passwords")
        >>> for pwd in result['cracked_passwords']:
        ...     print(f"  {pwd}")

        >>> # Use rules for password mutations
        >>> result = hashcat_crack(
        ...     hash_file="hashes.txt",
        ...     hash_type="md5",
        ...     wordlist="wordlist.txt",
        ...     rules="/usr/share/hashcat/rules/best64.rule"
        ... )

    Hash Type Reference:
        - 'md5' or 0: MD5
        - 'sha1' or 100: SHA1
        - 'ntlm' or 1000: NTLM
        - 'sha256' or 1400: SHA-256
        - 'sha512' or 1700: SHA-512
        - 'bcrypt' or 3200: bcrypt
        - 'wpa' or 2500: WPA/WPA2
        - 'zip' or 13600: WinZip

    Common Rules Files:
        - /usr/share/hashcat/rules/best64.rule (recommended)
        - /usr/share/hashcat/rules/rockyou-30000.rule
        - /usr/share/hashcat/rules/dive.rule
    """
    results = {
        "cracked_passwords": [],
        "total_hashes": 0,
        "cracked_count": 0,
        "crack_rate": 0.0,
        "time_elapsed": 0,
        "speed": 0,
        "session_file": "",
        "success": False,
        "error": None,
    }

    try:
        # Hash type mapping
        hash_type_map = {
            "md5": "0",
            "sha1": "100",
            "sha256": "1400",
            "sha512": "1700",
            "ntlm": "1000",
            "bcrypt": "3200",
            "mysql5": "300",
            "wpa": "2500",
            "wpa2": "2500",
            "zip": "13600",
            "rar": "13000",
        }

        # Convert hash type to mode number
        hash_mode = hash_type_map.get(hash_type.lower(), hash_type)

        # Verify files exist
        if not os.path.exists(hash_file):
            results["error"] = f"Hash file not found: {hash_file}"
            return results

        if not os.path.exists(wordlist):
            results["error"] = f"Wordlist not found: {wordlist}"
            return results

        # Count total hashes
        with open(hash_file) as f:
            results["total_hashes"] = sum(1 for line in f if line.strip())

        # Setup output file
        if output_file is None:
            output_file = f"{hash_file}.cracked"

        # Build hashcat command
        cmd = ["hashcat"]

        # Attack mode: 0 = dictionary attack
        cmd.extend(["-a", "0"])

        # Hash mode
        cmd.extend(["-m", hash_mode])

        # Session name for recovery
        cmd.extend(["--session", session_name])

        # Output format: username:hash:password
        cmd.extend(["--outfile", output_file])
        cmd.extend(["--outfile-format", "2"])  # Format: hash:password

        # GPU/CPU settings
        if use_gpu:
            cmd.append("--opencl-device-types=1,2")  # GPU + CPU
        else:
            cmd.append("--opencl-device-types=2")  # CPU only

        # Rules file if specified
        if rules and os.path.exists(rules):
            cmd.extend(["-r", rules])

        # Force overwrite
        cmd.append("--force")

        # Status updates
        cmd.append("--status")
        cmd.append("--status-timer=10")

        # Additional arguments
        if additional_args:
            cmd.extend(additional_args)

        # Hash file and wordlist
        cmd.append(hash_file)
        cmd.append(wordlist)

        # Store session file path
        results["session_file"] = f"{session_name}.restore"

        # Execute hashcat
        start_time = time.time()

        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,  # 1 hour timeout
        )

        results["time_elapsed"] = time.time() - start_time

        # Parse output file for cracked passwords
        if os.path.exists(output_file):
            with open(output_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        results["cracked_passwords"].append(line)
                        results["cracked_count"] += 1

        # Calculate crack rate
        if results["total_hashes"] > 0:
            results["crack_rate"] = (results["cracked_count"] / results["total_hashes"]) * 100

        # Extract speed from output
        if "Speed.#" in process.stderr:
            # Parse speed line (format varies by hashcat version)
            for line in process.stderr.split("\n"):
                if "Speed" in line and "H/s" in line:
                    try:
                        speed_str = line.split("H/s")[0].split()[-1]
                        results["speed"] = float(speed_str.replace("k", "000").replace("M", "000000"))
                    except Exception:
                        pass

        results["success"] = True

    except subprocess.TimeoutExpired:
        results["error"] = "Hashcat operation timed out (1 hour limit)"
    except FileNotFoundError:
        results["error"] = "Hashcat not found - install with: apt-get install hashcat"
    except Exception as e:
        results["error"] = str(e)

    return results


def generate_hashcat_masks(
    pattern: Optional[str] = None, min_length: int = 8, max_length: int = 12, charset: str = "mixed"
) -> dict[str, Any]:
    """
    Generate hashcat mask patterns for brute force attacks.

    Mask attack allows efficient brute forcing with custom patterns:
    - ?l = lowercase letters (a-z)
    - ?u = uppercase letters (A-Z)
    - ?d = digits (0-9)
    - ?s = special characters
    - ?a = all characters

    Args:
        pattern: Custom mask pattern (e.g., "?u?l?l?l?l?d?d?d?d")
        min_length: Minimum password length (for auto-generated masks)
        max_length: Maximum password length (for auto-generated masks)
        charset: Character set preset ('lower', 'upper', 'mixed', 'digits', 'all')

    Returns:
        Dictionary containing:
        - recommended_masks: List of optimized mask patterns
        - estimated_keyspace: Estimated number of combinations
        - estimated_time: Rough time estimate at common speeds
        - patterns: Dictionary of common password patterns
        - custom_charsets: Custom character sets for specific targets

    Example:
        >>> # Generate masks for corporate passwords (Capital + lowercase + digits)
        >>> masks = generate_hashcat_masks(
        ...     min_length=8,
        ...     max_length=10,
        ...     charset="mixed"
        ... )
        >>> for mask in masks['recommended_masks']:
        ...     print(f"Mask: {mask['pattern']}")
        ...     print(f"  Keyspace: {mask['keyspace']}")
        ...     print(f"  Est. time: {mask['time_estimate']}")

        >>> # Custom pattern for specific format
        >>> masks = generate_hashcat_masks(pattern="Admin?d?d?d?d")
        >>> # Will create: Admin0000, Admin0001, ..., Admin9999
    """
    results = {
        "recommended_masks": [],
        "estimated_keyspace": 0,
        "estimated_time": "",
        "patterns": {},
        "custom_charsets": {},
        "success": False,
        "error": None,
    }

    try:
        # Character set sizes
        charset_sizes = {
            "?l": 26,  # lowercase
            "?u": 26,  # uppercase
            "?d": 10,  # digits
            "?s": 33,  # special chars
            "?a": 95,  # all printable ASCII
        }

        if pattern:
            # Custom pattern provided
            keyspace = 1
            for i in range(0, len(pattern) - 1):
                if pattern[i] == "?":
                    mask_char = "?" + pattern[i + 1]
                    if mask_char in charset_sizes:
                        keyspace *= charset_sizes[mask_char]

            results["recommended_masks"].append(
                {
                    "pattern": pattern,
                    "keyspace": keyspace,
                    "time_estimate": _estimate_crack_time(keyspace),
                }
            )
        else:
            # Generate common patterns
            patterns = _generate_common_patterns(min_length, max_length, charset)
            results["recommended_masks"] = patterns

        # Common password patterns for CTF/corporate
        results["patterns"] = {
            "corporate_simple": "?u?l?l?l?l?d?d?d?d",  # Capital + lowercase + 4 digits
            "corporate_complex": "?u?l?l?l?l?l?d?d?s",  # Capital + letters + digits + special
            "ctf_flag_format": "CTF{?l?l?l?l?l?l?l?l}",  # CTF{lowercase}
            "year_suffix": "?l?l?l?l?l?l?d?d?d?d",  # password2024
            "common_substitution": "P@ssw0rd?d?d",  # P@ssw0rd + 2 digits
            "seasonal": "?u?l?l?l?l?l?d?d?d?d!",  # Spring2024!
        }

        # Custom character sets for targeted attacks
        results["custom_charsets"] = {
            "hex_lowercase": "0123456789abcdef",
            "hex_uppercase": "0123456789ABCDEF",
            "base64": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            "leetspeak": "0135780@!$",  # Common leet substitutions
        }

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def _generate_common_patterns(min_len: int, max_len: int, charset: str) -> list[dict[str, Any]]:
    """Generate common password mask patterns."""
    patterns = []

    # Pattern templates based on charset
    if charset == "lower":
        base = "?l"
    elif charset == "upper":
        base = "?u"
    elif charset == "digits":
        base = "?d"
    elif charset == "mixed":
        # Most common: Capital letter + lowercase + digits
        for length in range(min_len, max_len + 1):
            if length >= 8:
                pattern = "?u" + "?l" * (length - 4) + "?d" * 3
                keyspace = 26 * (26 ** (length - 4)) * (10**3)
                patterns.append(
                    {
                        "pattern": pattern,
                        "keyspace": keyspace,
                        "time_estimate": _estimate_crack_time(keyspace),
                        "description": f"Capital + lowercase + 3 digits ({length} chars)",
                    }
                )
        return patterns
    elif charset == "all":
        base = "?a"
    else:
        base = "?l"

    # Generate patterns for each length
    for length in range(min_len, max_len + 1):
        pattern = base * length

        if base == "?l":
            keyspace = 26**length
        elif base == "?u":
            keyspace = 26**length
        elif base == "?d":
            keyspace = 10**length
        elif base == "?a":
            keyspace = 95**length
        else:
            keyspace = 26**length

        patterns.append(
            {
                "pattern": pattern,
                "keyspace": keyspace,
                "time_estimate": _estimate_crack_time(keyspace),
                "description": f"{charset} charset, {length} characters",
            }
        )

    return patterns


def _estimate_crack_time(keyspace: int, speed: int = 1000000000) -> str:
    """
    Estimate crack time based on keyspace and hash rate.

    Args:
        keyspace: Total number of combinations
        speed: Hashes per second (default: 1 billion for modern GPU)

    Returns:
        Human-readable time estimate
    """
    seconds = keyspace / speed

    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds / 86400:.1f} days"
    else:
        return f"{seconds / 31536000:.1f} years"


def hashcat_mask_attack(
    hash_file: str,
    hash_type: str,
    mask: str,
    increment: bool = False,
    increment_min: int = 1,
    increment_max: int = 8,
    custom_charset: Optional[str] = None,
    session_name: str = "skynet_mask",
) -> dict[str, Any]:
    """
    Perform hashcat mask attack (brute force with pattern).

    Args:
        hash_file: Path to file containing hashes
        hash_type: Hash type identifier (e.g., 'md5', 'ntlm')
        mask: Mask pattern (e.g., "?u?l?l?l?l?d?d?d?d")
        increment: Enable incremental mode (try all lengths)
        increment_min: Minimum length for increment mode
        increment_max: Maximum length for increment mode
        custom_charset: Custom character set (e.g., "0123456789abcdef")
        session_name: Session name for recovery

    Returns:
        Same format as hashcat_crack()

    Example:
        >>> # Brute force 8-char lowercase passwords
        >>> result = hashcat_mask_attack(
        ...     hash_file="hashes.txt",
        ...     hash_type="md5",
        ...     mask="?l?l?l?l?l?l?l?l"
        ... )

        >>> # Incremental attack: try all lengths from 4 to 8
        >>> result = hashcat_mask_attack(
        ...     hash_file="hashes.txt",
        ...     hash_type="ntlm",
        ...     mask="?a?a?a?a?a?a?a?a",
        ...     increment=True,
        ...     increment_min=4,
        ...     increment_max=8
        ... )
    """
    results = {
        "cracked_passwords": [],
        "total_hashes": 0,
        "cracked_count": 0,
        "success": False,
        "error": None,
    }

    try:
        # Hash type mapping
        hash_type_map = {
            "md5": "0",
            "sha1": "100",
            "ntlm": "1000",
            "sha256": "1400",
            "sha512": "1700",
            "bcrypt": "3200",
        }
        hash_mode = hash_type_map.get(hash_type.lower(), hash_type)

        # Build command
        cmd = ["hashcat", "-a", "3", "-m", hash_mode]  # Attack mode 3 = mask
        cmd.extend(["--session", session_name])
        cmd.append("--force")

        # Increment mode
        if increment:
            cmd.append("--increment")
            cmd.extend(["--increment-min", str(increment_min)])
            cmd.extend(["--increment-max", str(increment_max)])

        # Custom charset
        if custom_charset:
            cmd.extend(["-1", custom_charset])
            mask = mask.replace("?c", "?1")  # Use custom charset

        # Output file
        output_file = f"{hash_file}.cracked"
        cmd.extend(["--outfile", output_file])

        cmd.append(hash_file)
        cmd.append(mask)

        # Execute
        subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

        # Parse results
        if os.path.exists(output_file):
            with open(output_file) as f:
                results["cracked_passwords"] = [line.strip() for line in f if line.strip()]
                results["cracked_count"] = len(results["cracked_passwords"])

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
