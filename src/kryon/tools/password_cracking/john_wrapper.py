"""
KRYON Password Cracking - John the Ripper Wrapper

CPU-optimized password cracking using John the Ripper.

Clearance Level: Alpha-Red (Offensive Operations Authority)
Specialization: Password hash cracking and format detection
Mission: Break password hashes with intelligent automation

This module provides:
- John the Ripper integration for CPU-based cracking
- Automatic hash format detection
- Custom rule generation for CTF patterns
- Incremental and wordlist modes
- Session management and recovery
"""

import os
import subprocess
import time
from typing import Any, Optional


def john_crack(
    hash_file: str,
    format: str = "auto",
    wordlist: Optional[str] = None,
    rules: Optional[str] = None,
    incremental: bool = False,
    session_name: str = "skynet_john",
    show_cracked: bool = True,
    timeout_minutes: int = 60,
) -> dict[str, Any]:
    """
    Crack password hashes using John the Ripper.

    John excels at:
    - Automatic hash format detection
    - CPU-optimized cracking
    - Intelligent rule generation
    - Password mangling and mutations

    Args:
        hash_file: Path to file containing hashes
        format: Hash format (auto-detect or specify: md5, sha1, ntlm, bcrypt, etc.)
        wordlist: Path to wordlist file (if None, uses incremental mode)
        rules: Rules to apply ('single', 'wordlist', or path to rules file)
        incremental: Enable incremental mode (brute force)
        session_name: Session name for recovery
        show_cracked: Display cracked passwords after completion
        timeout_minutes: Maximum time to run (default: 60 minutes)

    Returns:
        Dictionary containing:
        - cracked_passwords: List of username:password pairs
        - total_hashes: Total number of hashes
        - cracked_count: Number successfully cracked
        - crack_rate: Percentage cracked
        - time_elapsed: Time taken in seconds
        - format_detected: Detected hash format
        - session_file: Path to session file
        - success: Whether operation completed
        - error: Error message if failed

    Example:
        >>> # Auto-detect format and crack with wordlist
        >>> result = john_crack(
        ...     hash_file="hashes.txt",
        ...     wordlist="/usr/share/wordlists/rockyou.txt"
        ... )
        >>> print(f"Cracked {result['cracked_count']}/{result['total_hashes']} passwords")
        >>> for pwd in result['cracked_passwords']:
        ...     print(f"  {pwd}")

        >>> # Use specific format with rules
        >>> result = john_crack(
        ...     hash_file="ntlm_hashes.txt",
        ...     format="nt",
        ...     wordlist="wordlist.txt",
        ...     rules="best64"
        ... )

        >>> # Incremental mode (brute force)
        >>> result = john_crack(
        ...     hash_file="hashes.txt",
        ...     format="md5",
        ...     incremental=True,
        ...     timeout_minutes=30
        ... )

    Supported Formats:
        - md5, md5crypt
        - sha1, sha256, sha512
        - ntlm, netlm, netntlmv2
        - bcrypt
        - mysql, mysql-sha1
        - phpass (WordPress)
        - zip, rar
        - office (MS Office documents)
        - And many more...
    """
    results = {
        "cracked_passwords": [],
        "total_hashes": 0,
        "cracked_count": 0,
        "crack_rate": 0.0,
        "time_elapsed": 0,
        "format_detected": "",
        "session_file": "",
        "success": False,
        "error": None,
    }

    try:
        # Verify hash file exists
        if not os.path.exists(hash_file):
            results["error"] = f"Hash file not found: {hash_file}"
            return results

        # Count total hashes
        with open(hash_file) as f:
            results["total_hashes"] = sum(1 for line in f if line.strip())

        # Build john command
        cmd = ["john"]

        # Format specification
        if format != "auto":
            # Map common format names
            format_map = {
                "md5": "raw-md5",
                "sha1": "raw-sha1",
                "sha256": "raw-sha256",
                "sha512": "raw-sha512",
                "ntlm": "nt",
                "bcrypt": "bcrypt",
            }
            john_format = format_map.get(format.lower(), format)
            cmd.extend(["--format=" + john_format])
            results["format_detected"] = john_format

        # Session name
        cmd.extend(["--session=" + session_name])
        results["session_file"] = f"{session_name}.rec"

        # Attack mode
        if incremental:
            # Incremental mode (brute force)
            cmd.append("--incremental")
        elif wordlist:
            # Wordlist mode
            if not os.path.exists(wordlist):
                results["error"] = f"Wordlist not found: {wordlist}"
                return results

            cmd.extend(["--wordlist=" + wordlist])

            # Rules
            if rules:
                if rules in ["single", "wordlist", "jumbo", "best64"]:
                    cmd.extend(["--rules=" + rules])
                elif os.path.exists(rules):
                    cmd.extend(["--rules=" + rules])
        else:
            # Single crack mode (uses username/GECOS as wordlist)
            cmd.append("--single")

        # Hash file
        cmd.append(hash_file)

        # Execute john
        start_time = time.time()

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_minutes * 60)
            results["time_elapsed"] = time.time() - start_time

        except subprocess.TimeoutExpired:
            results["time_elapsed"] = timeout_minutes * 60
            # Timeout is not necessarily an error - may have cracked some

        # Show cracked passwords
        if show_cracked:
            show_cmd = ["john", "--show"]
            if format != "auto":
                show_cmd.extend(["--format=" + john_format])
            show_cmd.append(hash_file)

            show_process = subprocess.run(show_cmd, capture_output=True, text=True)

            # Parse output (format: username:password:uid:gid:gecos:home:shell)
            for line in show_process.stdout.split("\n"):
                line = line.strip()
                if line and ":" in line and not line.startswith("0 password"):
                    results["cracked_passwords"].append(line)
                    results["cracked_count"] += 1

        # Calculate crack rate
        if results["total_hashes"] > 0:
            results["crack_rate"] = (results["cracked_count"] / results["total_hashes"]) * 100

        results["success"] = True

    except FileNotFoundError:
        results["error"] = "John the Ripper not found - install with: apt-get install john"
    except Exception as e:
        results["error"] = str(e)

    return results


def john_generate_rules(output_file: str = "/tmp/skynet_john_rules.conf", target_type: str = "ctf") -> dict[str, Any]:
    """
    Generate custom John the Ripper rules for specific password patterns.

    Creates optimized rule sets for:
    - CTF flag formats (CTF{}, FLAG{}, etc.)
    - Corporate password policies
    - Common substitutions (leet speak)
    - Year/season suffixes
    - Special character patterns

    Args:
        output_file: Path to save generated rules file
        target_type: Type of target ('ctf', 'corporate', 'generic')

    Returns:
        Dictionary containing:
        - rule_file: Path to generated rules file
        - rule_count: Number of rules generated
        - rule_description: Description of rule patterns
        - examples: Example password transformations
        - success: Whether operation completed
        - error: Error message if failed

    Example:
        >>> # Generate CTF-specific rules
        >>> result = john_generate_rules(
        ...     output_file="/tmp/ctf_rules.conf",
        ...     target_type="ctf"
        ... )
        >>> print(f"Generated {result['rule_count']} rules")
        >>> print(f"Rule file: {result['rule_file']}")
        >>>
        >>> # Use with john
        >>> john_crack(
        ...     hash_file="hashes.txt",
        ...     wordlist="wordlist.txt",
        ...     rules=result['rule_file']
        ... )

    Rule Types:
        - Capitalization (first letter, all caps, toggle case)
        - Leet speak (a->@, e->3, i->1, o->0, s->$, t->7)
        - Suffix addition (123, 2024, !, !!, etc.)
        - Prefix addition (admin, user, test)
        - Character substitution
        - Duplication (password -> passwordpassword)
    """
    results = {
        "rule_file": output_file,
        "rule_count": 0,
        "rule_description": "",
        "examples": [],
        "success": False,
        "error": None,
    }

    try:
        rules = []

        if target_type == "ctf":
            # CTF-specific rules
            rules.extend(
                [
                    # Original word
                    ":",
                    # Capitalize first letter
                    "c",
                    # All lowercase
                    "l",
                    # All uppercase
                    "u",
                    # Toggle case
                    "t",
                    # Append digits
                    "$1 $2 $3",
                    "$2 $0 $2 $4",
                    "$! $! $!",
                    # Leet speak transformations
                    "sa@",  # a -> @
                    "se3",  # e -> 3
                    "si1",  # i -> 1
                    "so0",  # o -> 0
                    "ss$",  # s -> $
                    "st7",  # t -> 7
                    # Combined transformations
                    "c $1 $2 $3",  # Capital + 123
                    "c $2 $0 $2 $4",  # Capital + year
                    "l $! $!",  # lowercase + !!
                    # CTF flag format
                    "^{ ^F ^T ^C",  # CTF{word
                    # Duplicates
                    "d",  # duplicate word
                    # Reverse
                    "r",  # reverse word
                ]
            )

            results["rule_description"] = "CTF-optimized rules with leet speak, common suffixes, and flag formats"
            results["examples"] = [
                "password -> Password",
                "password -> password123",
                "password -> p@ssw0rd",
                "password -> Password2024",
                "flag -> CTF{flag",
                "admin -> admin!!",
            ]

        elif target_type == "corporate":
            # Corporate password policy rules
            rules.extend(
                [
                    # Capitalize first letter + digits + special
                    "c $1 $!",
                    "c $2 $0 $2 $4 $!",
                    "c $2 $0 $2 $5 $!",
                    # Company name patterns
                    "c $@ $1 $2 $3",
                    # Season + year
                    "c $2 $0 $2 $4",
                    "c $2 $0 $2 $5",
                    # Common corporate suffixes
                    "$! $2 $0 $2 $4",
                    "$@ $2 $0 $2 $4",
                    "$# $1 $2 $3",
                    # Leet speak + corporate
                    "sa@ se3 c $!",
                    "sa@ se3 c $2 $0 $2 $4",
                    # First letter capital + rest lowercase + suffix
                    "c l $1 $2 $3 $!",
                ]
            )

            results["rule_description"] = "Corporate password policy rules with complexity requirements"
            results["examples"] = [
                "company -> Company1!",
                "password -> Password2024!",
                "spring -> Spring2024",
                "admin -> Admin@2024",
                "password -> P@ssw0rd!",
            ]

        else:  # generic
            # Generic comprehensive rules
            rules.extend(
                [
                    ":",  # No change
                    "c",  # Capitalize
                    "l",  # Lowercase
                    "u",  # Uppercase
                    "C",  # Lowercase first, uppercase rest
                    "t",  # Toggle case
                    "r",  # Reverse
                    "d",  # Duplicate
                    "$1",
                    "$2",
                    "$3",
                    "$!",
                    "$@",
                    "$#",  # Append characters
                    "^1",
                    "^2",
                    "^3",  # Prepend characters
                    "sa@",
                    "se3",
                    "si1",
                    "so0",
                    "ss$",  # Leet speak
                    "c $1 $2 $3",  # Cap + 123
                    "l $! $!",  # Lower + !!
                ]
            )

            results["rule_description"] = "Generic comprehensive rule set"
            results["examples"] = [
                "password -> Password",
                "password -> password123",
                "password -> p@ssw0rd",
                "password -> drowssap (reversed)",
            ]

        # Write rules to file
        with open(output_file, "w") as f:
            f.write("# KRYON Custom John the Ripper Rules\n")
            f.write(f"# Target Type: {target_type}\n")
            f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("[List.Rules:KRYON]\n")
            for rule in rules:
                f.write(rule + "\n")

        results["rule_count"] = len(rules)
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def john_show_formats() -> dict[str, Any]:
    """
    List all hash formats supported by John the Ripper.

    Returns:
        Dictionary containing:
        - formats: List of supported format names
        - format_count: Total number of formats
        - common_formats: Dictionary of commonly used formats
        - success: Whether operation completed
        - error: Error message if failed

    Example:
        >>> formats = john_show_formats()
        >>> print(f"Total formats: {formats['format_count']}")
        >>> for name, desc in formats['common_formats'].items():
        ...     print(f"  {name}: {desc}")
    """
    results = {
        "formats": [],
        "format_count": 0,
        "common_formats": {},
        "success": False,
        "error": None,
    }

    try:
        # Run john --list=formats
        process = subprocess.run(["john", "--list=formats"], capture_output=True, text=True)

        # Parse output
        formats = []
        for line in process.stdout.split("\n"):
            line = line.strip()
            if line and not line.startswith("User") and "," in line:
                # Format: name, description
                formats.append(line)

        results["formats"] = formats
        results["format_count"] = len(formats)

        # Common formats reference
        results["common_formats"] = {
            "raw-md5": "MD5 hash",
            "raw-sha1": "SHA-1 hash",
            "raw-sha256": "SHA-256 hash",
            "raw-sha512": "SHA-512 hash",
            "nt": "NTLM (Windows)",
            "netlm": "NetLM (Windows)",
            "netntlmv2": "NetNTLMv2 (Windows)",
            "bcrypt": "bcrypt (common in Linux)",
            "md5crypt": "MD5-based Unix crypt",
            "sha256crypt": "SHA-256-based Unix crypt",
            "sha512crypt": "SHA-512-based Unix crypt",
            "phpass": "PHPass (WordPress, phpBB)",
            "mysql": "MySQL pre-4.1",
            "mysql-sha1": "MySQL 4.1+",
            "mssql": "MS SQL Server",
            "zip": "ZIP archive",
            "rar": "RAR archive",
            "office": "MS Office documents",
        }

        results["success"] = True

    except FileNotFoundError:
        results["error"] = "John the Ripper not found"
    except Exception as e:
        results["error"] = str(e)

    return results


def john_restore_session(session_name: str = "skynet_john") -> dict[str, Any]:
    """
    Restore a previously interrupted John the Ripper session.

    Args:
        session_name: Name of session to restore

    Returns:
        Dictionary containing:
        - restored: Whether session was restored
        - session_file: Path to session file
        - success: Whether operation completed
        - error: Error message if failed

    Example:
        >>> # If john was interrupted, restore it
        >>> result = john_restore_session("skynet_john")
        >>> if result['restored']:
        ...     print("Session restored successfully")
    """
    results = {
        "restored": False,
        "session_file": f"{session_name}.rec",
        "success": False,
        "error": None,
    }

    try:
        # Check if session file exists
        if not os.path.exists(results["session_file"]):
            results["error"] = f"Session file not found: {results['session_file']}"
            return results

        # Restore session
        cmd = ["john", "--restore=" + session_name]

        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,  # 1 hour
        )

        results["restored"] = True
        results["success"] = True

    except subprocess.TimeoutExpired:
        results["error"] = "Session restore timed out"
    except Exception as e:
        results["error"] = str(e)

    return results


def john_benchmark() -> dict[str, Any]:
    """
    Run John the Ripper benchmark to test hash cracking speed.

    Useful for:
    - Testing system performance
    - Comparing different hash algorithms
    - Estimating crack time

    Returns:
        Dictionary containing:
        - benchmark_results: List of format:speed pairs
        - fastest_format: Fastest hash format tested
        - slowest_format: Slowest hash format tested
        - success: Whether operation completed
        - error: Error message if failed

    Example:
        >>> benchmark = john_benchmark()
        >>> print(f"Fastest: {benchmark['fastest_format']}")
        >>> print(f"Slowest: {benchmark['slowest_format']}")
        >>> for result in benchmark['benchmark_results']:
        ...     print(f"  {result}")
    """
    results = {
        "benchmark_results": [],
        "fastest_format": "",
        "slowest_format": "",
        "success": False,
        "error": None,
    }

    try:
        # Run benchmark
        process = subprocess.run(
            ["john", "--test"],
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes
        )

        # Parse output
        benchmark_data = []
        for line in process.stdout.split("\n"):
            line = line.strip()
            if "c/s" in line:  # candidates per second
                results["benchmark_results"].append(line)

                # Extract speed
                try:
                    speed_part = line.split("c/s")[0].strip().split()[-1]
                    speed = float(speed_part.replace("K", "000").replace("M", "000000"))
                    benchmark_data.append((line, speed))
                except Exception:
                    pass

        # Find fastest and slowest
        if benchmark_data:
            benchmark_data.sort(key=lambda x: x[1])
            results["slowest_format"] = benchmark_data[0][0]
            results["fastest_format"] = benchmark_data[-1][0]

        results["success"] = True

    except subprocess.TimeoutExpired:
        results["error"] = "Benchmark timed out"
    except Exception as e:
        results["error"] = str(e)

    return results
