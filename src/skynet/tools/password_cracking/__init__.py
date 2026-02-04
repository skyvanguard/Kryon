"""
KRYON Password Cracking Tools

Complete password cracking and analysis toolkit.

Clearance Level: Alpha-Red (Offensive Operations Authority)
Mission: Break password hashes with maximum efficiency

Available Modules:
- hashcat_wrapper: GPU-accelerated hash cracking
- john_wrapper: CPU-optimized cracking with John the Ripper
- password_analysis: Password pattern analysis and wordlist generation

Example Usage:
    >>> from skynet.tools.password_cracking import hashcat_crack, john_crack
    >>> from skynet.tools.password_cracking import analyze_password_policy, generate_custom_wordlist
    >>>
    >>> # Crack NTLM hashes with hashcat
    >>> result = hashcat_crack(
    ...     hash_file="ntlm_hashes.txt",
    ...     hash_type="ntlm",
    ...     wordlist="/usr/share/wordlists/rockyou.txt"
    ... )
    >>>
    >>> # Crack with John the Ripper
    >>> result = john_crack(
    ...     hash_file="hashes.txt",
    ...     format="auto",
    ...     wordlist="wordlist.txt"
    ... )
    >>>
    >>> # Analyze cracked passwords
    >>> analysis = analyze_password_policy(result['cracked_passwords'])
    >>> print(f"Policy hints: {analysis['policy_hints']}")
    >>>
    >>> # Generate custom wordlist
    >>> target_info = {
    ...     "company_name": "TechCorp",
    ...     "locations": ["london"],
    ...     "keywords": ["admin", "welcome"]
    ... }
    >>> wordlist = generate_custom_wordlist(target_info)
"""

from .hashcat_wrapper import generate_hashcat_masks, hashcat_crack, hashcat_mask_attack
from .john_wrapper import (
    john_benchmark,
    john_crack,
    john_generate_rules,
    john_restore_session,
    john_show_formats,
)
from .password_analysis import (
    analyze_password_policy,
    assess_password_strength,
    compare_wordlists,
    generate_custom_wordlist,
)

__all__ = [
    # Hashcat functions
    "hashcat_crack",
    "generate_hashcat_masks",
    "hashcat_mask_attack",
    # John the Ripper functions
    "john_crack",
    "john_generate_rules",
    "john_show_formats",
    "john_restore_session",
    "john_benchmark",
    # Analysis functions
    "analyze_password_policy",
    "generate_custom_wordlist",
    "assess_password_strength",
    "compare_wordlists",
]
