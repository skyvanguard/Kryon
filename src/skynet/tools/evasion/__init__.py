"""
KRYON Evasion - Anti-Forensic and Stealth Operations

Complete anti-forensic and evasion capabilities.

Clearance Level: Alpha-Black (Anti-Forensic Operations Authority)
Mission: Remove traces and evade detection

Available Modules:
- log_cleaning: Log cleaning and evidence removal
- timestomping: File timestamp manipulation
- anti_forensic: Secure deletion and forensic countermeasures
- traffic_obfuscation: Network traffic obfuscation and C2 stealth

Example Usage:
    >>> from skynet.tools.evasion import (
    ...     clean_linux_logs,
    ...     remove_command_history,
    ...     selective_log_edit,
    ...     stomp_file_timestamps,
    ...     match_timestamps,
    ...     secure_delete_file,
    ...     wipe_free_space,
    ...     randomize_user_agent,
    ...     obfuscate_dns_query
    ... )
    >>>
    >>> # After compromising system, clean traces
    >>> clean_linux_logs(comprehensive=True)
    >>> remove_command_history()
    >>>
    >>> # Timestomp uploaded webshell to match legitimate file
    >>> match_timestamps(
    ...     target_file="/var/www/html/shell.php",
    ...     reference_file="/var/www/html/index.php"
    ... )
    >>>
    >>> # Securely delete exploit after use
    >>> secure_delete_file(
    ...     file_path="/tmp/exploit.elf",
    ...     overwrite_passes=7
    ... )
    >>>
    >>> # Obfuscate C2 traffic
    >>> ua = randomize_user_agent()
    >>> # Use ua['user_agent'] in requests
"""

# Log cleaning and evidence removal
# Advanced anti-forensic techniques
from .anti_forensic import (
    anti_forensic_cleanup_complete,
    clear_mft_entries_windows,
    clear_prefetch_windows,
    disable_logging_temporarily,
    memory_only_execution,
    secure_delete_file,
    wipe_free_space,
)
from .log_cleaning import (
    clean_linux_logs,
    clean_windows_logs,
    clear_web_logs,
    remove_command_history,
    selective_log_edit,
)

# Timestamp manipulation
from .timestomping import (
    bulk_timestomp,
    get_file_timestamps,
    hide_file_modifications,
    match_timestamps,
    restore_original_timestamps,
    stomp_file_timestamps,
    timestomp_directory_recursive,
)

# Traffic obfuscation and C2 stealth
from .traffic_obfuscation import (
    decode_c2_traffic,
    encode_c2_traffic,
    generate_covert_channel_payload,
    generate_domain_fronting_config,
    jitter_requests,
    obfuscate_dns_query,
    randomize_user_agent,
    timing_randomization,
)

__all__ = [
    # Log cleaning
    "clean_linux_logs",
    "clean_windows_logs",
    "remove_command_history",
    "selective_log_edit",
    "clear_web_logs",
    # Timestomping
    "stomp_file_timestamps",
    "match_timestamps",
    "bulk_timestomp",
    "restore_original_timestamps",
    "hide_file_modifications",
    "get_file_timestamps",
    "timestomp_directory_recursive",
    # Anti-forensic
    "secure_delete_file",
    "wipe_free_space",
    "disable_logging_temporarily",
    "memory_only_execution",
    "clear_prefetch_windows",
    "clear_mft_entries_windows",
    "anti_forensic_cleanup_complete",
    # Traffic obfuscation
    "randomize_user_agent",
    "timing_randomization",
    "encode_c2_traffic",
    "decode_c2_traffic",
    "generate_domain_fronting_config",
    "obfuscate_dns_query",
    "generate_covert_channel_payload",
    "jitter_requests",
]
