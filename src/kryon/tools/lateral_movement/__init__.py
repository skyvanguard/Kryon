"""
KRYON Lateral Movement Tools Module
=====================================

This module provides lateral movement capabilities for network penetration.
Includes pass-the-hash, remote execution, pivoting, and tunneling tools.

Capabilities:
- Pass-the-Hash (PTH) attacks
- Pass-the-Ticket (PTT) for Kerberos
- Remote command execution (WMI, DCOM, PsExec-style)
- SSH tunneling and port forwarding
- SOCKS proxy setup
- Network pivoting

Agents using this module:
- Pentest Agent (Alpha-Red): Network penetration and lateral movement
- Network Analyst (Alpha-Silver): Network reconnaissance and pivoting

Authorization: Only use within authorized penetration testing scope.
"""

from .pivoting import (
    check_pivot_connectivity,
    setup_port_forward,
    setup_reverse_port_forward,
    setup_socks_proxy,
    setup_ssh_tunnel,
)
from .pth_attacks import (
    crack_ntlm_hash,
    extract_ntlm_hash,
    pass_the_hash,
    pass_the_ticket,
)
from .remote_execution import (
    dcomexec_execute,
    psexec_execute,
    smbexec_execute,
    ssh_execute,
    winrm_execute,
    wmiexec_execute,
)

__all__ = [
    # PTH Attacks
    "pass_the_hash",
    "pass_the_ticket",
    "extract_ntlm_hash",
    "crack_ntlm_hash",
    # Remote Execution
    "psexec_execute",
    "wmiexec_execute",
    "smbexec_execute",
    "dcomexec_execute",
    "ssh_execute",
    "winrm_execute",
    # Pivoting
    "setup_ssh_tunnel",
    "setup_port_forward",
    "setup_socks_proxy",
    "setup_reverse_port_forward",
    "check_pivot_connectivity",
]
