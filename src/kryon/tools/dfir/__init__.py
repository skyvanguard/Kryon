"""
KRYON Digital Forensics & Incident Response (DFIR) Tools
==========================================================

Comprehensive toolkit for memory forensics, disk analysis, network forensics,
and log analysis. Essential for incident response and forensic investigations.

Tool Categories:
- Memory Forensics: Volatility framework for RAM analysis
- Disk Forensics: Autopsy, Sleuth Kit, PhotoRec for disk images
- Network Forensics: NetworkMiner, Zeek, Wireshark for PCAP analysis
- Log Analysis: Chainsaw for Windows event logs

PERFORMANCE NOTES:
- Memory/disk forensics: NOT cached (unique per investigation)
- Network forensics: Cached 1 hour (pcap_analysis)
- Log analysis: Cached 30 minutes (log_analysis)
"""

# Memory Forensics (Volatility)
# Disk Forensics
from kryon.tools.dfir.disk_forensics import (
    autopsy_analyze,
    photorec_recover,
    tsk_timeline,
)

# Log Analysis
from kryon.tools.dfir.log_analysis import (
    chainsaw_hunt,
    chainsaw_search,
    evtx_dump,
)

# Network Forensics
from kryon.tools.dfir.network_forensics import (
    networkminer_analyze,
    wireshark_filter,
    zeek_analyze_traffic,
)
from kryon.tools.dfir.volatility_forensics import (
    volatility_dump_process,
    volatility_find_malware,
    volatility_network_connections,
    volatility_process_list,
)

__all__ = [
    # Memory Forensics (4 functions)
    "volatility_process_list",
    "volatility_network_connections",
    "volatility_dump_process",
    "volatility_find_malware",
    # Disk Forensics (3 functions)
    "autopsy_analyze",
    "tsk_timeline",
    "photorec_recover",
    # Network Forensics (3 functions)
    "networkminer_analyze",
    "zeek_analyze_traffic",
    "wireshark_filter",
    # Log Analysis (3 functions)
    "chainsaw_hunt",
    "chainsaw_search",
    "evtx_dump",
]
