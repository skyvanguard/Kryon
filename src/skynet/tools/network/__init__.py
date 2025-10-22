"""
Network Traffic Capture Tools
==============================

Tools for capturing and analyzing network traffic from local and remote systems.

Tool Categories:
- Remote Traffic Capture: Capture packets from remote systems via SSH
- Traffic Analysis: Real-time packet capture and analysis

PERFORMANCE: Network capture is NOT cached (live traffic operations)
"""

from skynet.tools.network.capture_traffic import (
    capture_remote_traffic,
    remote_capture_session,
)

__all__ = [
    "capture_remote_traffic",
    "remote_capture_session",
]
