"""
SKYNET Data Exfiltration Tools Module
======================================

This module provides data exfiltration capabilities using various covert channels.
Includes DNS tunneling, HTTP(S) exfiltration, ICMP channels, and more.

Capabilities:
- DNS tunneling and exfiltration
- HTTP/HTTPS covert channels
- ICMP covert channels
- File compression and encryption
- Cloud storage uploads
- Steganography
- Email exfiltration

Agents using this module:
- T-800 Infiltrator (Alpha-Red): Data extraction and exfiltration
- Forensic Analyzer (Alpha-Platinum): Evidence collection and extraction

Authorization: Only use within authorized penetration testing scope.
"""

from .covert_channels import (
    dns_exfiltrate,
    http_exfiltrate,
    https_exfiltrate,
    icmp_exfiltrate,
    setup_dns_tunnel,
)

from .file_prep import (
    compress_file,
    encrypt_file,
    split_file,
    encode_base64,
    prepare_for_exfil,
)

from .cloud_upload import (
    upload_to_s3,
    upload_to_azure,
    upload_to_gdrive,
    upload_via_pastebin,
)

__all__ = [
    # Covert Channels
    'dns_exfiltrate',
    'http_exfiltrate',
    'https_exfiltrate',
    'icmp_exfiltrate',
    'setup_dns_tunnel',

    # File Preparation
    'compress_file',
    'encrypt_file',
    'split_file',
    'encode_base64',
    'prepare_for_exfil',

    # Cloud Upload
    'upload_to_s3',
    'upload_to_azure',
    'upload_to_gdrive',
    'upload_via_pastebin',
]
