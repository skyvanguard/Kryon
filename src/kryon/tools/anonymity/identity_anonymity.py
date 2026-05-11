"""
KRYON Anonymity - Digital Identity Anonymization

Browser fingerprinting evasion and identity obfuscation.

Clearance Level: Omega-Shadow (Maximum Anonymity Operations Authority)
Specialization: Browser fingerprinting, identity spoofing, tracking evasion
Mission: Eliminate digital fingerprints and tracking vectors

This module provides:
- Fake identity generation
- Browser fingerprint randomization
- Canvas fingerprinting evasion
- WebRTC leak prevention
- Timezone obfuscation
- Language header randomization
- Screen resolution spoofing
"""

import random
import string
from datetime import datetime
from typing import Any


def generate_fake_identity(country: str = "random", gender: str | None = None) -> dict[str, Any]:
    """
    Generate complete fake identity for anonymous operations.

    Creates realistic fake identity including:
    - Name (first, middle, last)
    - Age and birthdate
    - Email address
    - Phone number
    - Address
    - Social security / ID number

    Args:
        country: Country for identity (US, UK, DE, FR, random)
        gender: Gender (male, female, random)

    Returns:
        Complete fake identity

    Example:
        >>> from kryon.tools.anonymity import generate_fake_identity
        >>>
        >>> # Generate US identity
        >>> identity = generate_fake_identity(country="US", gender="male")
        >>>
        >>> print(f"Name: {identity['full_name']}")
        >>> print(f"Email: {identity['email']}")
        >>> print(f"Phone: {identity['phone']}")
        >>> print(f"Address: {identity['address']}")
        >>>
        >>> # Use for registration
        >>> register_account(
        ...     name=identity['full_name'],
        ...     email=identity['email']
        ... )

    Use Cases:
        - Anonymous account registration
        - OSINT investigations
        - Social engineering testing
        - Privacy research
    """
    results = {
        "country": country,
        "gender": gender,
        "full_name": "",
        "first_name": "",
        "middle_name": "",
        "last_name": "",
        "email": "",
        "phone": "",
        "address": "",
        "birthdate": "",
        "age": 0,
        "ssn": "",
        "success": False,
        "error": None,
    }

    try:
        # Select country if random
        if country == "random":
            country = random.choice(["US", "UK", "DE", "FR", "ES", "IT"])

        # Select gender if random
        if not gender or gender == "random":
            gender = random.choice(["male", "female"])

        # Name databases
        male_names_us = [
            "James",
            "John",
            "Robert",
            "Michael",
            "William",
            "David",
            "Richard",
            "Joseph",
        ]
        female_names_us = ["Mary", "Patricia", "Jennifer", "Linda", "Barbara", "Elizabeth", "Susan"]
        last_names_us = [
            "Smith",
            "Johnson",
            "Williams",
            "Brown",
            "Jones",
            "Garcia",
            "Miller",
            "Davis",
        ]

        male_names_uk = ["Oliver", "George", "Harry", "Jack", "Jacob", "Noah", "Charlie"]
        female_names_uk = ["Olivia", "Amelia", "Isla", "Ava", "Emily", "Isabella"]
        last_names_uk = ["Smith", "Jones", "Taylor", "Brown", "Williams", "Wilson", "Johnson"]

        # Generate name based on country and gender
        if country == "US":
            first = random.choice(male_names_us if gender == "male" else female_names_us)
            middle = random.choice(male_names_us if gender == "male" else female_names_us)
            last = random.choice(last_names_us)
        elif country == "UK":
            first = random.choice(male_names_uk if gender == "male" else female_names_uk)
            middle = random.choice(male_names_uk if gender == "male" else female_names_uk)
            last = random.choice(last_names_uk)
        else:  # Generic
            first = "".join(random.choices(string.ascii_uppercase, k=1)) + "".join(
                random.choices(string.ascii_lowercase, k=random.randint(4, 8))
            )
            middle = "".join(random.choices(string.ascii_uppercase, k=1)) + "".join(
                random.choices(string.ascii_lowercase, k=random.randint(4, 7))
            )
            last = "".join(random.choices(string.ascii_uppercase, k=1)) + "".join(
                random.choices(string.ascii_lowercase, k=random.randint(5, 10))
            )

        results["first_name"] = first
        results["middle_name"] = middle
        results["last_name"] = last
        results["full_name"] = f"{first} {middle} {last}"

        # Generate email
        email_providers = ["gmail.com", "yahoo.com", "outlook.com", "protonmail.com"]
        email_username = f"{first.lower()}.{last.lower()}{random.randint(100, 999)}"
        results["email"] = f"{email_username}@{random.choice(email_providers)}"

        # Generate phone
        if country == "US":
            area_code = random.randint(200, 999)
            prefix = random.randint(200, 999)
            line = random.randint(1000, 9999)
            results["phone"] = f"+1 ({area_code}) {prefix}-{line}"
        elif country == "UK":
            results["phone"] = f"+44 {random.randint(1000, 9999)} {random.randint(100000, 999999)}"
        else:
            results["phone"] = f"+{random.randint(1, 999)} {random.randint(100000000, 9999999999)}"

        # Generate address
        street_num = random.randint(1, 9999)
        street_names = ["Main St", "Oak Ave", "Maple Dr", "Park Ln", "Washington Blvd"]
        city_names = ["Springfield", "Franklin", "Clinton", "Madison", "Georgetown"]

        results["address"] = f"{street_num} {random.choice(street_names)}, {random.choice(city_names)}"

        # Generate age and birthdate
        age = random.randint(25, 65)
        year = datetime.now().year - age
        month = random.randint(1, 12)
        day = random.randint(1, 28)
        results["age"] = age
        results["birthdate"] = f"{year}-{month:02d}-{day:02d}"

        # Generate SSN (US) or equivalent
        if country == "US":
            results["ssn"] = f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"
        else:
            results["ssn"] = f"{random.randint(100000000, 999999999)}"

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def randomize_browser_fingerprint(platform_type: str = "random") -> dict[str, Any]:
    """
    Generate randomized browser fingerprint to evade tracking.

    Browser fingerprinting collects:
    - User-Agent
    - Screen resolution
    - Timezone
    - Installed fonts
    - Canvas fingerprint
    - WebGL fingerprint
    - Audio fingerprint

    Args:
        platform_type: Platform (windows, mac, linux, android, ios, random)

    Returns:
        Randomized browser fingerprint parameters

    Example:
        >>> from kryon.tools.anonymity import randomize_browser_fingerprint
        >>>
        >>> # Generate random fingerprint
        >>> fingerprint = randomize_browser_fingerprint(platform_type="windows")
        >>>
        >>> # Use with Selenium
        >>> from selenium import webdriver
        >>> options = webdriver.ChromeOptions()
        >>> options.add_argument(f'user-agent={fingerprint["user_agent"]}')
        >>> driver = webdriver.Chrome(options=options)
        >>>
        >>> # Inject other fingerprint parameters
        >>> driver.execute_cdp_cmd('Emulation.setTimezoneOverride', {
        ...     'timezoneId': fingerprint['timezone']
        ... })

    Fingerprint Components:
        - User-Agent: Browser identification
        - Screen: Resolution, color depth
        - Timezone: Geographic location indicator
        - Languages: Accept-Language header
        - Plugins: Installed browser plugins
        - Fonts: Available system fonts
    """
    results = {
        "platform": platform_type,
        "user_agent": "",
        "screen_resolution": "",
        "screen_color_depth": 24,
        "timezone": "",
        "languages": [],
        "plugins": [],
        "fonts": [],
        "success": False,
        "error": None,
    }

    try:
        # Select platform if random
        if platform_type == "random":
            platform_type = random.choice(["windows", "mac", "linux", "android", "ios"])

        results["platform"] = platform_type

        # Generate User-Agent
        chrome_version = random.randint(115, 125)

        if platform_type == "windows":
            windows_version = random.choice(["10.0", "11.0"])
            results["user_agent"] = (
                f"Mozilla/5.0 (Windows NT {windows_version}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version}.0.0.0 Safari/537.36"
            )

        elif platform_type == "mac":
            mac_version = random.choice(["10_15_7", "11_6_0", "12_5_0", "13_4_0"])
            results["user_agent"] = (
                f"Mozilla/5.0 (Macintosh; Intel Mac OS X {mac_version}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version}.0.0.0 Safari/537.36"
            )

        elif platform_type == "linux":
            results["user_agent"] = (
                f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version}.0.0.0 Safari/537.36"
            )

        elif platform_type == "android":
            android_version = random.randint(10, 14)
            results["user_agent"] = (
                f"Mozilla/5.0 (Linux; Android {android_version}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version}.0.0.0 Mobile Safari/537.36"
            )

        elif platform_type == "ios":
            ios_version = f"{random.randint(14, 17)}_{random.randint(0, 5)}"
            results["user_agent"] = (
                f"Mozilla/5.0 (iPhone; CPU iPhone OS {ios_version} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"
            )

        # Generate screen resolution (common resolutions)
        resolutions = [
            "1920x1080",
            "1366x768",
            "1440x900",
            "1536x864",
            "2560x1440",
            "1280x720",
            "1600x900",
            "1920x1200",
        ]
        results["screen_resolution"] = random.choice(resolutions)
        results["screen_color_depth"] = random.choice([24, 32])

        # Generate timezone
        timezones = [
            "America/New_York",
            "America/Chicago",
            "America/Los_Angeles",
            "Europe/London",
            "Europe/Paris",
            "Europe/Berlin",
            "Asia/Tokyo",
            "Asia/Shanghai",
            "Australia/Sydney",
        ]
        results["timezone"] = random.choice(timezones)

        # Generate languages
        language_sets = [
            ["en-US", "en"],
            ["en-GB", "en"],
            ["de-DE", "de", "en"],
            ["fr-FR", "fr", "en"],
            ["es-ES", "es", "en"],
        ]
        results["languages"] = random.choice(language_sets)

        # Generate plugins (realistic set)
        all_plugins = [
            "Chrome PDF Plugin",
            "Chrome PDF Viewer",
            "Native Client",
            "Widevine Content Decryption Module",
        ]
        results["plugins"] = random.sample(all_plugins, k=random.randint(2, 4))

        # Generate fonts (realistic subset)
        all_fonts = [
            "Arial",
            "Verdana",
            "Times New Roman",
            "Courier New",
            "Georgia",
            "Palatino",
            "Garamond",
            "Comic Sans MS",
            "Trebuchet MS",
            "Impact",
            "Helvetica",
            "Tahoma",
        ]
        results["fonts"] = random.sample(all_fonts, k=random.randint(20, 40))

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def canvas_poisoning(method: str = "random_noise") -> dict[str, Any]:
    """
    Generate canvas poisoning script to evade canvas fingerprinting.

    Canvas fingerprinting draws hidden text/shapes and reads pixels.
    Each browser/system renders slightly differently → unique fingerprint.

    Canvas poisoning methods:
    - random_noise: Add random noise to canvas pixels
    - offset: Shift canvas data by random offset
    - color_shift: Shift color values slightly

    Args:
        method: Poisoning method (random_noise, offset, color_shift)

    Returns:
        JavaScript code for canvas poisoning

    Example:
        >>> from kryon.tools.anonymity import canvas_poisoning
        >>>
        >>> # Generate canvas poisoning script
        >>> result = canvas_poisoning(method="random_noise")
        >>>
        >>> # Inject into browser (Selenium)
        >>> driver.execute_script(result['javascript'])
        >>>
        >>> # Or use as browser extension content script

    How Canvas Fingerprinting Works:
        1. Website draws text/shapes on hidden canvas
        2. Reads pixel data (getImageData)
        3. Hashes pixel data → fingerprint
        4. Fingerprint is ~99% unique

    How Canvas Poisoning Works:
        - Intercepts getImageData() calls
        - Adds subtle random changes to pixel data
        - Changes are invisible but break fingerprint
        - Each page load = different fingerprint
    """
    results = {"method": method, "javascript": "", "success": False, "error": None}

    try:
        if method == "random_noise":
            # Add random noise to canvas pixels
            js_code = """
(function() {
    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;

    CanvasRenderingContext2D.prototype.getImageData = function(x, y, width, height) {
        const imageData = originalGetImageData.apply(this, arguments);

        // Add random noise to RGBA values
        for (let i = 0; i < imageData.data.length; i += 4) {
            // Random noise: -2 to +2 for each RGB channel
            imageData.data[i] += Math.floor(Math.random() * 5) - 2;     // R
            imageData.data[i+1] += Math.floor(Math.random() * 5) - 2;   // G
            imageData.data[i+2] += Math.floor(Math.random() * 5) - 2;   // B
            // Alpha channel unchanged
        }

        return imageData;
    };

    console.log('[KRYON] Canvas poisoning active: random_noise');
})();
"""

        elif method == "offset":
            # Shift canvas data
            js_code = """
(function() {
    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;

    CanvasRenderingContext2D.prototype.getImageData = function(x, y, width, height) {
        const imageData = originalGetImageData.apply(this, arguments);

        // Random offset: 1-3 pixels
        const offset = Math.floor(Math.random() * 3) + 1;

        const newData = new Uint8ClampedArray(imageData.data.length);
        for (let i = 0; i < imageData.data.length; i++) {
            const newIndex = (i + offset * 4) % imageData.data.length;
            newData[newIndex] = imageData.data[i];
        }

        imageData.data.set(newData);
        return imageData;
    };

    console.log('[KRYON] Canvas poisoning active: offset');
})();
"""

        elif method == "color_shift":
            # Shift color values
            js_code = """
(function() {
    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;

    CanvasRenderingContext2D.prototype.getImageData = function(x, y, width, height) {
        const imageData = originalGetImageData.apply(this, arguments);

        // Random color shift
        const shift = Math.floor(Math.random() * 10) - 5;

        for (let i = 0; i < imageData.data.length; i += 4) {
            imageData.data[i] = (imageData.data[i] + shift) % 256;       // R
            imageData.data[i+1] = (imageData.data[i+1] + shift) % 256;   // G
            imageData.data[i+2] = (imageData.data[i+2] + shift) % 256;   // B
        }

        return imageData;
    };

    console.log('[KRYON] Canvas poisoning active: color_shift');
})();
"""
        else:
            js_code = ""

        results["javascript"] = js_code
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def webrtc_leak_prevention() -> dict[str, Any]:
    """
    Generate JavaScript to prevent WebRTC IP leaks.

    WebRTC can leak real IP address even when using VPN/Tor:
    - STUN servers discover local/public IPs
    - Exposed through RTCPeerConnection
    - Bypasses proxy/VPN configuration

    Returns:
        JavaScript code to disable WebRTC

    Example:
        >>> from kryon.tools.anonymity import webrtc_leak_prevention
        >>>
        >>> # Generate WebRTC blocking script
        >>> result = webrtc_leak_prevention()
        >>>
        >>> # Inject into browser
        >>> driver.execute_script(result['javascript'])

    WebRTC Leak Detection:
        Visit: https://browserleaks.com/webrtc
        Without protection: Shows real IP
        With protection: No IP leak

    Methods to Prevent:
        1. Disable WebRTC in browser settings
        2. Use browser extension (uBlock Origin)
        3. Inject JavaScript to disable RTCPeerConnection
    """
    results = {"javascript": "", "success": False, "error": None}

    try:
        js_code = """
(function() {
    // Method 1: Override RTCPeerConnection
    if (window.RTCPeerConnection) {
        window.RTCPeerConnection = function() {
            throw new Error('WebRTC disabled by KRYON');
        };
    }

    if (window.webkitRTCPeerConnection) {
        window.webkitRTCPeerConnection = function() {
            throw new Error('WebRTC disabled by KRYON');
        };
    }

    if (window.mozRTCPeerConnection) {
        window.mozRTCPeerConnection = function() {
            throw new Error('WebRTC disabled by KRYON');
        };
    }

    // Method 2: Override getUserMedia
    if (navigator.getUserMedia) {
        navigator.getUserMedia = function() {
            throw new Error('getUserMedia disabled by KRYON');
        };
    }

    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
        navigator.mediaDevices.getUserMedia = function() {
            return Promise.reject(new Error('getUserMedia disabled by KRYON'));
        };
    }

    // Method 3: Disable WebRTC data channels
    if (window.RTCDataChannel) {
        window.RTCDataChannel = undefined;
    }

    console.log('[KRYON] WebRTC leak prevention active');
})();
"""

        results["javascript"] = js_code
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def timezone_randomization() -> dict[str, Any]:
    """
    Generate timezone randomization configuration.

    Timezone leaks geographic location:
    - JavaScript: new Date().getTimezoneOffset()
    - Can narrow down location to specific region
    - Combined with other fingerprints → precise location

    Returns:
        Randomized timezone configuration

    Example:
        >>> from kryon.tools.anonymity import timezone_randomization
        >>>
        >>> # Get random timezone
        >>> result = timezone_randomization()
        >>>
        >>> # Use with Selenium CDP
        >>> driver.execute_cdp_cmd('Emulation.setTimezoneOverride', {
        ...     'timezoneId': result['timezone']
        ... })
        >>>
        >>> # Or via JavaScript injection
        >>> driver.execute_script(result['javascript'])
    """
    results = {
        "timezone": "",
        "timezone_offset": 0,
        "javascript": "",
        "success": False,
        "error": None,
    }

    try:
        # All timezones with offsets
        timezones = [
            ("America/New_York", -300),
            ("America/Chicago", -360),
            ("America/Denver", -420),
            ("America/Los_Angeles", -480),
            ("Europe/London", 0),
            ("Europe/Paris", 60),
            ("Europe/Berlin", 60),
            ("Europe/Moscow", 180),
            ("Asia/Dubai", 240),
            ("Asia/Kolkata", 330),
            ("Asia/Shanghai", 480),
            ("Asia/Tokyo", 540),
            ("Australia/Sydney", 600),
            ("Pacific/Auckland", 720),
        ]

        timezone, offset = random.choice(timezones)
        results["timezone"] = timezone
        results["timezone_offset"] = offset

        # JavaScript to override timezone
        js_code = f"""
(function() {{
    const originalDate = Date;
    const timezoneOffset = {offset};

    Date = class extends originalDate {{
        getTimezoneOffset() {{
            return timezoneOffset;
        }}
    }};

    Date.now = originalDate.now;
    Date.parse = originalDate.parse;
    Date.UTC = originalDate.UTC;

    console.log('[KRYON] Timezone spoofed to: {timezone}');
}})();
"""

        results["javascript"] = js_code
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def language_header_randomization() -> dict[str, Any]:
    """
    Generate randomized Accept-Language headers.

    Accept-Language header reveals:
    - User's language preferences
    - Geographic location indicator
    - Browser language settings

    Returns:
        Randomized language configuration

    Example:
        >>> from kryon.tools.anonymity import language_header_randomization
        >>>
        >>> # Get random language headers
        >>> result = language_header_randomization()
        >>>
        >>> # Use with requests
        >>> import requests
        >>> headers = {"Accept-Language": result['accept_language']}
        >>> response = requests.get(url, headers=headers)
    """
    results = {
        "primary_language": "",
        "accept_language": "",
        "navigator_languages": [],
        "success": False,
        "error": None,
    }

    try:
        # Language configurations (realistic)
        language_configs = [
            {"primary": "en-US", "accept": "en-US,en;q=0.9", "navigator": ["en-US", "en"]},
            {"primary": "en-GB", "accept": "en-GB,en;q=0.9", "navigator": ["en-GB", "en"]},
            {
                "primary": "de-DE",
                "accept": "de-DE,de;q=0.9,en;q=0.8",
                "navigator": ["de-DE", "de", "en"],
            },
            {
                "primary": "fr-FR",
                "accept": "fr-FR,fr;q=0.9,en;q=0.8",
                "navigator": ["fr-FR", "fr", "en"],
            },
            {
                "primary": "es-ES",
                "accept": "es-ES,es;q=0.9,en;q=0.8",
                "navigator": ["es-ES", "es", "en"],
            },
            {
                "primary": "zh-CN",
                "accept": "zh-CN,zh;q=0.9,en;q=0.8",
                "navigator": ["zh-CN", "zh", "en"],
            },
            {
                "primary": "ja-JP",
                "accept": "ja-JP,ja;q=0.9,en;q=0.8",
                "navigator": ["ja-JP", "ja", "en"],
            },
        ]

        config = random.choice(language_configs)
        results["primary_language"] = config["primary"]
        results["accept_language"] = config["accept"]
        results["navigator_languages"] = config["navigator"]

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def screen_resolution_spoofing(custom_resolution: str | None = None) -> dict[str, Any]:
    """
    Generate screen resolution spoofing configuration.

    Screen properties reveal:
    - Physical screen size
    - Device type (desktop, mobile, tablet)
    - Operating system hints
    - Window manager configuration

    Args:
        custom_resolution: Custom resolution (e.g., "1920x1080") or None for random

    Returns:
        Screen spoofing configuration with JavaScript

    Example:
        >>> from kryon.tools.anonymity import screen_resolution_spoofing
        >>>
        >>> # Random common resolution
        >>> result = screen_resolution_spoofing()
        >>>
        >>> # Inject into browser
        >>> driver.execute_script(result['javascript'])
        >>>
        >>> # Or use with Selenium CDP
        >>> driver.execute_cdp_cmd('Emulation.setDeviceMetricsOverride', {
        ...     'width': result['width'],
        ...     'height': result['height'],
        ...     'deviceScaleFactor': 1,
        ...     'mobile': False
        ... })
    """
    results = {
        "resolution": "",
        "width": 0,
        "height": 0,
        "color_depth": 24,
        "pixel_ratio": 1.0,
        "javascript": "",
        "success": False,
        "error": None,
    }

    try:
        # Common screen resolutions
        common_resolutions = [
            ("1920x1080", 1920, 1080),
            ("1366x768", 1366, 768),
            ("1440x900", 1440, 900),
            ("1536x864", 1536, 864),
            ("2560x1440", 2560, 1440),
            ("1280x720", 1280, 720),
            ("1600x900", 1600, 900),
            ("1920x1200", 1920, 1200),
        ]

        if custom_resolution:
            width, height = map(int, custom_resolution.split("x"))
            resolution = custom_resolution
        else:
            resolution, width, height = random.choice(common_resolutions)

        results["resolution"] = resolution
        results["width"] = width
        results["height"] = height
        results["color_depth"] = random.choice([24, 32])
        results["pixel_ratio"] = random.choice([1.0, 1.25, 1.5, 2.0])

        # JavaScript to spoof screen properties
        js_code = f"""
(function() {{
    Object.defineProperty(screen, 'width', {{
        get: function() {{ return {width}; }}
    }});

    Object.defineProperty(screen, 'height', {{
        get: function() {{ return {height}; }}
    }});

    Object.defineProperty(screen, 'availWidth', {{
        get: function() {{ return {width}; }}
    }});

    Object.defineProperty(screen, 'availHeight', {{
        get: function() {{ return {height - 40}; }}
    }});

    Object.defineProperty(screen, 'colorDepth', {{
        get: function() {{ return {results["color_depth"]}; }}
    }});

    Object.defineProperty(screen, 'pixelDepth', {{
        get: function() {{ return {results["color_depth"]}; }}
    }});

    Object.defineProperty(window, 'devicePixelRatio', {{
        get: function() {{ return {results["pixel_ratio"]}; }}
    }});

    console.log('[KRYON] Screen spoofed to: {resolution}');
}})();
"""

        results["javascript"] = js_code
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
