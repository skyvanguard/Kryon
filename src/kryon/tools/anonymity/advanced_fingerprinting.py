"""
KRYON Anonymity - Advanced Fingerprinting Evasion

Defense against modern browser and hardware fingerprinting techniques.

Clearance Level: Omega-Shadow (Maximum Anonymity Operations Authority)
Specialization: Fingerprint evasion, tracking prevention, identity obfuscation
Mission: Defeat advanced fingerprinting and tracking

This module provides:
- Hardware fingerprint evasion (GPU, CPU, RAM)
- Font fingerprinting prevention
- Audio context spoofing
- Battery API randomization
- TLS fingerprint randomization (JA3 evasion)
- HTTP/2 fingerprint evasion
- Sensor API spoofing
- Media device randomization
- Performance API fuzzing
- Plugin enumeration blocking
"""

import hashlib
import json
import random
import secrets
from typing import Any


def hardware_fingerprint_evasion(
    randomize_gpu: bool = True, randomize_cpu: bool = True, randomize_ram: bool = True
) -> dict[str, Any]:
    """
    Spoof hardware signatures (GPU, CPU, RAM) to evade fingerprinting.

    Hardware fingerprinting uses:
    - WebGL renderer info (GPU model, vendor)
    - Navigator.hardwareConcurrency (CPU cores)
    - Performance.memory (RAM info)
    - Canvas rendering variations (hardware-specific)

    Args:
        randomize_gpu: Randomize GPU vendor/renderer
        randomize_cpu: Randomize CPU core count
        randomize_ram: Randomize RAM amounts

    Returns:
        JavaScript injection code

    Example:
        >>> from kryon.tools.anonymity import hardware_fingerprint_evasion
        >>>
        >>> # Generate spoofing script
        >>> spoof = hardware_fingerprint_evasion(
        ...     randomize_gpu=True,
        ...     randomize_cpu=True,
        ...     randomize_ram=True
        ... )
        >>>
        >>> # Inject into browser via Selenium
        >>> driver.execute_script(spoof['javascript'])
    """
    results = {
        "randomize_gpu": randomize_gpu,
        "randomize_cpu": randomize_cpu,
        "randomize_ram": randomize_ram,
        "javascript": "",
        "python_selenium": "",
        "success": False,
        "error": None,
    }

    try:
        js_parts = []

        if randomize_gpu:
            # Common GPU vendors and renderers
            gpus = [
                {"vendor": "Intel Inc.", "renderer": "Intel(R) HD Graphics 620"},
                {"vendor": "NVIDIA Corporation", "renderer": "NVIDIA GeForce GTX 1060"},
                {"vendor": "AMD", "renderer": "AMD Radeon RX 580"},
                {"vendor": "Intel Inc.", "renderer": "Intel(R) UHD Graphics 630"},
                {"vendor": "NVIDIA Corporation", "renderer": "NVIDIA GeForce RTX 2060"},
            ]

            gpu = random.choice(gpus)

            js_parts.append(f"""
// Spoof WebGL GPU info
const getParameter = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(parameter) {{
    if (parameter === 37445) {{
        return "{gpu["vendor"]}";  // UNMASKED_VENDOR_WEBGL
    }}
    if (parameter === 37446) {{
        return "{gpu["renderer"]}";  // UNMASKED_RENDERER_WEBGL
    }}
    return getParameter.call(this, parameter);
}};
""")

        if randomize_cpu:
            # Randomize CPU core count (common values)
            cores = random.choice([2, 4, 6, 8, 12, 16])

            js_parts.append(f"""
// Spoof CPU core count
Object.defineProperty(navigator, 'hardwareConcurrency', {{
    get: () => {cores}
}});
""")

        if randomize_ram:
            # Randomize RAM (in GB, then convert to bytes)
            ram_gb = random.choice([4, 8, 16, 32])
            ram_bytes = ram_gb * 1024 * 1024 * 1024

            js_parts.append(f"""
// Spoof memory info
if (performance.memory) {{
    Object.defineProperty(performance.memory, 'jsHeapSizeLimit', {{
        get: () => {ram_bytes}
    }});
    Object.defineProperty(performance.memory, 'totalJSHeapSize', {{
        get: () => {int(ram_bytes * 0.6)}
    }});
    Object.defineProperty(performance.memory, 'usedJSHeapSize', {{
        get: () => {int(ram_bytes * 0.4)}
    }});
}}
""")

        results["javascript"] = "\n".join(js_parts)

        # Python Selenium code
        results["python_selenium"] = f"""
from selenium import webdriver

driver = webdriver.Firefox()

# Inject hardware spoofing before page load
driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {{
    'source': '''
{results["javascript"]}
    '''
}})

driver.get("https://example.com")
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def font_fingerprinting_prevention(randomize_fonts: bool = True, font_set: str = "common") -> dict[str, Any]:
    """
    Prevent font-based fingerprinting.

    Font fingerprinting detects installed fonts:
    - Renders text in different fonts
    - Measures canvas dimensions
    - Creates unique font signature

    Defenses:
    - Report common font set only
    - Randomize reported fonts
    - Block canvas font measurements

    Args:
        randomize_fonts: Randomize font list
        font_set: common, windows, macos, linux

    Returns:
        Font spoofing configuration

    Example:
        >>> from kryon.tools.anonymity import font_fingerprinting_prevention
        >>>
        >>> # Prevent font fingerprinting
        >>> fonts = font_fingerprinting_prevention(
        ...     randomize_fonts=True,
        ...     font_set="windows"
        ... )
    """
    results = {
        "randomize_fonts": randomize_fonts,
        "font_set": font_set,
        "javascript": "",
        "success": False,
        "error": None,
    }

    try:
        font_sets = {
            "common": ["Arial", "Times New Roman", "Courier New", "Verdana", "Georgia"],
            "windows": ["Arial", "Calibri", "Cambria", "Consolas", "Segoe UI", "Tahoma"],
            "macos": ["Helvetica Neue", "San Francisco", "Monaco", "Courier", "Times"],
            "linux": ["DejaVu Sans", "Liberation Sans", "Ubuntu", "Noto Sans"],
        }

        fonts = font_sets.get(font_set, font_sets["common"])

        if randomize_fonts:
            # Add some random fonts from the list
            num_fonts = random.randint(len(fonts), len(fonts) + 5)
            fonts = random.sample(fonts * 2, num_fonts)

        results["fonts"] = fonts

        # JavaScript to override font enumeration
        results["javascript"] = f"""
// Block font fingerprinting
const supportedFonts = {json.dumps(fonts)};

// Override canvas font measurements
const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
CanvasRenderingContext2D.prototype.measureText = function(text) {{
    // Add random noise to measurements
    const result = originalMeasureText.call(this, text);
    const noise = Math.random() * 0.1;
    result.width += noise;
    return result;
}};

// Override font check functions
Document.prototype.fonts = {{
    check: function(font) {{
        // Only report fonts in our allowed list
        return supportedFonts.some(f => font.includes(f));
    }}
}};
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def audio_context_spoofing() -> dict[str, Any]:
    """
    Spoof AudioContext API to prevent audio fingerprinting.

    Audio fingerprinting:
    - Generates audio signal
    - Processes through AudioContext
    - Hardware creates unique distortions
    - Creates audio fingerprint

    Defense:
    - Add random noise to audio data
    - Normalize across hardware

    Returns:
        Audio spoofing script

    Example:
        >>> from kryon.tools.anonymity import audio_context_spoofing
        >>>
        >>> # Prevent audio fingerprinting
        >>> audio = audio_context_spoofing()
        >>> driver.execute_script(audio['javascript'])
    """
    results = {"javascript": "", "success": False, "error": None}

    try:
        results["javascript"] = """
// Spoof AudioContext fingerprinting
const AudioContext = window.AudioContext || window.webkitAudioContext;

if (AudioContext) {
    const OriginalAudioContext = AudioContext;

    window.AudioContext = function() {
        const context = new OriginalAudioContext();

        // Override createOscillator
        const originalCreateOscillator = context.createOscillator;
        context.createOscillator = function() {
            const oscillator = originalCreateOscillator.call(this);

            // Override frequency to add noise
            const originalFrequency = oscillator.frequency;
            Object.defineProperty(oscillator, 'frequency', {
                get: function() {
                    const noise = (Math.random() - 0.5) * 0.01;
                    originalFrequency.value += noise;
                    return originalFrequency;
                }
            });

            return oscillator;
        };

        // Override createDynamicsCompressor
        const originalCreateDynamicsCompressor = context.createDynamicsCompressor;
        context.createDynamicsCompressor = function() {
            const compressor = originalCreateDynamicsCompressor.call(this);

            // Add noise to reduction
            const originalReduction = compressor.reduction;
            Object.defineProperty(compressor, 'reduction', {
                get: function() {
                    return originalReduction + (Math.random() - 0.5) * 0.1;
                }
            });

            return compressor;
        };

        return context;
    };
}
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def battery_api_randomization() -> dict[str, Any]:
    """
    Randomize Battery Status API to prevent fingerprinting.

    Battery fingerprinting:
    - Battery level (0-100%)
    - Charging time
    - Discharging time
    - Charging status

    Creates unique signature especially on laptops.

    Returns:
        Battery randomization script

    Example:
        >>> from kryon.tools.anonymity import battery_api_randomization
        >>>
        >>> # Randomize battery info
        >>> battery = battery_api_randomization()
        >>> driver.execute_script(battery['javascript'])
    """
    results = {"javascript": "", "success": False, "error": None}

    try:
        # Random battery values
        level = random.uniform(0.3, 0.9)
        charging = random.choice([True, False])

        results["javascript"] = f"""
// Randomize Battery API
navigator.getBattery = function() {{
    return Promise.resolve({{
        level: {level},
        charging: {str(charging).lower()},
        chargingTime: Infinity,
        dischargingTime: {random.randint(3600, 14400)},
        addEventListener: function() {{}},
        removeEventListener: function() {{}}
    }});
}};
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def tls_fingerprint_randomization(
    cipher_order: str = "random", extensions: str = "mimic_chrome", curves: str = "randomize"
) -> dict[str, Any]:
    """
    Randomize TLS ClientHello to evade JA3 fingerprinting.

    JA3 fingerprinting:
    - TLS version
    - Cipher suites (order matters)
    - Extensions (order matters)
    - Elliptic curves
    - Point formats

    Creates unique TLS fingerprint (JA3 hash).

    Args:
        cipher_order: random, chrome, firefox, edge
        extensions: mimic_chrome, mimic_firefox, random
        curves: randomize or fixed

    Returns:
        TLS randomization configuration

    Example:
        >>> from kryon.tools.anonymity import tls_fingerprint_randomization
        >>>
        >>> # Evade JA3 fingerprinting
        >>> tls = tls_fingerprint_randomization(
        ...     cipher_order="random",
        ...     extensions="mimic_chrome"
        ... )
        >>>
        >>> # Use with custom TLS library or curl
        >>> # curl --ciphers <cipher_string> https://example.com
    """
    results = {
        "cipher_order": cipher_order,
        "extensions": extensions,
        "curves": curves,
        "cipher_string": "",
        "ja3_hash": "",
        "success": False,
        "error": None,
    }

    try:
        # Common cipher suites
        ciphers = [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        ]

        if cipher_order == "random":
            random.shuffle(ciphers)
        elif cipher_order == "chrome":
            # Chrome's typical order
            ciphers = [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            ]

        results["cipher_string"] = ":".join(ciphers)

        # TLS extensions
        extension_sets = {
            "mimic_chrome": [0, 10, 11, 13, 16, 17, 18, 21, 23, 27, 35, 43, 45, 51],
            "mimic_firefox": [0, 10, 11, 13, 16, 17, 23, 35, 43, 45, 51],
            "random": random.sample(range(0, 60), 10),
        }

        results["extensions"] = extension_sets.get(extensions, extension_sets["mimic_chrome"])

        # Elliptic curves
        if curves == "randomize":
            curve_list = ["X25519", "secp256r1", "secp384r1", "secp521r1"]
            random.shuffle(curve_list)
            results["curves"] = curve_list
        else:
            results["curves"] = ["X25519", "secp256r1", "secp384r1"]

        # Generate JA3 hash (simplified)
        ja3_string = f"771,{'-'.join(map(str, results['extensions']))},{'-'.join(results['curves'])}"
        results["ja3_hash"] = hashlib.md5(ja3_string.encode()).hexdigest()  # nosemgrep: insecure-hash-algorithm-md5

        results["curl_command"] = f"""
curl --ciphers '{results["cipher_string"]}' \\
     --tls13-ciphers '{results["cipher_string"]}' \\
     https://example.com
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def http2_fingerprint_evasion() -> dict[str, Any]:
    """
    Evade HTTP/2 fingerprinting (SETTINGS frame analysis).

    HTTP/2 fingerprinting:
    - SETTINGS frame parameters
    - WINDOW_UPDATE values
    - Priority frames
    - Stream dependencies

    Creates unique HTTP/2 fingerprint (Akamai HTTP/2).

    Returns:
        HTTP/2 evasion configuration

    Example:
        >>> from kryon.tools.anonymity import http2_fingerprint_evasion
        >>>
        >>> # Generate HTTP/2 evasion config
        >>> http2 = http2_fingerprint_evasion()
    """
    results = {
        "settings_frame": {},
        "window_update": 0,
        "priority_scheme": "",
        "success": False,
        "error": None,
    }

    try:
        # Randomize SETTINGS frame
        results["settings_frame"] = {
            "HEADER_TABLE_SIZE": random.choice([4096, 8192, 16384, 65536]),
            "ENABLE_PUSH": random.choice([0, 1]),
            "MAX_CONCURRENT_STREAMS": random.choice([100, 128, 256, 1000]),
            "INITIAL_WINDOW_SIZE": random.choice([65535, 131072, 262144]),
            "MAX_FRAME_SIZE": random.choice([16384, 32768, 65536]),
            "MAX_HEADER_LIST_SIZE": random.choice([8192, 16384, 65536]),
        }

        # Window update size
        results["window_update"] = random.choice([65535, 131072, 262144, 1048576])

        results["note"] = """
HTTP/2 fingerprinting is harder to evade than JA3.
Requires custom HTTP/2 library or browser modification.

Tools:
- h2 (Python library)
- nghttp2 (C library)
- curl with --http2 flag
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def sensor_api_spoofing(
    sensors: list[str] = None,
) -> dict[str, Any]:
    """
    Spoof device sensor APIs (accelerometer, gyroscope, magnetometer).

    Sensor fingerprinting (mobile):
    - Accelerometer readings
    - Gyroscope data
    - Magnetometer values
    - Hardware imperfections create unique signature

    Args:
        sensors: List of sensors to spoof

    Returns:
        Sensor spoofing script

    Example:
        >>> from kryon.tools.anonymity import sensor_api_spoofing
        >>>
        >>> # Spoof all sensors
        >>> sensors = sensor_api_spoofing(
        ...     sensors=["accelerometer", "gyroscope", "magnetometer"]
        ... )
    """
    if sensors is None:
        sensors = ["accelerometer", "gyroscope", "magnetometer"]
    results = {"sensors": sensors, "javascript": "", "success": False, "error": None}

    try:
        js_parts = []

        if "accelerometer" in sensors:
            js_parts.append("""
// Spoof Accelerometer
if (window.DeviceMotionEvent) {
    window.addEventListener = function(event, handler) {
        if (event === 'devicemotion') {
            const fakeHandler = function(e) {
                e.accelerationIncludingGravity = {
                    x: Math.random() * 2 - 1,
                    y: Math.random() * 2 - 1,
                    z: 9.8 + Math.random() * 0.2
                };
                handler(e);
            };
            EventTarget.prototype.addEventListener.call(window, event, fakeHandler);
        }
    };
}
""")

        if "gyroscope" in sensors:
            js_parts.append("""
// Spoof Gyroscope
if (window.DeviceOrientationEvent) {
    window.addEventListener = function(event, handler) {
        if (event === 'deviceorientation') {
            const fakeHandler = function(e) {
                e.alpha = Math.random() * 360;
                e.beta = Math.random() * 180 - 90;
                e.gamma = Math.random() * 180 - 90;
                handler(e);
            };
            EventTarget.prototype.addEventListener.call(window, event, fakeHandler);
        }
    };
}
""")

        if "magnetometer" in sensors:
            js_parts.append("""
// Spoof Magnetometer (if available)
if (window.Magnetometer) {
    window.Magnetometer = class {
        start() {}
        stop() {}
        get x() { return Math.random() * 100 - 50; }
        get y() { return Math.random() * 100 - 50; }
        get z() { return Math.random() * 100 - 50; }
    };
}
""")

        results["javascript"] = "\n".join(js_parts)
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def media_device_randomization() -> dict[str, Any]:
    """
    Randomize media devices (cameras, microphones) enumeration.

    Media device fingerprinting:
    - Device labels
    - Device IDs
    - Number of devices
    - Device capabilities

    Returns:
        Media device spoofing script

    Example:
        >>> from kryon.tools.anonymity import media_device_randomization
        >>>
        >>> # Randomize media devices
        >>> media = media_device_randomization()
        >>> driver.execute_script(media['javascript'])
    """
    results = {"javascript": "", "success": False, "error": None}

    try:
        # Random device names
        camera_names = [
            "HD Webcam",
            "USB Camera",
            "Integrated Camera",
            "FaceTime HD Camera",
            "Logitech Webcam",
        ]

        mic_names = [
            "Built-in Microphone",
            "USB Microphone",
            "Headset Microphone",
            "Array Microphone",
        ]

        num_cameras = random.randint(0, 2)
        num_mics = random.randint(1, 2)

        devices = []
        for _i in range(num_cameras):
            devices.append(
                {
                    "deviceId": secrets.token_hex(16),
                    "kind": "videoinput",
                    "label": random.choice(camera_names),
                    "groupId": secrets.token_hex(16),
                }
            )

        for _i in range(num_mics):
            devices.append(
                {
                    "deviceId": secrets.token_hex(16),
                    "kind": "audioinput",
                    "label": random.choice(mic_names),
                    "groupId": secrets.token_hex(16),
                }
            )

        results["devices"] = devices

        results["javascript"] = f"""
// Randomize media devices
navigator.mediaDevices.enumerateDevices = function() {{
    return Promise.resolve({json.dumps(devices)});
}};
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def performance_api_fuzzing() -> dict[str, Any]:
    """
    Add noise to Performance API to prevent timing attacks.

    Timing attacks use:
    - performance.now() (high-resolution)
    - Date.now() (millisecond resolution)
    - Execution timing differences

    Defense:
    - Add random noise
    - Reduce precision

    Returns:
        Performance API fuzzing script

    Example:
        >>> from kryon.tools.anonymity import performance_api_fuzzing
        >>>
        >>> # Fuzz performance timing
        >>> perf = performance_api_fuzzing()
        >>> driver.execute_script(perf['javascript'])
    """
    results = {"javascript": "", "success": False, "error": None}

    try:
        results["javascript"] = """
// Fuzz Performance API
(function() {
    const originalNow = performance.now;
    const noise = Math.random() * 0.1;

    performance.now = function() {
        // Add random noise and round to 0.1ms
        const time = originalNow.call(this);
        return Math.round((time + noise) * 10) / 10;
    };

    // Also fuzz Date.now()
    const originalDateNow = Date.now;
    Date.now = function() {
        const time = originalDateNow.call(this);
        return time + Math.floor(Math.random() * 2);
    };
})();
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def plugin_enumeration_blocking() -> dict[str, Any]:
    """
    Block plugin and extension enumeration.

    Plugin fingerprinting:
    - navigator.plugins list
    - MIME types
    - Plugin versions
    - Extension detection

    Defense:
    - Report empty plugin list
    - Block extension detection

    Returns:
        Plugin blocking script

    Example:
        >>> from kryon.tools.anonymity import plugin_enumeration_blocking
        >>>
        >>> # Block plugin enumeration
        >>> plugins = plugin_enumeration_blocking()
        >>> driver.execute_script(plugins['javascript'])
    """
    results = {"javascript": "", "success": False, "error": None}

    try:
        results["javascript"] = """
// Block plugin enumeration
Object.defineProperty(navigator, 'plugins', {
    get: () => []
});

Object.defineProperty(navigator, 'mimeTypes', {
    get: () => []
});

// Block common extension detection
(function() {
    // Block resource timing for extension detection
    const originalGetEntriesByType = performance.getEntriesByType;
    performance.getEntriesByType = function(type) {
        const entries = originalGetEntriesByType.call(this, type);
        // Filter out extension URLs
        return entries.filter(entry =>
            !entry.name.startsWith('chrome-extension://') &&
            !entry.name.startsWith('moz-extension://')
        );
    };
})();
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
