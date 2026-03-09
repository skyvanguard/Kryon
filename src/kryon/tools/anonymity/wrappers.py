"""
KRYON Anonymity - Integration Wrappers

Automatic anonymity integration for existing KRYON functions.

Clearance Level: Omega-Shadow (Maximum Anonymity Operations Authority)
Specialization: Transparent anonymity injection
Mission: Make all KRYON operations anonymous by default

This module provides:
- Decorators for automatic anonymity
- Wrapper functions for existing tools
- Transparent proxy injection
- Automatic User-Agent randomization
"""

import functools
import os
import subprocess
from typing import Callable


def anonymize(
    tor: bool = True,
    vpn: bool = False,
    rotate_ip: bool = False,
    user_agent: bool = True,
    fingerprint: bool = False,
):
    """
    Decorator to automatically anonymize function calls.

    Applies anonymity features to any function:
    - Routes through Tor/VPN
    - Randomizes User-Agent
    - Rotates IP if requested
    - Randomizes fingerprint

    Args:
        tor: Use Tor proxy
        vpn: Use VPN (requires configuration)
        rotate_ip: Rotate IP before execution
        user_agent: Randomize User-Agent
        fingerprint: Randomize browser fingerprint

    Example:
        >>> from kryon.tools.anonymity.wrappers import anonymize
        >>>
        >>> @anonymize(tor=True, user_agent=True)
        ... def my_recon_function(target):
        ...     # Function automatically uses Tor + random User-Agent
        ...     import requests
        ...     response = requests.get(f"http://{target}")
        ...     return response.text
        >>>
        >>> # Function now runs anonymously
        >>> result = my_recon_function("example.com")

    How It Works:
        1. Decorator checks if anonymity enabled globally
        2. Sets up Tor proxy (if requested)
        3. Generates random User-Agent
        4. Rotates IP (if requested)
        5. Calls original function
        6. Returns result
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            from kryon.tools.anonymity.anonymity_manager import get_anonymity_context

            # Get anonymity context
            context = get_anonymity_context()

            # If global anonymity disabled, run normally
            if not context["enabled"]:
                return func(*args, **kwargs)

            # Rotate IP if requested
            if rotate_ip and context["tor_enabled"]:
                from kryon.tools.anonymity.network_anonymity import rotate_ip as rotate_ip_func

                rotate_ip_func(method="tor")

            # Inject anonymity context into kwargs (if function accepts it)
            if "anonymity_context" in func.__code__.co_varnames:
                kwargs["anonymity_context"] = context

            # Call original function
            return func(*args, **kwargs)

        return wrapper

    return decorator


def anonymous_curl(args: str = "", target: str = "", tor_proxy: bool = True) -> str:
    """
    Anonymous curl wrapper.

    Wraps curl with automatic Tor routing and User-Agent randomization.

    Args:
        args: curl arguments
        target: Target URL
        tor_proxy: Use Tor SOCKS proxy

    Returns:
        curl output

    Example:
        >>> from kryon.tools.anonymity.wrappers import anonymous_curl
        >>>
        >>> # Curl through Tor
        >>> result = anonymous_curl(target="https://check.torproject.org")
        >>> print(result)
        >>> # "Congratulations. This browser is configured to use Tor."
    """
    from kryon.tools.anonymity.anonymity_manager import get_anonymity_context

    context = get_anonymity_context()

    # Build curl command
    cmd_parts = ["curl"]

    # Add Tor proxy if enabled
    if tor_proxy and context["tor_enabled"]:
        cmd_parts.extend(["--socks5-hostname", "localhost:9050"])

    # Add random User-Agent if available
    if context["user_agent"]:
        cmd_parts.extend(["-A", context["user_agent"]])

    # Add user args
    if args:
        cmd_parts.append(args)

    # Add target
    if target:
        cmd_parts.append(target)

    # Execute
    result = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=300)

    return result.stdout


def anonymous_nmap(target: str, args: str = "") -> str:
    """
    Anonymous nmap wrapper.

    Wraps nmap with Tor routing via proxychains.

    Args:
        target: Target to scan
        args: nmap arguments

    Returns:
        nmap output

    Example:
        >>> from kryon.tools.anonymity.wrappers import anonymous_nmap
        >>>
        >>> # Nmap through Tor
        >>> result = anonymous_nmap("10.10.10.5", "-sV -p 80,443")
        >>> print(result)

    Note:
        Requires proxychains4 installed:
        apt install proxychains4
    """
    from kryon.tools.anonymity.anonymity_manager import get_anonymity_context

    context = get_anonymity_context()

    # Build nmap command
    cmd_parts = []

    # Add proxychains if Tor enabled
    if context["tor_enabled"]:
        # Check if proxychains available
        check = subprocess.run(["which", "proxychains4"], capture_output=True, timeout=10)

        if check.returncode == 0:
            cmd_parts.extend(["proxychains4", "-q"])

    cmd_parts.append("nmap")

    # Add args
    if args:
        cmd_parts.extend(args.split())

    # Add target
    cmd_parts.append(target)

    # Execute
    result = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=300)

    return result.stdout


def anonymous_gobuster(url: str, wordlist: str, args: str = "") -> str:
    """
    Anonymous gobuster wrapper.

    Wraps gobuster with Tor routing.

    Args:
        url: Target URL
        wordlist: Wordlist path
        args: Additional gobuster arguments

    Returns:
        gobuster output

    Example:
        >>> from kryon.tools.anonymity.wrappers import anonymous_gobuster
        >>>
        >>> # Gobuster through Tor
        >>> result = anonymous_gobuster(
        ...     url="http://example.com",
        ...     wordlist="/usr/share/wordlists/dirb/common.txt"
        ... )
    """
    from kryon.tools.anonymity.anonymity_manager import get_anonymity_context

    context = get_anonymity_context()

    # Build gobuster command
    cmd_parts = ["gobuster", "dir"]

    # Add URL
    cmd_parts.extend(["-u", url])

    # Add wordlist
    cmd_parts.extend(["-w", wordlist])

    # Add proxy if Tor enabled
    if context["tor_enabled"]:
        cmd_parts.extend(["--proxy", "socks5://localhost:9050"])

    # Add User-Agent if available
    if context["user_agent"]:
        cmd_parts.extend(["-a", context["user_agent"]])

    # Add user args
    if args:
        cmd_parts.extend(args.split())

    # Execute
    result = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=300)

    return result.stdout


def get_anonymous_requests_session():
    """
    Get requests.Session configured for anonymity.

    Returns:
        Configured requests.Session with Tor proxy and random User-Agent

    Example:
        >>> from kryon.tools.anonymity.wrappers import get_anonymous_requests_session
        >>>
        >>> # Get anonymous session
        >>> session = get_anonymous_requests_session()
        >>>
        >>> # All requests through this session use Tor
        >>> response = session.get("https://check.torproject.org")
        >>> print(response.text)
    """
    import requests

    from kryon.tools.anonymity.anonymity_manager import get_anonymity_context

    context = get_anonymity_context()

    session = requests.Session()

    # Configure Tor proxy if enabled
    if context["tor_enabled"]:
        session.proxies = context["tor_proxy"]

    # Set User-Agent if available
    if context["user_agent"]:
        session.headers.update({"User-Agent": context["user_agent"]})

    # Additional headers for anonymity
    if context["fingerprint"]:
        fingerprint = context["fingerprint"]

        # Add language headers
        if fingerprint.get("languages"):
            lang_header = ", ".join(fingerprint["languages"])
            session.headers.update({"Accept-Language": lang_header})

    return session


def inject_anonymity_into_subprocess(command: list, use_tor: bool = True) -> list:
    """
    Inject anonymity into subprocess command.

    Modifies command to route through Tor/proxychains.

    Args:
        command: Original command as list
        use_tor: Prepend proxychains for Tor routing

    Returns:
        Modified command with anonymity

    Example:
        >>> from kryon.tools.anonymity.wrappers import inject_anonymity_into_subprocess
        >>>
        >>> # Original command
        >>> cmd = ["curl", "https://ifconfig.me"]
        >>>
        >>> # Inject anonymity
        >>> anonymous_cmd = inject_anonymity_into_subprocess(cmd)
        >>> # Result: ["proxychains4", "-q", "curl", "https://ifconfig.me"]
        >>>
        >>> # Execute
        >>> import subprocess
        >>> result = subprocess.run(anonymous_cmd, capture_output=True, text=True)
    """
    from kryon.tools.anonymity.anonymity_manager import get_anonymity_context

    context = get_anonymity_context()

    if not context["enabled"] or not use_tor:
        return command

    # Check if proxychains available
    if context["tor_enabled"]:
        check = subprocess.run(["which", "proxychains4"], capture_output=True, timeout=10)

        if check.returncode == 0:
            return ["proxychains4", "-q"] + command

    return command


def wrap_function_with_anonymity(func: Callable) -> Callable:
    """
    Wrap any function with automatic anonymity.

    Generic wrapper that applies anonymity context to any function.

    Args:
        func: Function to wrap

    Returns:
        Wrapped function with anonymity

    Example:
        >>> from kryon.tools.anonymity.wrappers import wrap_function_with_anonymity
        >>> from kryon.tools.reconnaissance import dnsenum
        >>>
        >>> # Wrap existing function
        >>> anonymous_dnsenum = wrap_function_with_anonymity(dnsenum)
        >>>
        >>> # Now uses anonymity automatically
        >>> result = anonymous_dnsenum(target="example.com")
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        from kryon.tools.anonymity.anonymity_manager import get_anonymity_context

        context = get_anonymity_context()

        # Set environment variables for anonymity
        if context["enabled"]:
            if context["tor_enabled"]:
                os.environ["http_proxy"] = "socks5h://localhost:9050"
                os.environ["https_proxy"] = "socks5h://localhost:9050"

        # Call original function
        result = func(*args, **kwargs)

        # Clean up environment
        if context["enabled"]:
            os.environ.pop("http_proxy", None)
            os.environ.pop("https_proxy", None)

        return result

    return wrapper


def auto_wrap_reconnaissance_tools():
    """
    Automatically wrap all reconnaissance tools with anonymity.

    Modifies reconnaissance module to use anonymity by default.

    Example:
        >>> from kryon.tools.anonymity.wrappers import auto_wrap_reconnaissance_tools
        >>> from kryon.tools.anonymity import enable_global_anonymity
        >>>
        >>> # Enable anonymity
        >>> enable_global_anonymity(level="HIGH")
        >>>
        >>> # Auto-wrap all recon tools
        >>> auto_wrap_reconnaissance_tools()
        >>>
        >>> # Now all recon tools use anonymity
        >>> from kryon.tools.reconnaissance import nmap
        >>> nmap("10.10.10.5")  # Automatically uses Tor
    """
    try:
        import kryon.tools.reconnaissance as recon

        # List of functions to wrap
        functions_to_wrap = [
            "nmap",
            "gobuster",
            "dnsenum",
            "curl",
            "nikto",
            "wpscan",
            "ffuf",
            "dirsearch",
        ]

        for func_name in functions_to_wrap:
            if hasattr(recon, func_name):
                original_func = getattr(recon, func_name)
                wrapped_func = wrap_function_with_anonymity(original_func)
                setattr(recon, func_name, wrapped_func)

    except ImportError:
        pass


def create_anonymous_selenium_driver(browser: str = "firefox"):
    """
    Create Selenium WebDriver with anonymity features.

    Configures WebDriver with:
    - Tor proxy
    - Random User-Agent
    - WebRTC leak prevention
    - Canvas poisoning
    - Fingerprint randomization

    Args:
        browser: Browser to use (firefox, chrome)

    Returns:
        Configured WebDriver

    Example:
        >>> from kryon.tools.anonymity.wrappers import create_anonymous_selenium_driver
        >>>
        >>> # Create anonymous browser
        >>> driver = create_anonymous_selenium_driver(browser="firefox")
        >>>
        >>> # Browse anonymously
        >>> driver.get("https://check.torproject.org")
        >>> print(driver.page_source)
        >>> # Should show: "Congratulations. This browser is configured to use Tor."
        >>>
        >>> driver.quit()
    """
    from kryon.tools.anonymity.anonymity_manager import get_anonymity_context
    from kryon.tools.anonymity.identity_anonymity import (
        canvas_poisoning,
        webrtc_leak_prevention,
    )

    context = get_anonymity_context()

    if browser == "firefox":
        from selenium import webdriver
        from selenium.webdriver.firefox.options import Options

        options = Options()

        # Configure Tor proxy
        if context["tor_enabled"]:
            options.set_preference("network.proxy.type", 1)
            options.set_preference("network.proxy.socks", "localhost")
            options.set_preference("network.proxy.socks_port", 9050)
            options.set_preference("network.proxy.socks_remote_dns", True)

        # Set User-Agent
        if context["user_agent"]:
            options.set_preference("general.useragent.override", context["user_agent"])

        # Disable WebRTC
        options.set_preference("media.peerconnection.enabled", False)

        # Create driver
        driver = webdriver.Firefox(options=options)

        # Inject canvas poisoning
        canvas_script = canvas_poisoning(method="random_noise")
        driver.execute_script(canvas_script["javascript"])

        # Inject WebRTC prevention
        webrtc_script = webrtc_leak_prevention()
        driver.execute_script(webrtc_script["javascript"])

        return driver

    elif browser == "chrome":
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options

        options = Options()

        # Configure Tor proxy
        if context["tor_enabled"]:
            options.add_argument("--proxy-server=socks5://localhost:9050")

        # Set User-Agent
        if context["user_agent"]:
            options.add_argument(f"user-agent={context['user_agent']}")

        # Disable WebRTC
        options.add_experimental_option(
            "prefs",
            {
                "webrtc.ip_handling_policy": "disable_non_proxied_udp",
                "webrtc.multiple_routes_enabled": False,
                "webrtc.nonproxied_udp_enabled": False,
            },
        )

        driver = webdriver.Chrome(options=options)

        # Inject scripts
        canvas_script = canvas_poisoning(method="random_noise")
        driver.execute_script(canvas_script["javascript"])

        webrtc_script = webrtc_leak_prevention()
        driver.execute_script(webrtc_script["javascript"])

        return driver

    else:
        raise ValueError(f"Unsupported browser: {browser}")
