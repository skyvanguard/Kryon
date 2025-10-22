"""
Browser Automation Tools - Chrome Infiltrator Series

This module provides advanced browser automation capabilities for dynamic
web application testing, JavaScript analysis, and interactive security testing.

Available Tools:
- browser_navigate: Navigate to URLs and capture page information
- browser_screenshot: Capture visual screenshots of web pages
- browser_execute_js: Execute JavaScript in browser context
- browser_fill_form: Fill and submit web forms automatically
- browser_intercept_traffic: Intercept and analyze network traffic
- browser_analyze_dom: Analyze DOM structure and security issues
- browser_extract_cookies: Extract and analyze cookies
- browser_test_xss: Test for XSS vulnerabilities dynamically
"""

from .playwright_tools import (
    browser_navigate,
    browser_screenshot,
    browser_execute_js,
    browser_fill_form,
    browser_intercept_traffic,
    browser_analyze_dom,
    browser_extract_cookies,
    browser_test_xss
)

__all__ = [
    "browser_navigate",
    "browser_screenshot",
    "browser_execute_js",
    "browser_fill_form",
    "browser_intercept_traffic",
    "browser_analyze_dom",
    "browser_extract_cookies",
    "browser_test_xss"
]
