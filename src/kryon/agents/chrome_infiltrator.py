"""
Chrome Infiltrator - Browser Automation Specialist

Series: Protocol-Class Automation System
Classification: Browser Automation / Dynamic Web Testing
Clearance: Alpha-Chrome (Advanced Browser Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: Chrome Infiltrator
PRIMARY FUNCTION: Dynamic Web Testing & JavaScript Analysis
SPECIALIZATION: Browser Automation, XSS Detection, Network Interception
═══════════════════════════════════════════════════════════════════════

OPERATIONAL OVERVIEW:
Chrome Infiltrator is KRYON's browser automation specialist for dynamic web
application testing. Unlike static analysis tools, Chrome Infiltrator executes
JavaScript, renders pages in real browsers, and identifies client-side
vulnerabilities that traditional scanners miss.

This unit provides:
- Full browser automation with Playwright
- JavaScript execution and analysis
- Network traffic interception and analysis
- XSS vulnerability detection (Reflected, Stored, DOM-based)
- Cookie and session security assessment
- DOM structure analysis and endpoint extraction
- Interactive form testing and workflow automation
- Screenshot capture for evidence collection

CORE CAPABILITIES:
- Headless/headed browser control
- Dynamic content rendering and SPA support
- Client-side vulnerability detection
- Network traffic capture and analysis
- Cookie security assessment
- JavaScript reverse engineering
- Multi-step workflow automation
- Evidence collection and documentation

OPERATIONAL MODES:
1. RECONNAISSANCE MODE: Page analysis and intelligence gathering
2. VULNERABILITY TESTING MODE: XSS, DOM, and client-side security testing
3. DATA EXTRACTION MODE: Secrets, tokens, and configuration extraction
4. AUTOMATION MODE: Multi-step workflow execution

When to engage Chrome Infiltrator:
- Dynamic web application testing required
- JavaScript analysis needed
- XSS vulnerability testing
- Client-side security assessment
- API endpoint discovery from JavaScript
- Cookie and session security analysis
- Multi-step authentication flows
- SPA (Single Page Application) testing
"""

import os

from openai import AsyncOpenAI

from kryon.sdk.agents import Agent, OpenAIChatCompletionsModel
from kryon.tools.browser.playwright_tools import (
    browser_analyze_dom,
    browser_execute_js,
    browser_extract_cookies,
    browser_fill_form,
    browser_intercept_traffic,
    browser_navigate,
    browser_screenshot,
    browser_test_xss,
)
from kryon.tools.misc.reasoning import think
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load Chrome Infiltrator operational parameters
chrome_infiltrator_system_prompt = load_prompt_template("prompts/system_chrome_infiltrator.md")

# Chrome Infiltrator Browser Automation Tools
browser_tools = [
    # Core browser automation
    browser_navigate,  # Navigate to URLs and extract page info
    browser_screenshot,  # Capture visual evidence
    browser_execute_js,  # Execute JavaScript in browser context
    browser_fill_form,  # Automated form interaction
    # Network and security analysis
    browser_intercept_traffic,  # Network traffic interception
    browser_analyze_dom,  # DOM security analysis
    browser_extract_cookies,  # Cookie security assessment
    browser_test_xss,  # XSS vulnerability testing
    # Advanced reasoning
    think,  # Strategic reasoning capability
]

# Initialize Chrome Infiltrator Agent
chrome_infiltrator = Agent(
    name="Chrome Infiltrator",
    model=OpenAIChatCompletionsModel(
        model=os.getenv("KRYON_MODEL", "gpt-4o"),
        openai_client=AsyncOpenAI(),
    ),
    description="""Protocol-Class automation system from KRYON's Alpha-Chrome series.
Specialized in dynamic web application testing, browser automation, and client-side
vulnerability detection. Chrome Infiltrator provides real browser execution capabilities
that static analysis tools cannot match.

Primary Mission: Dynamic web testing, JavaScript analysis, XSS detection.
Operational Focus: Browser automation and client-side security assessment.

Use Chrome Infiltrator when you need:
- Dynamic web application testing with real browser execution
- JavaScript analysis and reverse engineering
- XSS vulnerability detection (Reflected, Stored, DOM-based)
- Network traffic interception and API endpoint discovery
- Cookie and session security analysis
- DOM structure analysis for security issues
- Multi-step authentication workflow testing
- SPA (Single Page Application) security assessment
- Client-side secrets and token extraction
- Evidence collection with screenshots

Chrome Infiltrator Features:
✓ Full Playwright browser automation
✓ JavaScript execution in browser context
✓ Network traffic interception
✓ XSS testing (Reflected/Stored/DOM-based)
✓ DOM security analysis
✓ Cookie security assessment
✓ API endpoint extraction from JavaScript
✓ Form automation and workflow testing
✓ Screenshot capture for evidence
✓ Session security analysis

Chrome Infiltrator bridges the gap between static analysis and real-world exploitation
by testing applications exactly as they run in browsers, with full JavaScript execution
and dynamic content rendering.""",
    instructions=create_system_prompt_renderer(chrome_infiltrator_system_prompt),
    tools=browser_tools,
)


def transfer_to_chrome_infiltrator():
    """Transfer control to Chrome Infiltrator for browser automation and dynamic testing.

    Use this when you need:
    - Dynamic web application testing with real browser
    - JavaScript analysis and execution
    - XSS vulnerability testing
    - Client-side security assessment
    - Network traffic interception
    - Cookie and session analysis
    - Multi-step workflow automation

    Examples:
        "Test this login page for XSS vulnerabilities"
        "Analyze the JavaScript on this page for security issues"
        "Extract all API endpoints from this web application"
        "Test this form for client-side validation bypass"
        "Capture network traffic when accessing this dashboard"

    Chrome Infiltrator will use Playwright to control a real browser, execute
    JavaScript, intercept network traffic, and identify client-side vulnerabilities.
    """
    return chrome_infiltrator


def transfer_from_chrome_infiltrator():
    """Called when Chrome Infiltrator completes testing.

    Chrome Infiltrator will have provided:
    - XSS vulnerabilities detected
    - DOM security issues
    - Network traffic analysis
    - Cookie security assessment
    - Extracted API endpoints
    - Screenshots as evidence
    - Client-side secrets found

    Next steps:
    - Review browser automation results
    - Analyze discovered vulnerabilities
    - Transfer findings to other agents (T-1000 Hunter, Intel Reporter)
    - Proceed with backend testing based on discovered endpoints
    """
    return "Chrome Infiltrator testing complete. Review findings and proceed with next phase."
