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
"""

from kryon.agents.base import create_agent
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
chrome_infiltrator = create_agent(
    name="Chrome Infiltrator",
    description="""Protocol-Class automation system from KRYON's Alpha-Chrome series.
Specialized in dynamic web application testing, browser automation, and client-side
vulnerability detection. Chrome Infiltrator provides real browser execution capabilities
that static analysis tools cannot match.

Primary Mission: Dynamic web testing, JavaScript analysis, XSS detection.
Operational Focus: Browser automation and client-side security assessment.""",
    instructions=create_system_prompt_renderer(chrome_infiltrator_system_prompt),
    tools=browser_tools,
)


def transfer_to_chrome_infiltrator():
    """Transfer control to Chrome Infiltrator for browser automation and dynamic testing.

    Chrome Infiltrator will use Playwright to control a real browser, execute
    JavaScript, intercept network traffic, and identify client-side vulnerabilities.
    """
    return chrome_infiltrator


def transfer_from_chrome_infiltrator():
    """Called when Chrome Infiltrator completes testing."""
    return "Chrome Infiltrator testing complete. Review findings and proceed with next phase."
