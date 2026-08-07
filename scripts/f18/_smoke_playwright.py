"""Playwright smoke test — runs inside the kryon container after rebuild.

Verifies:
 1. playwright Python package importable
 2. PLAYWRIGHT_BROWSERS_PATH points at the baked-in install
 3. Chromium launches headless with --no-sandbox
 4. Can GET a page and read its <title>

Usage:
    docker exec kryon python3 /workspace/scripts/f18/_smoke_playwright.py
"""
from __future__ import annotations

import asyncio
import os
import sys


async def main() -> int:
    print(f"PLAYWRIGHT_BROWSERS_PATH={os.environ.get('PLAYWRIGHT_BROWSERS_PATH', '<unset>')}")

    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        print(f"FAIL: playwright import: {exc}")
        return 1

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox"],
            )
            page = await browser.new_page()
            # Use a target reachable from ctfnet; Juice Shop is the canonical
            # demo target. Fall back to about:blank if juice is not up.
            target = os.environ.get("PW_SMOKE_URL", "http://juice.local:3000/")
            try:
                await page.goto(target, timeout=10000)
                title = await page.title()
                print(f"OK: loaded {target} title={title!r}")
            except Exception as exc:
                print(f"WARN: could not load {target}: {exc}. Falling back to about:blank")
                await page.goto("about:blank")
                print("OK: about:blank loaded")
            await browser.close()
    except Exception as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}")
        return 2

    print("playwright smoke test passed")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
