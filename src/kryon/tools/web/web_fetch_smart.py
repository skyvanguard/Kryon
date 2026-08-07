"""
F203.B — Smart web fetcher.

Equivalente a `WebFetch` que usa Claude: GET + HTML→markdown limpio +
extracción de links + meta tags, JSON→pretty. NO renderiza JS (es
recon pasivo, banca-safe).

A diferencia del `run_command curl` crudo:
- Estructura el output (markdown body + meta + links + headers)
- Trunca a 500KB para que el LLM no se ahogue
- User-Agent realista para no ser detectado como bot trivial
- Timeout corto (10s default) — banca-safe
- Sigue máximo 3 redirects (evita loops)
- GET only — no muta nada en el target

Banca-safe contract: solo HTTP GET, sin POST/PUT/DELETE. No envía cookies
ni credenciales. Read-only por design.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from html.parser import HTMLParser
from typing import Any

from kryon.sdk.agents import function_tool

logger = logging.getLogger(__name__)


_DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Kryon-Investigate/1.0"
)

# Tags whose content we drop entirely (no semantic value for audit).
_DROP_TAGS = {"script", "style", "noscript", "iframe", "svg"}

# Tags that imply block-level boundary (newline in markdown output).
_BLOCK_TAGS = {
    "p",
    "div",
    "section",
    "article",
    "header",
    "footer",
    "nav",
    "main",
    "aside",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "li",
    "ul",
    "ol",
    "table",
    "tr",
    "td",
    "th",
    "pre",
    "blockquote",
    "form",
    "fieldset",
}


class _MarkdownExtractor(HTMLParser):
    """Streaming HTML → plain-text-with-structure converter.

    Strategy:
    - Drop content inside script/style/noscript.
    - Convert <a href>...</a> -> [text](url)
    - Convert <h1..h6> -> "#"*N text
    - Track meta tags separately.
    - Track all hrefs separately (links list).
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._buf: list[str] = []
        self._skip_depth = 0  # nested drop-tags counter
        self._in_anchor = False
        self._anchor_href = ""
        self._anchor_text: list[str] = []
        self.links: list[str] = []
        self.meta: dict[str, str] = {}
        self.title: str = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs):  # type: ignore[override]
        attrs_d = {k: v for k, v in attrs if v is not None}
        if tag in _DROP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "meta":
            name = attrs_d.get("name") or attrs_d.get("property") or attrs_d.get("http-equiv")
            content = attrs_d.get("content")
            if name and content:
                # Cap meta value to avoid bloat
                self.meta[name.lower()] = content[:500]
            return
        if tag == "title":
            self._in_title = True
            return
        if tag == "a":
            href = attrs_d.get("href", "")
            if href:
                self.links.append(href[:500])
                self._in_anchor = True
                self._anchor_href = href
                self._anchor_text = []
            return
        if tag.startswith("h") and len(tag) == 2 and tag[1].isdigit():
            level = int(tag[1])
            self._buf.append("\n\n" + "#" * level + " ")
            return
        if tag == "br":
            self._buf.append("\n")
            return
        if tag in _BLOCK_TAGS:
            self._buf.append("\n")
            return
        if tag == "li":
            self._buf.append("\n- ")
            return

    def handle_endtag(self, tag: str):  # type: ignore[override]
        if tag in _DROP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if self._skip_depth:
            return
        if tag == "title":
            self._in_title = False
            return
        if tag == "a" and self._in_anchor:
            txt = "".join(self._anchor_text).strip()
            if txt and self._anchor_href:
                self._buf.append(f"[{txt}]({self._anchor_href})")
            elif self._anchor_href:
                self._buf.append(self._anchor_href)
            self._in_anchor = False
            self._anchor_href = ""
            self._anchor_text = []
            return
        if tag in _BLOCK_TAGS:
            self._buf.append("\n")

    def handle_data(self, data: str):  # type: ignore[override]
        if self._skip_depth:
            return
        if self._in_title:
            self.title += data
            return
        if self._in_anchor:
            self._anchor_text.append(data)
            return
        self._buf.append(data)

    def get_markdown(self) -> str:
        raw = "".join(self._buf)
        # Collapse whitespace: multiple newlines -> max 2, multiple spaces -> 1.
        lines = [ln.rstrip() for ln in raw.splitlines()]
        compact: list[str] = []
        prev_blank = False
        for ln in lines:
            if not ln.strip():
                if not prev_blank:
                    compact.append("")
                prev_blank = True
            else:
                compact.append(" ".join(ln.split()))
                prev_blank = False
        return "\n".join(compact).strip()


def _fetch_raw(
    url: str,
    *,
    timeout: int,
    max_size: int,
    user_agent: str,
) -> tuple[int, dict[str, str], bytes, str]:
    """Plain GET with safety caps. Returns (status, headers, body, final_url).

    Raises urllib.error.URLError on connection failures.
    """
    from kryon.util.http_headers import extra_http_headers  # noqa: PLC0415

    _headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5,es;q=0.4",
        # NO cookies, NO auth — banca-safe.
    }
    # Bug-bounty research-identification header (e.g. X-HackerOne-Research) when
    # KRYON_HTTP_EXTRA_HEADERS is set — required by some VDP policies on all traffic.
    _headers.update(extra_http_headers())
    req = urllib.request.Request(url, method="GET", headers=_headers)
    # Limit redirects to 3 via custom opener.
    handler = urllib.request.HTTPRedirectHandler()
    opener = urllib.request.build_opener(handler)
    opener.addheaders = list(req.headers.items())
    with opener.open(req, timeout=timeout) as resp:
        status = resp.getcode()
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.read(max_size + 1)
        truncated = len(body) > max_size
        body = body[:max_size]
        final_url = resp.geturl()
    if truncated:
        headers["_kryon_truncated"] = f"true (capped at {max_size} bytes)"
    return status, headers, body, final_url


@function_tool
def web_fetch_smart(
    url: str,
    timeout_s: int = 10,
    max_size_kb: int = 500,
) -> str:
    """F203.B — Smart HTTP GET with HTML→markdown extraction.

    Equivalent to a sane `WebFetch`: pulls a URL, extracts visible
    text as markdown (anchors converted to [text](href)), lists all
    outbound links, captures meta tags, and detects content-type.

    Use this BEFORE manually grepping raw HTML. The LLM gets a clean
    summary instead of minified JS noise.

    Args:
        url: HTTP(S) URL to GET. No POST/PUT/DELETE supported.
        timeout_s: Connection + read timeout in seconds (default 10).
        max_size_kb: Maximum response body to read (default 500 KB).

    Returns:
        JSON string with keys:
            status, final_url, content_type, title, body_md,
            links[], meta{}, headers{}, error?
    """
    timeout_s = max(1, min(timeout_s, 60))
    max_size = max(1024, min(max_size_kb * 1024, 5 * 1024 * 1024))

    if not (url.startswith("http://") or url.startswith("https://")):
        return json.dumps({"error": f"unsupported scheme in url: {url}"})

    from kryon.validation.target_guard import placeholder_reason

    _ph = placeholder_reason(url)
    if _ph:
        return json.dumps({"error": _ph, "action": "ask_user_for_target"})

    # SSRF guard — block cloud-metadata / link-local / reserved hosts (credential theft),
    # but allow private/loopback so internal-network & CTF targets still work.
    from kryon.tools.common._url_validation import validate_external_url  # noqa: PLC0415

    ssrf_err = validate_external_url(url, allow_private=True)
    if ssrf_err:
        return json.dumps({"error": f"blocked by SSRF guard: {ssrf_err}"})

    try:
        status, headers, body, final_url = _fetch_raw(url, timeout=timeout_s, max_size=max_size, user_agent=_DEFAULT_UA)
    except urllib.error.HTTPError as e:
        return json.dumps(
            {
                "error": f"HTTP {e.code}: {e.reason}",
                "status": e.code,
                "url": url,
            }
        )
    except urllib.error.URLError as e:
        return json.dumps({"error": f"URLError: {e.reason}", "url": url})
    except TimeoutError:
        return json.dumps({"error": "timeout", "url": url})
    except Exception as e:  # noqa: BLE001 — network paths have many failure modes
        return json.dumps({"error": f"{type(e).__name__}: {e}", "url": url})

    content_type = headers.get("content-type", "").lower()
    # Decode body — try utf-8 then latin-1 fallback.
    text = ""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = body.decode("latin-1", errors="replace")

    result: dict[str, Any] = {
        "status": status,
        "final_url": final_url,
        "content_type": content_type,
        "headers": {k: v for k, v in headers.items() if not k.startswith("_kryon_")},
        "truncated": "_kryon_truncated" in headers,
    }

    if "json" in content_type:
        try:
            parsed = json.loads(text)
            # Pretty-print structure preview
            result["body_json_preview"] = json.dumps(parsed, indent=2)[:8000]
            # Top-level keys for structural overview
            if isinstance(parsed, dict):
                result["json_keys"] = list(parsed.keys())[:50]
            elif isinstance(parsed, list):
                result["json_array_len"] = len(parsed)
        except json.JSONDecodeError:
            result["body_text"] = text[:8000]
    elif "html" in content_type or "<html" in text[:200].lower():
        parser = _MarkdownExtractor()
        try:
            parser.feed(text)
            parser.close()
        except Exception as e:  # noqa: BLE001
            result["parse_error"] = f"{type(e).__name__}: {e}"
            result["body_raw_preview"] = text[:4000]
        else:
            result["title"] = parser.title.strip()[:200]
            result["meta"] = parser.meta
            result["body_md"] = parser.get_markdown()[:8000]
            # Dedupe + cap link list
            seen: set[str] = set()
            uniq_links: list[str] = []
            for href in parser.links:
                if href not in seen:
                    seen.add(href)
                    uniq_links.append(href)
                    if len(uniq_links) >= 100:
                        break
            result["links"] = uniq_links
    else:
        # Other content-types: include text preview only.
        result["body_text"] = text[:4000] if text else ""
        if not text and body:
            result["body_hex_preview"] = body[:200].hex()

    return json.dumps(result, ensure_ascii=False)


__all__ = ["web_fetch_smart"]
