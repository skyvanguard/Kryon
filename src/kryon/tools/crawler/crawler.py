"""F108 — same-origin BFS crawler with banca-safety contract.

Design choices:

  - **Sync + threading**, NOT async. The rest of the toolkit is sync;
    we get concurrency from a ThreadPoolExecutor. Keeps debugging
    sane and matches the F97-F107 patterns.
  - **Same-origin only by default.** No off-site fetches unless the
    operator explicitly extends `allowed_hosts`.
  - **Internal-IP / loopback / link-local block by default**. Acts as
    an internal SSRF guard so the crawler never reaches into the
    operator's intranet.
  - **GET / HEAD only.** Form submission is descriptive (extracted +
    reported) — NOT executed.
  - **Rate-limited.** Token-bucket per host. Default 5 req/s.
  - **Bounded.** max_pages, max_depth, max_body_bytes all enforced.
  - **HTML + JS only.** PDFs, images, fonts: we record they exist but
    do not parse them.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import requests
from requests.adapters import HTTPAdapter

from kryon.tools.crawler.extractors import (
    ExtractedForm,
    extract_endpoints_from_js,
    extract_forms_from_html,
    extract_links_from_html,
    extract_meta_tags_from_html,
    extract_script_srcs_from_html,
)

__all__ = [
    "CrawlerConfig",
    "Crawler",
    "CrawledPage",
    "DiscoveredEndpoint",
    "DiscoveredForm",
    "CrawlError",
    "CrawlResult",
]


@dataclass(frozen=True)
class CrawlerConfig:
    """Bounded configuration. All limits are hard caps."""

    seeds: tuple[str, ...]
    user_agent: str = "Kryon-Crawler/1.0 (banca-safe; +read-only)"
    max_pages: int = 200
    max_depth: int = 5
    max_concurrency: int = 4
    max_body_bytes: int = 100_000
    per_request_timeout_seconds: float = 8.0
    rate_limit_per_second: float = 5.0
    respect_robots: bool = True
    same_origin_only: bool = True
    # Extra hosts allowed beyond the seed origins (e.g. CDN, asset host).
    allowed_extra_hosts: tuple[str, ...] = ()
    # Block reach to internal / loopback / link-local IPs even when the
    # operator explicitly adds an internal host. Default: True.
    block_internal_ips: bool = True
    # Crawl external JS bundle bodies to extract endpoints. Default: True.
    fetch_external_js: bool = True
    # Cookies passed in for authenticated crawl (operator-supplied).
    auth_cookies: tuple[tuple[str, str], ...] = ()
    auth_headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class CrawledPage:
    url: str
    http_status: int
    content_type: str
    headers: tuple[tuple[str, str], ...] = ()
    body_snippet: str = ""  # truncated at max_body_bytes
    body_length: int = 0
    depth: int = 0
    fetched_at: float = 0.0


@dataclass(frozen=True)
class DiscoveredEndpoint:
    """A URL discovered during the crawl. NOT necessarily fetched —
    just observed."""

    url: str
    source: str  # "html-a" / "html-script" / "html-form" / "js-fetch" / ...
    source_page: str = ""  # URL that referenced this endpoint
    method: str = "GET"
    parameters: tuple[str, ...] = ()


@dataclass(frozen=True)
class DiscoveredForm:
    """Reformulated ExtractedForm with provenance."""

    action: str
    method: str
    fields: tuple[tuple[str, str], ...] = ()  # (name, type) tuples
    source_page: str = ""


@dataclass(frozen=True)
class CrawlError:
    url: str
    reason: str
    detail: str = ""


@dataclass(frozen=True)
class CrawlResult:
    pages: tuple[CrawledPage, ...] = field(default_factory=tuple)
    endpoints: tuple[DiscoveredEndpoint, ...] = field(default_factory=tuple)
    forms: tuple[DiscoveredForm, ...] = field(default_factory=tuple)
    script_urls: tuple[str, ...] = field(default_factory=tuple)
    # meta_tags is a tuple of (page_url, tuple of (name, content) tuples).
    meta_tags: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = field(default_factory=tuple)
    errors: tuple[CrawlError, ...] = field(default_factory=tuple)
    elapsed_seconds: float = 0.0


# ----- internal helpers -----------------------------------------------------


def _host_of(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower()


def _origin_of(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme.lower()}://{(parsed.hostname or '').lower()}"


def _is_html_response(content_type: str) -> bool:
    if not content_type:
        return False
    return content_type.lower().startswith("text/html") or content_type.lower().startswith(
        "application/xhtml"
    )


def _is_js_response(content_type: str, url: str) -> bool:
    if content_type and (
        "javascript" in content_type.lower() or "ecmascript" in content_type.lower()
    ):
        return True
    return url.lower().endswith((".js", ".mjs"))


def _resolves_to_internal(hostname: str) -> bool:
    """Resolve hostname → IP → check if private/loopback/link-local.

    Returns True for hostnames we should refuse to fetch. Best-effort —
    returns False on resolution failure (we'd rather let the request
    fail naturally than be paranoid)."""
    if not hostname:
        return False
    # Literal IP shortcut
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except ValueError:
        pass
    try:
        for info in socket.getaddrinfo(hostname, None):
            ip_str = info[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                    return True
            except ValueError:
                continue
    except (socket.gaierror, OSError):
        # Resolution failed — let the actual fetch handle the error
        return False
    return False


class _TokenBucket:
    """Trivial thread-safe token bucket for per-host rate limiting."""

    def __init__(self, rate_per_second: float) -> None:
        self._rate = max(0.1, rate_per_second)
        self._tokens = self._rate
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
            self._last = now
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self._rate
                time.sleep(wait)
                # After sleeping, we've conceptually accrued the 1 token
                # we needed; consume it and reset the clock so the NEXT
                # request also waits its full quantum.
                self._tokens = 0.0
                self._last = time.monotonic()
            else:
                self._tokens -= 1.0


# ----- main Crawler ---------------------------------------------------------


class Crawler:
    """BFS same-origin crawler with banca-safety guard rails."""

    def __init__(self, config: CrawlerConfig) -> None:
        if not config.seeds:
            raise ValueError("CrawlerConfig.seeds must be non-empty")
        self.config = config
        self._allowed_origins: set[str] = {_origin_of(s) for s in config.seeds}
        # Also allow the bare hostnames of seeds + extras for matching
        self._allowed_hosts: set[str] = {_host_of(s) for s in config.seeds}
        self._allowed_hosts.update(h.lower() for h in config.allowed_extra_hosts)
        self._buckets: dict[str, _TokenBucket] = {}
        self._buckets_lock = threading.Lock()
        self._robots: dict[str, RobotFileParser | None] = {}
        self._robots_lock = threading.Lock()
        self._session = self._build_session()
        # Visited-URL set guarded by lock so the dispatcher and workers
        # share it.
        self._visited: set[str] = set()
        self._visited_lock = threading.Lock()

    def _build_session(self) -> requests.Session:
        sess = requests.Session()
        sess.headers["User-Agent"] = self.config.user_agent
        for name, value in self.config.auth_headers:
            sess.headers[name] = value
        for name, value in self.config.auth_cookies:
            sess.cookies.set(name, value)
        adapter = HTTPAdapter(
            pool_connections=self.config.max_concurrency,
            pool_maxsize=self.config.max_concurrency,
            max_retries=0,
        )
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        return sess

    # ----- scope decisions ---------------------------------------------------

    def _in_scope(self, url: str) -> tuple[bool, str]:
        """Return (in_scope, reason_if_not)."""
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            return False, f"scheme '{scheme}' not allowed"
        host = (parsed.hostname or "").lower()
        if not host:
            return False, "missing hostname"
        if self.config.same_origin_only:
            if host not in self._allowed_hosts:
                return False, f"off-scope host {host!r}"
        if self.config.block_internal_ips and _resolves_to_internal(host):
            return False, f"host {host!r} resolves to internal/loopback IP"
        return True, ""

    def _robots_for(self, url: str) -> RobotFileParser | None:
        if not self.config.respect_robots:
            return None
        origin = _origin_of(url)
        with self._robots_lock:
            if origin in self._robots:
                return self._robots[origin]
            rp = RobotFileParser()
            rp.set_url(origin + "/robots.txt")
            try:
                rp.read()
            except Exception:
                # If robots.txt can't be fetched, treat as permissive
                rp = None
            self._robots[origin] = rp
            return rp

    def _allowed_by_robots(self, url: str) -> bool:
        rp = self._robots_for(url)
        if rp is None:
            return True
        try:
            return rp.can_fetch(self.config.user_agent, url)
        except Exception:
            return True

    def _bucket_for(self, host: str) -> _TokenBucket:
        with self._buckets_lock:
            bucket = self._buckets.get(host)
            if bucket is None:
                bucket = _TokenBucket(self.config.rate_limit_per_second)
                self._buckets[host] = bucket
            return bucket

    # ----- fetching ----------------------------------------------------------

    def _fetch(self, url: str) -> tuple[requests.Response | None, str]:
        """Returns (response_or_None, error_reason). Rate-limits + handles
        errors uniformly."""
        host = _host_of(url)
        self._bucket_for(host).acquire()
        try:
            resp = self._session.get(
                url,
                timeout=self.config.per_request_timeout_seconds,
                allow_redirects=True,
                stream=True,
            )
            # Read at most max_body_bytes to enforce body cap
            content = resp.raw.read(
                self.config.max_body_bytes + 1, decode_content=True
            )
            # Stash the content on the response so caller sees a clean
            # `.text` / `.content`. We can't reassign resp.content
            # cleanly, so attach a custom attribute.
            resp._kryon_capped_content = content[: self.config.max_body_bytes]  # type: ignore[attr-defined]
            return resp, ""
        except requests.exceptions.SSLError as e:
            return None, f"ssl-error: {e}"
        except requests.exceptions.Timeout:
            return None, "timeout"
        except requests.exceptions.ConnectionError as e:
            return None, f"connection-error: {e}"
        except requests.exceptions.RequestException as e:
            return None, f"request-error: {e}"

    # ----- crawl loop --------------------------------------------------------

    def crawl(self) -> CrawlResult:
        start = time.monotonic()
        pages: list[CrawledPage] = []
        endpoints: list[DiscoveredEndpoint] = []
        endpoints_seen: set[tuple[str, str, str]] = set()
        forms: list[DiscoveredForm] = []
        script_urls: list[str] = []
        script_urls_seen: set[str] = set()
        meta_tags: list[tuple[str, tuple[str, str], ...]] = []
        errors: list[CrawlError] = []

        # BFS queue of (url, depth, parent_url)
        queue: deque[tuple[str, int, str]] = deque(
            (s, 0, "") for s in self.config.seeds
        )

        def _enqueue_if_new(target: str, depth: int, parent: str) -> None:
            with self._visited_lock:
                if target in self._visited:
                    return
                if len(self._visited) >= self.config.max_pages:
                    return
                self._visited.add(target)
            queue.append((target, depth, parent))

        def _record_endpoint(
            url: str, source: str, source_page: str
        ) -> None:
            key = (url, source, source_page)
            if key in endpoints_seen:
                return
            endpoints_seen.add(key)
            endpoints.append(
                DiscoveredEndpoint(
                    url=url, source=source, source_page=source_page
                )
            )

        # Seed the visited set
        with self._visited_lock:
            for seed in self.config.seeds:
                self._visited.add(seed)

        # ThreadPool — we dispatch up to max_concurrency in flight
        with ThreadPoolExecutor(max_workers=self.config.max_concurrency) as pool:
            while queue and len(pages) < self.config.max_pages:
                batch: list[tuple[str, int, str]] = []
                while queue and len(batch) < self.config.max_concurrency:
                    batch.append(queue.popleft())

                future_map: dict[Future, tuple[str, int, str]] = {}
                for url, depth, parent in batch:
                    in_scope, reason = self._in_scope(url)
                    if not in_scope:
                        errors.append(
                            CrawlError(url=url, reason="out-of-scope", detail=reason)
                        )
                        continue
                    if not self._allowed_by_robots(url):
                        errors.append(
                            CrawlError(url=url, reason="robots-blocked")
                        )
                        continue
                    fut = pool.submit(self._fetch, url)
                    future_map[fut] = (url, depth, parent)

                for fut, (url, depth, parent) in future_map.items():
                    resp, err = fut.result()
                    if resp is None:
                        errors.append(CrawlError(url=url, reason=err))
                        continue
                    content_type = resp.headers.get("Content-Type", "")
                    raw_body: bytes = getattr(resp, "_kryon_capped_content", b"")
                    body_str: str = ""
                    if _is_html_response(content_type) or _is_js_response(
                        content_type, url
                    ):
                        try:
                            body_str = raw_body.decode(
                                resp.encoding or "utf-8", errors="replace"
                            )
                        except Exception:
                            body_str = raw_body.decode("utf-8", errors="replace")
                    pages.append(
                        CrawledPage(
                            url=url,
                            http_status=resp.status_code,
                            content_type=content_type,
                            headers=tuple(resp.headers.items()),
                            body_snippet=body_str,
                            body_length=len(raw_body),
                            depth=depth,
                            fetched_at=time.time(),
                        )
                    )

                    # Only extract links if HTML + 2xx
                    if (
                        not _is_html_response(content_type)
                        or not (200 <= resp.status_code < 300)
                        or not body_str
                    ):
                        # Still extract endpoints from JS bundles
                        if (
                            _is_js_response(content_type, url)
                            and 200 <= resp.status_code < 300
                            and body_str
                        ):
                            for ep_url in extract_endpoints_from_js(body_str, url):
                                _record_endpoint(ep_url, "js-extract", url)
                        continue

                    # HTML body — full extraction pass
                    links = extract_links_from_html(body_str, url)
                    for link in links:
                        _record_endpoint(
                            link.url, f"html-{link.source_tag}", url
                        )
                        # Enqueue navigational links + iframes
                        if link.source_tag in ("a", "iframe") and depth + 1 <= self.config.max_depth:
                            in_scope, _ = self._in_scope(link.url)
                            if in_scope:
                                _enqueue_if_new(link.url, depth + 1, url)

                    # External script URLs — enqueue if we plan to fetch them
                    for src in extract_script_srcs_from_html(body_str, url):
                        if src not in script_urls_seen:
                            script_urls_seen.add(src)
                            script_urls.append(src)
                        if (
                            self.config.fetch_external_js
                            and depth + 1 <= self.config.max_depth
                        ):
                            in_scope, _ = self._in_scope(src)
                            if in_scope:
                                _enqueue_if_new(src, depth + 1, url)

                    # Forms
                    for form in extract_forms_from_html(body_str, url):
                        forms.append(
                            DiscoveredForm(
                                action=form.action,
                                method=form.method,
                                fields=tuple((f.name, f.field_type) for f in form.fields),
                                source_page=url,
                            )
                        )
                        _record_endpoint(form.action, "html-form", url)

                    # Meta tags
                    metas = extract_meta_tags_from_html(body_str)
                    if metas:
                        meta_tags.append(
                            (url, tuple((k, v) for k, v in metas.items()))
                        )

        return CrawlResult(
            pages=tuple(pages),
            endpoints=tuple(endpoints),
            forms=tuple(forms),
            script_urls=tuple(script_urls),
            meta_tags=tuple(meta_tags),
            errors=tuple(errors),
            elapsed_seconds=time.monotonic() - start,
        )
