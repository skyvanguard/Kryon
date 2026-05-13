"""F109 — Unified Web Audit Pipeline.

Single entry point that runs the F108 crawler + every applicable
F97-F107 analyzer in sequence, producing one flat finding list with
provenance.

Banca-safety: respects every downstream module's contract. Two
stages are opt-in (require explicit authorization for extra
network activity):

  * `run_disclosure`  — F101 issues additional HEAD/GET probes
                        against well-known paths NOT discovered by
                        the crawler (`.git/config`, `.env`, etc.).
                        Off by default.
  * `run_tls`         — F100 opens a separate TLS socket to capture
                        the cert chain + supported protocols.
                        Off by default.

The crawler itself runs at its banca-safe defaults; the caller can
override via the optional `crawler` field on `PipelineConfig`."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse

from kryon.tools.api.cms_fingerprint import (
    FingerprintObservation,
    analyze_fingerprint,
)
from kryon.tools.api.cookie_security import analyze_cookies
from kryon.tools.api.dom_xss import JsSnippet, analyze_dom_xss
from kryon.tools.api.info_disclosure import (
    DisclosureProbe,
    analyze_probes as analyze_disclosure_probes,
)
from kryon.tools.api.security_headers import (
    HTTPResponse,
    analyze_security_headers,
)
from kryon.tools.api.tls_audit import analyze_tls_profile
from kryon.tools.api.vuln_js_libs import (
    ScriptObservation,
    analyze_scripts,
)
from kryon.tools.crawler.crawler import Crawler, CrawlerConfig, CrawlResult
from kryon.tools.nuclei.runner import (
    NuclieConfig,
    is_nuclei_available,
    run_nuclei,
)
from kryon.tools.pipeline.tls_capture import capture_tls_profile

__all__ = [
    "PipelineConfig",
    "PipelineResult",
    "UnifiedFinding",
    "Pipeline",
    "run_pipeline",
]


# Minimal disclosure path set (banca-safe by default — operator can
# pass the full default_probe_paths() if `run_disclosure_full=True`).
_DISCLOSURE_MINIMAL_PATHS: tuple[str, ...] = (
    "/.git/config",
    "/.env",
    "/.env.production",
    "/robots.txt",
    "/server-status",
    "/phpinfo.php",
    "/swagger-ui.html",
    "/openapi.json",
    "/.aws/credentials",
    "/terraform.tfstate",
    "/wp-config.php.bak",
    "/actuator/env",
    "/actuator/heapdump",
    "/debug/pprof/",
)


@dataclass(frozen=True)
class PipelineConfig:
    """Configuration for one full-pipeline run."""

    seeds: tuple[str, ...]
    crawler: CrawlerConfig | None = None
    # Which analyzer stages to run (each defaults to ON for the pure-
    # static analyzers, OFF for stages that perform extra network IO).
    run_headers: bool = True       # F97
    run_cookies: bool = True       # F98
    run_cms: bool = True           # F104
    run_js_libs: bool = True       # F102
    run_dom_xss: bool = True       # F107
    run_disclosure: bool = False   # F101 — extra probes (banca opt-in)
    run_disclosure_full: bool = False  # full ~130-path scan (operator opt-in)
    disclosure_paths: tuple[str, ...] = ()  # explicit override; if empty + run_disclosure use minimal
    run_tls: bool = False          # F100 — opens TLS socket (banca opt-in)
    tls_timeout: float = 5.0
    run_nuclei: bool = False       # F110 — delegate to nuclei CLI (banca opt-in)
    nuclei_config: NuclieConfig | None = None  # if None + run_nuclei: build a banca-safe default


@dataclass(frozen=True)
class UnifiedFinding:
    """One finding normalized across every analyzer module."""

    rule_id: str
    severity: str
    title: str
    detail: str
    remediation: str
    source_module: str  # "F97" / "F98" / "F100" / "F101" / "F102" / "F104" / "F107"
    target: str = ""    # URL / host where it was found
    extra: tuple[tuple[str, str], ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class PipelineResult:
    crawl: CrawlResult
    findings: tuple[UnifiedFinding, ...] = field(default_factory=tuple)
    elapsed_seconds: float = 0.0
    stages_run: tuple[str, ...] = ()
    stages_skipped: tuple[str, ...] = ()


# ----- helpers --------------------------------------------------------------


def _headers_to_dict(headers: tuple[tuple[str, str], ...]) -> dict[str, str]:
    """Convert (name, value) pairs into a dict, merging duplicates
    with `, ` separators (RFC 9110 §5.3)."""
    out: dict[str, str] = {}
    for name, value in headers:
        if name in out:
            out[name] = out[name] + ", " + value
        else:
            out[name] = value
    return out


def _extract_set_cookie_strings(
    headers: tuple[tuple[str, str], ...],
) -> list[str]:
    return [v for k, v in headers if k.lower() == "set-cookie"]


def _is_html(content_type: str) -> bool:
    if not content_type:
        return False
    low = content_type.lower()
    return low.startswith("text/html") or low.startswith("application/xhtml")


def _is_js(content_type: str, url: str) -> bool:
    if content_type:
        low = content_type.lower()
        if "javascript" in low or "ecmascript" in low:
            return True
    return url.lower().endswith((".js", ".mjs"))


def _cookie_names_from_strings(set_cookies: list[str]) -> list[str]:
    """Light cookie-name parser (just the part before the first `=`)."""
    out: list[str] = []
    for raw in set_cookies:
        first_kv = raw.split(";", 1)[0]
        if "=" in first_kv:
            name = first_kv.split("=", 1)[0].strip()
            if name:
                out.append(name)
    return out


# ----- core pipeline --------------------------------------------------------


class Pipeline:
    def __init__(self, config: PipelineConfig) -> None:
        if not config.seeds:
            raise ValueError("PipelineConfig.seeds must be non-empty")
        self.config = config

    def _make_crawler_config(self) -> CrawlerConfig:
        if self.config.crawler is not None:
            return self.config.crawler
        return CrawlerConfig(seeds=self.config.seeds)

    def _analyze_headers(self, page) -> list[UnifiedFinding]:
        headers_dict = _headers_to_dict(page.headers)
        response = HTTPResponse(
            url=page.url,
            method="GET",
            is_https=page.url.startswith("https://"),
            headers=headers_dict,
        )
        analysis = analyze_security_headers(response)
        return [
            UnifiedFinding(
                rule_id=f.rule_id,
                severity=f.severity,
                title=f.title,
                detail=f.detail,
                remediation=f.remediation,
                source_module="F97",
                target=page.url,
            )
            for f in analysis.findings
        ]

    def _analyze_cookies(self, page) -> list[UnifiedFinding]:
        set_cookies = _extract_set_cookie_strings(page.headers)
        if not set_cookies:
            return []
        analysis = analyze_cookies(
            set_cookies, is_https=page.url.startswith("https://")
        )
        return [
            UnifiedFinding(
                rule_id=f.rule_id,
                severity=f.severity,
                title=f.title,
                detail=f.detail,
                remediation=f.remediation,
                source_module="F98",
                target=page.url,
            )
            for f in analysis.findings
        ]

    def _analyze_cms(self, page, crawl: CrawlResult) -> list[UnifiedFinding]:
        # Find metas captured by the crawler for THIS page
        metas: tuple[tuple[str, str], ...] = ()
        for url, pairs in crawl.meta_tags:
            if url == page.url:
                metas = pairs
                break
        set_cookies = _extract_set_cookie_strings(page.headers)
        cookie_names = tuple(_cookie_names_from_strings(set_cookies))
        obs = FingerprintObservation(
            url=page.url,
            headers=page.headers,
            body_snippet=page.body_snippet,
            cookie_names=cookie_names,
        )
        analysis = analyze_fingerprint(obs)
        return [
            UnifiedFinding(
                rule_id=f.rule_id,
                severity=f.severity,
                title=f.title,
                detail=f.detail,
                remediation=f.remediation,
                source_module="F104",
                target=page.url,
                extra=(
                    ("detected_tech", f.detected_tech),
                    ("detected_version", f.detected_version),
                ),
            )
            for f in analysis.findings
        ]

    def _analyze_js_libs(
        self, script_urls: Iterable[str]
    ) -> list[UnifiedFinding]:
        observations = [ScriptObservation(src=src) for src in script_urls]
        analysis = analyze_scripts(observations)
        return [
            UnifiedFinding(
                rule_id=f.rule_id,
                severity=f.severity,
                title=f.title,
                detail=f.detail,
                remediation=f.remediation,
                source_module="F102",
                target=f.script_src,
                extra=(
                    ("library", f.library),
                    ("detected_version", f.detected_version),
                    ("cve", f.cve),
                ),
            )
            for f in analysis.findings
        ]

    def _analyze_dom_xss(self, page) -> list[UnifiedFinding]:
        snippets = [JsSnippet(file_path=page.url, body=page.body_snippet)]
        analysis = analyze_dom_xss(snippets)
        return [
            UnifiedFinding(
                rule_id=f.rule_id,
                severity=f.severity,
                title=f.title,
                detail=f.detail,
                remediation=f.remediation,
                source_module="F107",
                target=f"{f.file_path}:{f.line}",
                extra=(("snippet", f.snippet),),
            )
            for f in analysis.findings
        ]

    def _disclosure_paths(self) -> tuple[str, ...]:
        if self.config.disclosure_paths:
            return self.config.disclosure_paths
        if self.config.run_disclosure_full:
            from kryon.tools.api.info_disclosure import default_probe_paths
            return tuple(default_probe_paths())
        return _DISCLOSURE_MINIMAL_PATHS

    def _run_disclosure_for_origin(
        self, origin: str
    ) -> list[UnifiedFinding]:
        """Spin up a side-crawler with seeds = origin + each disclosure
        path, depth 0, fetch_external_js=False. Lets us reuse all the
        crawler safety guards."""
        paths = self._disclosure_paths()
        seeds = tuple(origin.rstrip("/") + p for p in paths)
        # Inherit auth + rate from main crawler config if provided.
        base = self.config.crawler
        cfg = CrawlerConfig(
            seeds=seeds,
            max_pages=len(seeds) + 1,
            max_depth=0,
            max_concurrency=base.max_concurrency if base else 4,
            rate_limit_per_second=base.rate_limit_per_second if base else 5.0,
            per_request_timeout_seconds=base.per_request_timeout_seconds if base else 8.0,
            max_body_bytes=2000,  # probe body fingerprint only
            respect_robots=False,  # disclosure paths are deliberately not in robots
            same_origin_only=True,
            allowed_extra_hosts=tuple(),
            block_internal_ips=base.block_internal_ips if base else True,
            fetch_external_js=False,
            auth_cookies=base.auth_cookies if base else (),
            auth_headers=base.auth_headers if base else (),
            user_agent=(base.user_agent if base else "Kryon-Crawler/1.0 (banca-safe; +read-only)"),
        )
        crawl = Crawler(cfg).crawl()
        probes: list[DisclosureProbe] = []
        # Build path-keyed map
        for page in crawl.pages:
            parsed = urlparse(page.url)
            path = parsed.path or "/"
            probes.append(
                DisclosureProbe(
                    path=path,
                    http_status=page.http_status,
                    body_fingerprint=page.body_snippet[:200],
                )
            )
        # Errors from out-of-scope etc. become 0-status probes — irrelevant.
        analysis = analyze_disclosure_probes(probes)
        return [
            UnifiedFinding(
                rule_id=f.rule_id,
                severity=f.severity,
                title=f.title,
                detail=f.detail,
                remediation=f.remediation,
                source_module="F101",
                target=origin.rstrip("/") + f.path,
            )
            for f in analysis.findings
        ]

    def _run_nuclei_for_seeds(self) -> list[UnifiedFinding]:
        """Delegate breadth-of-coverage to nuclei. Returns empty list
        if binary not installed (no error — soft failure)."""
        cfg = self.config.nuclei_config or NuclieConfig(targets=self.config.seeds)
        result = run_nuclei(cfg)
        if result.nuclei_missing:
            return []
        out: list[UnifiedFinding] = []
        for f in result.findings:
            extra: list[tuple[str, str]] = [
                ("template_id", f.template_id),
                ("nuclei_severity", f.nuclei_severity),
            ]
            if f.cve_id:
                extra.append(("cve", f.cve_id))
            if f.cvss_score:
                extra.append(("cvss", f"{f.cvss_score:.1f}"))
            if f.tags:
                extra.append(("tags", ",".join(f.tags)))
            if f.reference:
                extra.append(("references", " | ".join(f.reference[:3])))
            out.append(
                UnifiedFinding(
                    rule_id=f"NUC:{f.template_id}",
                    severity=f.severity,
                    title=f.name or f.template_id,
                    detail=f.description or f.name or "",
                    remediation=(
                        "Review nuclei template + the matched-at URL. "
                        "Confirm exploitability before remediation."
                    ),
                    source_module="F110",
                    target=f.matched_at or f.target,
                    extra=tuple(extra),
                )
            )
        return out

    def _run_tls_for_host(self, host: str, port: int = 443) -> list[UnifiedFinding]:
        profile = capture_tls_profile(host, port, timeout=self.config.tls_timeout)
        if profile is None:
            return []
        analysis = analyze_tls_profile(profile)
        return [
            UnifiedFinding(
                rule_id=f.rule_id,
                severity=f.severity,
                title=f.title,
                detail=f.detail,
                remediation=f.remediation,
                source_module="F100",
                target=f"{host}:{port}",
            )
            for f in analysis.findings
        ]

    # ---- public entry point ------------------------------------------------

    def run(self) -> PipelineResult:
        t0 = time.monotonic()
        stages_run: list[str] = []
        stages_skipped: list[str] = []
        findings: list[UnifiedFinding] = []

        # ---- Stage 1: crawl ----
        crawler = Crawler(self._make_crawler_config())
        crawl = crawler.crawl()
        stages_run.append("crawl")

        # ---- Stage 2: per-page analyzers ----
        for page in crawl.pages:
            if _is_html(page.content_type):
                if self.config.run_headers:
                    findings.extend(self._analyze_headers(page))
                if self.config.run_cookies:
                    findings.extend(self._analyze_cookies(page))
                if self.config.run_cms:
                    findings.extend(self._analyze_cms(page, crawl))
            elif _is_js(page.content_type, page.url):
                if self.config.run_dom_xss:
                    findings.extend(self._analyze_dom_xss(page))
        if self.config.run_headers:
            stages_run.append("F97-headers")
        else:
            stages_skipped.append("F97-headers")
        if self.config.run_cookies:
            stages_run.append("F98-cookies")
        else:
            stages_skipped.append("F98-cookies")
        if self.config.run_cms:
            stages_run.append("F104-cms")
        else:
            stages_skipped.append("F104-cms")
        if self.config.run_dom_xss:
            stages_run.append("F107-dom-xss")
        else:
            stages_skipped.append("F107-dom-xss")

        # ---- Stage 3: JS libs (one batch over all script URLs) ----
        if self.config.run_js_libs and crawl.script_urls:
            findings.extend(self._analyze_js_libs(crawl.script_urls))
            stages_run.append("F102-js-libs")
        else:
            stages_skipped.append("F102-js-libs")

        # ---- Stage 4: F101 disclosure (opt-in) ----
        if self.config.run_disclosure:
            # One round per unique scheme://host[:port] of seeds.
            # Port matters — without it the side-crawl would target
            # the default port, not whatever the operator pointed at.
            origins: set[str] = set()
            for seed in self.config.seeds:
                parsed = urlparse(seed)
                if parsed.scheme and parsed.hostname:
                    netloc = parsed.hostname
                    if parsed.port:
                        netloc = f"{parsed.hostname}:{parsed.port}"
                    origins.add(f"{parsed.scheme}://{netloc}")
            for origin in origins:
                findings.extend(self._run_disclosure_for_origin(origin))
            stages_run.append("F101-disclosure")
        else:
            stages_skipped.append("F101-disclosure")

        # ---- Stage 5b: F110 Nuclei (opt-in) ----
        # Run BEFORE TLS so it can use any extra surface area
        # discovered without blocking on a TLS handshake.
        if self.config.run_nuclei:
            if is_nuclei_available(
                (self.config.nuclei_config.nuclei_binary
                 if self.config.nuclei_config else "nuclei")
            ):
                findings.extend(self._run_nuclei_for_seeds())
                stages_run.append("F110-nuclei")
            else:
                stages_skipped.append("F110-nuclei (binary-missing)")
        else:
            stages_skipped.append("F110-nuclei")

        # ---- Stage 5: F100 TLS (opt-in) ----
        if self.config.run_tls:
            hosts_seen: set[str] = set()
            for seed in self.config.seeds:
                parsed = urlparse(seed)
                if parsed.scheme == "https" and parsed.hostname:
                    port = parsed.port or 443
                    key = f"{parsed.hostname}:{port}"
                    if key not in hosts_seen:
                        hosts_seen.add(key)
                        findings.extend(
                            self._run_tls_for_host(parsed.hostname, port)
                        )
            stages_run.append("F100-tls")
        else:
            stages_skipped.append("F100-tls")

        # Sort: severity (CRITICAL→INFO), then module, then rule_id
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(
            key=lambda f: (
                severity_order.get(f.severity, 99),
                f.source_module,
                f.rule_id,
                f.target,
            )
        )
        return PipelineResult(
            crawl=crawl,
            findings=tuple(findings),
            elapsed_seconds=time.monotonic() - t0,
            stages_run=tuple(stages_run),
            stages_skipped=tuple(stages_skipped),
        )


def run_pipeline(config: PipelineConfig) -> PipelineResult:
    """Functional shortcut: configure + run in one call."""
    return Pipeline(config).run()
