r"""F171 — NVD CVE cache populator.

Pulls public CVE feeds from NVD and writes the IDs into the local
``cves.txt`` cache that :mod:`kryon.validation.cve_validator` reads
when ``KRYON_CVE_CACHE_REQUIRED=true``. With the cache populated,
hallucinated CVE IDs that pass the format check (correct year +
4-7 digit sequence) get rejected because they aren't real published
vulnerabilities.

Why this exists: F170 bench showed gpt-oss-20b emit ``CVE-2013-6235``
(JAMon JSP XSS) as a finding for OWASP Juice Shop. The CVE is real,
but JAMon is a Java profiling tool — completely inapplicable to a
Node.js target. Format validation alone passed it. Strict mode +
populated cache would still pass it (it IS a real CVE), so this
populator is *necessary but not sufficient*. It IS sufficient to
catch the pure fabrications R1 emitted in F150.B
(``CVE-2020-10445`` / ``CVE-2026-29608`` style invented IDs).

NVD feed strategy:
  * Use the legacy ``nvdcve-1.1-{YEAR}.json.gz`` per-year files (one
    HTTP GET per year, no API key, no pagination). The endpoint is
    flagged for sunset but still serves and is the cheapest way to
    populate the cache offline.
  * Fall back to NVD 2.0 API when the legacy feed is unavailable —
    404 (retired) OR 403/410 (NVD now actively blocks the legacy
    endpoint). The 2.0 endpoint paginates 2000 records per page —
    single year fits in ~15 pages. Requests are spaced to respect the
    public rate limit (5 req / 30 s ≈ 6 s apart); set ``NVD_API_KEY``
    to raise that to 50 req / 30 s (~0.7 s apart, much faster).

The module is pure-stdlib (``urllib``, ``gzip``, ``json``) — no extra
dependencies. Network errors fail loudly so the operator notices
instead of silently shipping a stale cache.

Usage from the CLI is wired up in ``kryon.cli.cve_cache_cmd``::

    kryon update-cve-cache --year 2025
    kryon update-cve-cache --years 2020-2026
    kryon update-cve-cache --all   # 1999..current_year+1
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kryon.validation.cve_validator import (
    _MIN_YEAR,
    _default_cache_path,
    is_valid_cve_format,
)

logger = logging.getLogger(__name__)

_LEGACY_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_API_PAGE_SIZE = 2000
# NVD 2.0 rejects pubStartDate/pubEndDate ranges wider than 120 days (404),
# so a full year must be walked in ≤120-day windows.
_NVD_API_MAX_WINDOW_DAYS = 120

# HTTP codes that mean "the legacy feed is not available to us" → fall back
# to the 2.0 API. 404 = retired; 403 = NVD actively blocks the endpoint
# (current behaviour, 2026); 410 = gone.
_LEGACY_UNAVAILABLE_CODES = frozenset({403, 404, 410})

# NVD public rate limit is 5 requests / rolling 30 s; an API key raises it to
# 50 / 30 s. Space paginated API requests so we don't get 403/429-throttled.
_NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()
_NVD_API_DELAY_S = 0.7 if _NVD_API_KEY else 6.5

_USER_AGENT = "Kryon-CVE-Cache-Updater/1.0 (banca-safe)"


@dataclass(frozen=True)
class UpdateResult:
    """Summary of one ``update_cache`` invocation."""

    years_attempted: tuple[int, ...]
    years_succeeded: tuple[int, ...]
    cve_count_before: int
    cve_count_after: int
    cve_count_added: int
    cache_path: Path
    errors: tuple[str, ...]

    def summary(self) -> str:
        parts = [
            f"cache: {self.cache_path}",
            f"years requested: {len(self.years_attempted)} ({min(self.years_attempted)}..{max(self.years_attempted)})",
            f"years succeeded: {len(self.years_succeeded)}",
            f"CVEs before: {self.cve_count_before}",
            f"CVEs after:  {self.cve_count_after}",
            f"CVEs added:  {self.cve_count_added}",
        ]
        if self.errors:
            parts.append(f"errors:      {len(self.errors)}")
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Fetchers
# ---------------------------------------------------------------------------


def _http_get(url: str, *, timeout: int = 60, extra_headers: dict | None = None) -> bytes:
    headers = {"User-Agent": _USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - trusted URL
        return resp.read()


def fetch_year_legacy_feed(year: int, *, timeout: int = 60) -> set[str]:
    """Download ``nvdcve-1.1-{year}.json.gz`` and return the CVE IDs in it.

    Raises ``urllib.error.HTTPError`` / ``URLError`` on network failure.
    The caller decides whether to retry or fall back.
    """
    url = _LEGACY_FEED_URL.format(year=year)
    logger.info("fetching NVD legacy feed for %d: %s", year, url)
    raw = _http_get(url, timeout=timeout)
    with gzip.open(io.BytesIO(raw), "rt", encoding="utf-8") as fh:
        doc = json.load(fh)
    return _extract_ids_from_legacy(doc)


def _extract_ids_from_legacy(doc: dict) -> set[str]:
    """Extract CVE IDs from a parsed legacy NVD JSON 1.1 feed."""
    cve_items = doc.get("CVE_Items") or []
    ids: set[str] = set()
    for item in cve_items:
        try:
            cid = item["cve"]["CVE_data_meta"]["ID"]
        except (KeyError, TypeError):
            continue
        if isinstance(cid, str) and is_valid_cve_format(cid):
            ids.add(cid.upper())
    return ids


def _nvd_ts(dt: datetime) -> str:
    """Format a datetime as the millisecond ISO-8601 stamp NVD 2.0 expects."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_year_api_v2(year: int, *, timeout: int = 60, delay: float = _NVD_API_DELAY_S) -> set[str]:
    """Fallback: pull a single year via the NVD 2.0 REST API.

    NVD 2.0 rejects any ``pubStartDate``/``pubEndDate`` span wider than 120
    days with a 404, so the year is walked in ≤120-day windows; each window
    is paginated 2000 records per page. Requests are spaced by ``delay``
    seconds to stay under the rate limit, and send the ``apiKey`` header
    when ``NVD_API_KEY`` is set (raises the limit 10×).
    """
    headers = {"apiKey": _NVD_API_KEY} if _NVD_API_KEY else None
    ids: set[str] = set()
    window_start = datetime(year, 1, 1, tzinfo=timezone.utc)
    year_end = datetime(year, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    first_request = True
    while window_start <= year_end:
        window_end = min(window_start + timedelta(days=_NVD_API_MAX_WINDOW_DAYS - 1), year_end)
        start_index = 0
        while True:
            if not first_request and delay > 0:
                time.sleep(delay)  # respect NVD rate limit between requests
            first_request = False
            url = (
                f"{_NVD_API_URL}?pubStartDate={_nvd_ts(window_start)}"
                f"&pubEndDate={_nvd_ts(window_end)}"
                f"&resultsPerPage={_NVD_API_PAGE_SIZE}&startIndex={start_index}"
            )
            logger.info(
                "fetching NVD 2.0 API for %d [%s..%s] startIndex=%d",
                year,
                window_start.date(),
                window_end.date(),
                start_index,
            )
            raw = _http_get(url, timeout=timeout, extra_headers=headers)
            doc = json.loads(raw.decode("utf-8"))
            for vuln in doc.get("vulnerabilities", []):
                cid = vuln.get("cve", {}).get("id", "")
                if isinstance(cid, str) and is_valid_cve_format(cid):
                    ids.add(cid.upper())
            total = int(doc.get("totalResults") or 0)
            start_index += _NVD_API_PAGE_SIZE
            if start_index >= total:
                break
        window_start = window_end + timedelta(seconds=1)
    return ids


def fetch_year(year: int, *, timeout: int = 60) -> set[str]:
    """Fetch one year, preferring the legacy feed and falling back to
    the 2.0 API when the legacy feed is unavailable (403/404/410).
    """
    try:
        return fetch_year_legacy_feed(year, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code in _LEGACY_UNAVAILABLE_CODES:
            logger.info(
                "legacy feed for %d returned %d; falling back to NVD 2.0 API",
                year,
                exc.code,
            )
            return fetch_year_api_v2(year, timeout=timeout)
        raise


# ---------------------------------------------------------------------------
# Cache file I/O
# ---------------------------------------------------------------------------


def _read_existing(path: Path) -> set[str]:
    if not path.exists():
        return set()
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if is_valid_cve_format(line):
            out.add(line.upper())
    return out


def _write_cache(path: Path, ids: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sorted_ids = sorted(ids, key=_sort_key)
    header = [
        "# Generated by kryon update-cve-cache",
        f"# {datetime.now(timezone.utc).isoformat()}",
        f"# count: {len(sorted_ids)}",
        "",
    ]
    path.write_text("\n".join(header + sorted_ids) + "\n", encoding="utf-8")


_SORT_RE = re.compile(r"^CVE-(\d+)-(\d+)$", re.IGNORECASE)


def _sort_key(cve_id: str) -> tuple[int, int]:
    m = _SORT_RE.match(cve_id)
    if not m:
        return (0, 0)
    return (int(m.group(1)), int(m.group(2)))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def resolve_years(*, year: int | None, years_range: str | None, all_years: bool) -> list[int]:
    """Resolve operator flags into a list of years to fetch."""
    if all_years:
        return list(range(_MIN_YEAR, _current_year() + 2))
    if years_range:
        start, _, end = years_range.partition("-")
        a = int(start.strip())
        b = int((end or start).strip())
        if a > b:
            a, b = b, a
        return list(range(a, b + 1))
    if year is not None:
        return [year]
    return [_current_year()]


def _current_year() -> int:
    return datetime.now(timezone.utc).year


def update_cache(
    years: list[int],
    *,
    cache_path: Path | None = None,
    fetcher=fetch_year,
    timeout: int = 60,
) -> UpdateResult:
    """Fetch the given years, merge with the existing cache, and write
    the result. ``fetcher`` is injectable so tests don't need a network.
    """
    path = cache_path or _default_cache_path()
    existing = _read_existing(path)
    before = len(existing)

    merged = set(existing)
    succeeded: list[int] = []
    errors: list[str] = []
    for y in years:
        try:
            new_ids = fetcher(y, timeout=timeout)
        except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{y}: {type(exc).__name__}: {exc}")
            continue
        merged.update(new_ids)
        succeeded.append(y)

    _write_cache(path, merged)
    after = len(merged)
    return UpdateResult(
        years_attempted=tuple(years),
        years_succeeded=tuple(succeeded),
        cve_count_before=before,
        cve_count_after=after,
        cve_count_added=after - before,
        cache_path=path,
        errors=tuple(errors),
    )
