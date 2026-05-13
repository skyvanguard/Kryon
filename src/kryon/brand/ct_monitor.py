"""F90.2 — Certificate Transparency monitor.

Every CA-issued SSL/TLS certificate is logged to the public CT
ecosystem (Google Argon/Xenon, Cloudflare Nimbus, Let's Encrypt
Oak, Sectigo Sabre, …). For brand protection that's a continuous
stream of cheap intelligence: an attacker setting up
`login.bcp-secure.com` with a Let's Encrypt cert leaves a public
trace minutes after issuance.

This module queries the **crt.sh** aggregator (a public front-end
to Sectigo's CT log monitor) for certificates matching a brand
keyword, then classifies each entry against the bank's legitimate
domain whitelist + suspicious-TLD heuristics.

Why crt.sh:
  - Free, public, no API key required.
  - JSON output via `?output=json`.
  - Indexes every major log; we don't need to plumb the binary
    RFC 6962 protocol ourselves.
  - Single-call query model fits the F90 banca-safe contract (no
    persistent subscription).

Banca-safety:
  - Same double-gate as F90.1: KRYON_BRAND_FIRE=true env +
    fire=True kwarg. Default DRY-RUN returns an empty result.
  - Read-only HTTPS GET. 2 MB response cap.
  - Rate limiter: 1 query per second to be a polite client of a
    free public service.
  - Stdlib urllib only.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


__all__ = [
    "CTCertificate",
    "CTQueryResult",
    "CTRiskAssessment",
    "query_crtsh",
    "classify_cert",
    "filter_recent",
    "DEFAULT_RESPONSE_CAP_BYTES",
    "DEFAULT_MAX_CERTS",
    "SUSPICIOUS_TLDS",
]


DEFAULT_RESPONSE_CAP_BYTES = 2 * 1024 * 1024  # 2 MB
DEFAULT_MAX_CERTS = 200
_CRTSH_BASE_URL = "https://crt.sh/"

# TLDs that legitimate banking infrastructure essentially never uses.
# A cert for a brand-keyword domain on one of these is a strong
# phishing signal. The list is conservative — adding more TLDs here
# trades false-positive noise for catch rate.
SUSPICIOUS_TLDS = frozenset(
    {
        "click",
        "top",
        "xyz",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "buzz",
        "review",
        "country",
        "stream",
        "men",
        "loan",
        "win",
        "racing",
        "online",
        "site",
    }
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CTCertificate:
    """One certificate observed in a CT log."""

    cert_id: str  # crt.sh internal id (used to fetch the full PEM later)
    common_name: str
    san_names: tuple[str, ...]  # all SAN entries (DNS, IPAddress, …)
    issuer_name: str
    not_before: str  # ISO-8601 UTC
    not_after: str
    entry_timestamp: str  # when crt.sh ingested it (proxy for "fresh")
    serial_number: str = ""


@dataclass(frozen=True)
class CTQueryResult:
    """The full outcome of one CT query."""

    keyword: str
    verdict: str  # "ok" | "dry_run" | "rate_limited" | "error"
    certificates: tuple[CTCertificate, ...] = field(default_factory=tuple)
    error: str | None = None
    notes: str = ""


@dataclass(frozen=True)
class CTRiskAssessment:
    """Risk classification for one certificate."""

    cert: CTCertificate
    risk: str  # "low" | "medium" | "high"
    matched_brand: bool
    matched_legitimate: bool
    matched_suspicious_tld: bool
    matched_recent: bool
    reason: str


# ---------------------------------------------------------------------------
# Fire gate + rate limiter
# ---------------------------------------------------------------------------


def _fire_enabled(fire: bool) -> bool:
    if not fire:
        return False
    return os.environ.get("KRYON_BRAND_FIRE", "").strip().lower() in ("1", "true", "yes")


# Module-level last-query timestamp for the polite-client rate limit.
_last_query_at: float = 0.0
_MIN_QUERY_INTERVAL_S = 1.0


def _wait_for_rate_limit() -> None:
    """Sleep enough that we issue ≤ 1 query/second against crt.sh.
    Stateful across calls — the operator running back-to-back keyword
    queries gets a 1s gap between each."""
    global _last_query_at
    elapsed = time.monotonic() - _last_query_at
    if elapsed < _MIN_QUERY_INTERVAL_S:
        time.sleep(_MIN_QUERY_INTERVAL_S - elapsed)
    _last_query_at = time.monotonic()


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _parse_certificates(payload: list[dict]) -> tuple[CTCertificate, ...]:
    """Parse crt.sh's JSON array into CTCertificate tuple.

    crt.sh fields used:
      id, common_name, name_value (newline-separated SANs),
      issuer_name, not_before, not_after, entry_timestamp,
      serial_number.

    Defensive: missing fields collapse to empty string; non-list
    payload returns empty tuple. We don't raise — the caller already
    knows the query succeeded structurally."""
    if not isinstance(payload, list):
        return ()
    out: list[CTCertificate] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        san_raw = entry.get("name_value") or ""
        if isinstance(san_raw, str):
            # crt.sh joins SANs with \n. Strip + dedupe + lower-case.
            san_set: set[str] = set()
            for line in san_raw.split("\n"):
                cleaned = line.strip().lower()
                if cleaned:
                    san_set.add(cleaned)
            san_tuple = tuple(sorted(san_set))
        else:
            san_tuple = ()

        out.append(
            CTCertificate(
                cert_id=str(entry.get("id") or ""),
                common_name=str(entry.get("common_name") or "").lower(),
                san_names=san_tuple,
                issuer_name=str(entry.get("issuer_name") or ""),
                not_before=str(entry.get("not_before") or ""),
                not_after=str(entry.get("not_after") or ""),
                entry_timestamp=str(entry.get("entry_timestamp") or ""),
                serial_number=str(entry.get("serial_number") or ""),
            )
        )
    return tuple(out)


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------


def query_crtsh(
    keyword: str,
    *,
    fire: bool = False,
    max_certs: int = DEFAULT_MAX_CERTS,
    exclude_expired: bool = True,
    timeout: int = 30,
    cap_bytes: int = DEFAULT_RESPONSE_CAP_BYTES,
) -> CTQueryResult:
    """Query crt.sh for certificates matching `keyword`.

    DRY-RUN (default) → returns CTQueryResult(verdict="dry_run")
    with empty certificates. Live fetch requires
    KRYON_BRAND_FIRE=true env AND fire=True kwarg.

    `max_certs` caps the parsed result (crt.sh sometimes returns
    100k+ rows for a popular keyword — we sort by entry_timestamp
    descending and keep the top N).
    """
    if not keyword.strip():
        return CTQueryResult(
            keyword=keyword,
            verdict="error",
            error="empty keyword",
        )

    if not _fire_enabled(fire):
        return CTQueryResult(
            keyword=keyword,
            verdict="dry_run",
            notes=f"would query crt.sh for {keyword!r}",
        )

    _wait_for_rate_limit()

    params = {"q": f"%{keyword}%", "output": "json"}
    if exclude_expired:
        params["exclude"] = "expired"
    url = _CRTSH_BASE_URL + "?" + urllib.parse.urlencode(params)
    req = Request(url, headers={"Accept": "application/json"}, method="GET")

    try:
        with urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read(cap_bytes)
    except HTTPError as e:
        # crt.sh returns 429 when over-loaded; tag distinctly so the
        # operator knows to back off vs investigate a real error.
        if e.code == 429:
            return CTQueryResult(
                keyword=keyword,
                verdict="rate_limited",
                error="crt.sh returned HTTP 429",
            )
        return CTQueryResult(
            keyword=keyword,
            verdict="error",
            error=f"HTTP {e.code}: {e.reason}",
        )
    except (URLError, TimeoutError, OSError) as e:
        return CTQueryResult(
            keyword=keyword,
            verdict="error",
            error=f"{type(e).__name__}: {e}",
        )
    except Exception as e:  # noqa: BLE001
        return CTQueryResult(
            keyword=keyword,
            verdict="error",
            error=f"{type(e).__name__}: {e}",
        )

    if status != 200:
        return CTQueryResult(
            keyword=keyword,
            verdict="error",
            error=f"unexpected HTTP {status}",
        )

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return CTQueryResult(
            keyword=keyword,
            verdict="error",
            error=f"invalid JSON: {e}",
        )

    certs = _parse_certificates(payload)
    # Sort by entry_timestamp descending; keep top max_certs.
    sorted_certs = tuple(
        sorted(certs, key=lambda c: c.entry_timestamp, reverse=True)
    )[:max_certs]
    return CTQueryResult(
        keyword=keyword,
        verdict="ok",
        certificates=sorted_certs,
    )


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _matches_brand(cert: CTCertificate, brand_keyword: str) -> bool:
    kw = brand_keyword.strip().lower()
    if not kw:
        return False
    if kw in cert.common_name:
        return True
    return any(kw in san for san in cert.san_names)


def _matches_legitimate(cert: CTCertificate, legitimate_domains: tuple[str, ...]) -> bool:
    """A cert is legitimate when EVERY identifier (CN + SANs) is
    covered by the bank's whitelist. A cert covering both legitimate
    and unknown SANs is NOT legitimate — attackers can request a
    cert for `bcp.com.py + login-bcp-secure.com` if the CA validates
    only the first SAN; we surface that.

    Empty legitimate_domains list → no match (we don't have a
    whitelist to assess against)."""
    if not legitimate_domains:
        return False
    legit = {d.strip().lower() for d in legitimate_domains}
    identifiers: set[str] = set()
    if cert.common_name:
        identifiers.add(cert.common_name)
    identifiers.update(cert.san_names)
    if not identifiers:
        return False

    def _is_covered(name: str) -> bool:
        # Strip leading wildcard label for matching.
        stripped = name[2:] if name.startswith("*.") else name
        # Direct match OR ends-with-dot-legit (subdomain of a
        # whitelisted root).
        return stripped in legit or any(stripped.endswith("." + d) for d in legit)

    return all(_is_covered(n) for n in identifiers)


def _matches_suspicious_tld(cert: CTCertificate) -> bool:
    """Any identifier on a suspicious TLD lights this up."""
    identifiers: list[str] = []
    if cert.common_name:
        identifiers.append(cert.common_name)
    identifiers.extend(cert.san_names)
    for name in identifiers:
        if "." not in name:
            continue
        tld = name.rsplit(".", 1)[-1].lower()
        if tld in SUSPICIOUS_TLDS:
            return True
    return False


def _matches_recent(cert: CTCertificate, max_age_days: int) -> bool:
    """True when entry_timestamp is within max_age_days of now (UTC).

    Returns False for malformed / missing timestamps — better to
    under-flag than over-flag based on bad metadata."""
    ts_raw = cert.entry_timestamp
    if not ts_raw:
        return False
    # crt.sh format: "2026-05-10T12:34:56.789" (no timezone suffix —
    # always UTC). Trim sub-second fraction for parsing.
    ts_clean = re.sub(r"\.\d+$", "", ts_raw)
    try:
        ts = datetime.fromisoformat(ts_clean).replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    age = datetime.now(timezone.utc) - ts
    return age.total_seconds() <= max_age_days * 86400


def classify_cert(
    cert: CTCertificate,
    brand_keyword: str,
    *,
    legitimate_domains: tuple[str, ...] = (),
    recency_days: int = 30,
) -> CTRiskAssessment:
    """Classify one cert. Decision tree:

      1. brand keyword NOT in any identifier → low (incidental hit
         on the substring query).
      2. all identifiers on the legitimate whitelist → low (it's
         the bank's own cert).
      3. brand match AND suspicious TLD → high.
      4. brand match AND recent issuance AND not on legitimate list
         → high (cert just appeared, not whitelisted).
      5. brand match AND recent → medium (suspicious but on a
         normal TLD; could be a customer subdomain that
         legitimate_domains missed).
      6. brand match older → medium (worth a manual look).
    """
    matched_brand = _matches_brand(cert, brand_keyword)
    matched_legitimate = _matches_legitimate(cert, legitimate_domains)
    matched_suspicious = _matches_suspicious_tld(cert)
    matched_recent = _matches_recent(cert, recency_days)

    if not matched_brand:
        return CTRiskAssessment(
            cert=cert,
            risk="low",
            matched_brand=False,
            matched_legitimate=matched_legitimate,
            matched_suspicious_tld=matched_suspicious,
            matched_recent=matched_recent,
            reason="brand keyword not in any identifier — incidental match",
        )

    if matched_legitimate:
        return CTRiskAssessment(
            cert=cert,
            risk="low",
            matched_brand=True,
            matched_legitimate=True,
            matched_suspicious_tld=matched_suspicious,
            matched_recent=matched_recent,
            reason="all identifiers covered by the legitimate-domains whitelist",
        )

    if matched_suspicious:
        return CTRiskAssessment(
            cert=cert,
            risk="high",
            matched_brand=True,
            matched_legitimate=False,
            matched_suspicious_tld=True,
            matched_recent=matched_recent,
            reason="brand-matching cert on suspicious TLD",
        )

    if matched_recent:
        return CTRiskAssessment(
            cert=cert,
            risk="high",
            matched_brand=True,
            matched_legitimate=False,
            matched_suspicious_tld=False,
            matched_recent=True,
            reason="brand-matching cert recently issued and not whitelisted",
        )

    return CTRiskAssessment(
        cert=cert,
        risk="medium",
        matched_brand=True,
        matched_legitimate=False,
        matched_suspicious_tld=False,
        matched_recent=False,
        reason="brand-matching cert older than the recency window — worth a manual look",
    )


def filter_recent(
    certs: list[CTCertificate] | tuple[CTCertificate, ...],
    *,
    max_age_days: int = 7,
) -> tuple[CTCertificate, ...]:
    """Convenience filter for the operator: return only the certs
    issued in the last `max_age_days`. Useful for daily / weekly
    digests."""
    return tuple(c for c in certs if _matches_recent(c, max_age_days))
