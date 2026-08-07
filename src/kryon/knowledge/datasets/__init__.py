"""F84.6 — CISA ICS Advisories dataset loader.

Loads the CISA ICS Advisory Project CSV (ODbL v1.0) and exposes a typed,
hashable view suitable for correlating banner-detected OT vendor/product
strings with vigent CVEs.

Storage layout:
  - Repo seed:   src/kryon/knowledge/datasets/cisa_ics_advisories_seed.csv
                 (~110 KB, ~166 advisories for the current year — banca
                 air-gap fallback so the loader works without network).
  - Operator full: $KRYON_HOME/datasets/cisa_ics_advisories.csv
                 (defaults to ~/.kryon/datasets/...). Refresh via
                 scripts/update_cisa_advisories.sh which pulls the Master
                 CSV from icsadvprj/ICS-Advisory-Project (~2.8 MB).

Loader prefers the operator full file when present; falls back to the
repo seed otherwise. This means CI and ephemeral containers always have
*something* to query, while production deployments with periodic refresh
get the full historical corpus.

Attribution:
  "Contains information from the ICS Advisory Project, licensed under
   the Open Database License (ODbL) v1.0."

  See NOTICE in repo root for the long-form attribution.
"""

from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from pathlib import Path

__all__ = [
    "Advisory",
    "load_cisa_advisories",
    "advisories_by_vendor",
    "DEFAULT_SEED_PATH",
    "OPERATOR_FULL_PATH",
]

DEFAULT_SEED_PATH: Path = Path(__file__).resolve().parent / "cisa_ics_advisories_seed.csv"


def _resolve_operator_full_path() -> Path:
    """The full ICS-Advisory-Project Master CSV, refreshed by
    scripts/update_cisa_advisories.sh. KRYON_HOME defaults to
    ~/.kryon — overridable for testing and Docker bind mounts."""
    kryon_home = os.environ.get("KRYON_HOME") or str(Path.home() / ".kryon")
    return Path(kryon_home) / "datasets" / "cisa_ics_advisories.csv"


OPERATOR_FULL_PATH: Path = _resolve_operator_full_path()


@dataclass(frozen=True)
class Advisory:
    """A single CISA ICS Advisory row, normalized.

    Hashable + frozen so it can live in sets, dict keys, and lru_cache
    return values. CVE / CWE / sector tuples are immutable on purpose —
    callers that want a list can `list(adv.cves)`.
    """

    advisory_id: str  # "ICSA-26-132-01"
    title: str
    vendor: str
    product: str
    products_affected: str
    cves: tuple[str, ...]
    cvss_v3: float | None
    severity: str  # "Low" | "Medium" | "High" | "Critical" | ""
    cwes: tuple[str, ...]
    sectors: tuple[str, ...]
    published: date | None
    last_updated: date | None
    headquarters: str


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_CWE_RE = re.compile(r"CWE-\d+")


def _parse_date(raw: str) -> date | None:
    """Source uses U.S. M/D/YYYY (e.g. "5/12/2026"). Return None on
    blanks or malformed values rather than raising — the loader must
    not abort on a single bad row in a 2.8 MB CSV."""
    raw = raw.strip()
    if not raw:
        return None
    try:
        month, day, year = (int(p) for p in raw.split("/"))
        return date(year, month, day)
    except (ValueError, AttributeError):
        return None


def _parse_cvss(raw: str) -> float | None:
    raw = raw.strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def _split_multivalued(raw: str, pattern: re.Pattern[str]) -> tuple[str, ...]:
    """CVE / CWE columns are comma-separated; sector column is
    semicolon-separated. We use regex extraction so noise (extra spaces,
    trailing punctuation, free-text like "and others") doesn't corrupt
    the tuple."""
    if not raw:
        return ()
    return tuple(dict.fromkeys(pattern.findall(raw)))  # preserve order, dedupe


def _split_sectors(raw: str) -> tuple[str, ...]:
    if not raw:
        return ()
    parts = [s.strip() for s in re.split(r"[;,]", raw)]
    return tuple(p for p in parts if p)


def _row_to_advisory(row: dict[str, str]) -> Advisory | None:
    """Defensive parser — returns None for rows missing mandatory keys."""
    advisory_id = row.get("ICS-CERT_Number", "").strip()
    if not advisory_id:
        return None
    return Advisory(
        advisory_id=advisory_id,
        title=row.get("ICS-CERT_Advisory_Title", "").strip(),
        vendor=row.get("Vendor", "").strip(),
        product=row.get("Product", "").strip(),
        products_affected=row.get("Products_Affected", "").strip(),
        cves=_split_multivalued(row.get("CVE_Number", ""), _CVE_RE),
        cvss_v3=_parse_cvss(row.get("Cumulative_CVSS", "")),
        severity=row.get("CVSS_Severity", "").strip(),
        cwes=_split_multivalued(row.get("CWE_Number", ""), _CWE_RE),
        sectors=_split_sectors(row.get("Critical_Infrastructure_Sector", "")),
        published=_parse_date(row.get("Original_Release_Date", "")),
        last_updated=_parse_date(row.get("Last_Updated", "")),
        headquarters=row.get("Company_Headquarters", "").strip(),
    )


@lru_cache(maxsize=4)
def load_cisa_advisories(path: Path | None = None) -> tuple[Advisory, ...]:
    """Load CISA ICS advisories from the CSV at `path`. If None, prefers
    OPERATOR_FULL_PATH (full Master, when refreshed) and falls back to
    DEFAULT_SEED_PATH (banca air-gap fallback, current-year subset).

    Cached: callers can hammer this without re-parsing the CSV.
    """
    if path is None:
        path = OPERATOR_FULL_PATH if OPERATOR_FULL_PATH.is_file() else DEFAULT_SEED_PATH

    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        advisories = tuple(adv for row in reader if (adv := _row_to_advisory(row)) is not None)

    return advisories


def advisories_by_vendor(
    vendor: str,
    path: Path | None = None,
) -> tuple[Advisory, ...]:
    """Return advisories whose vendor field matches `vendor`
    case-insensitively. Vendor strings in the source CSV are
    inconsistent — "Siemens" vs "Siemens AG" vs "Siemens Industry Inc."
    — so we use substring containment in either direction to be lenient.
    """
    target = vendor.strip().lower()
    if not target:
        return ()
    advisories = load_cisa_advisories(path)
    return tuple(adv for adv in advisories if target in adv.vendor.lower() or adv.vendor.lower() in target)
