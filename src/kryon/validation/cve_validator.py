r"""F151 — CVE ID validator (anti-hallucination).

LLMs like R1 invent plausible-looking CVE IDs as ``rule_id`` values
when forced to emit JSON findings (we saw ``CVE-2020-10445`` and
``CVE-2021-44228`` from R1 against Juice Shop — both fabricated).
This module gives the parser a hard gate: a finding whose ``rule_id``
matches the CVE shape but fails validation is **dropped** outright,
not merely flagged.

Validation layers (best → cheapest):

  1. **Format**: regex ``^CVE-(\d{4})-(\d{4,7})$``. Year must be in
     the plausible window 1999..current_year+1.
  2. **Local NVD cache** (optional): ``.kryon/nvd_cache/cves.txt`` —
     one CVE ID per line. If the file exists, we check membership.
     Missing cache → format check only (don't reject silently for
     lack of data).

Env:
  - ``KRYON_CVE_VALIDATE``    default ``true``. Set to ``false`` to
    disable the gate entirely (research / testing).
  - ``KRYON_CVE_CACHE_PATH``  default ``.kryon/nvd_cache/cves.txt``.
  - ``KRYON_CVE_CACHE_REQUIRED``  default ``false``. When ``true``,
    a finding's CVE must be in the local cache; otherwise dropped.

Pure module — no network calls. The cache is populated externally
(``kryon update-cve-cache`` will land in a follow-up; for now the
operator places the file manually).
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,7})$", re.IGNORECASE)

# CVE program started in 1999; we accept current year + 1 to handle
# pre-disclosed CVEs published just before year rollover.
_MIN_YEAR = 1999


def _current_year() -> int:
    return datetime.now(timezone.utc).year


def is_valid_cve_format(value: str) -> bool:
    """Return True iff ``value`` is a syntactically valid CVE ID with
    a plausible year. Case-insensitive on the ``CVE-`` prefix.

    Examples (valid):   CVE-2021-44228, CVE-1999-0001, cve-2024-12345
    Examples (invalid): CVE-2099-1, CVE-1990-1234, CVE-X-Y, not-a-cve
    """
    if not value or not isinstance(value, str):
        return False
    m = _CVE_RE.match(value.strip())
    if not m:
        return False
    year = int(m.group(1))
    if year < _MIN_YEAR or year > _current_year() + 1:
        return False
    return True


def _env_true(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _default_cache_path() -> Path:
    # Home-anchored (NOT cwd-relative): the updater and the validator import
    # this same function, so a cwd-relative default meant populating the cache
    # from one directory and reading it from another silently missed. Matches
    # the documented ~/.kryon/nvd_cache/cves.txt and the rest of ~/.kryon/*.
    root = os.environ.get("KRYON_CVE_CACHE_PATH", "").strip()
    if root:
        return Path(root)
    return Path.home() / ".kryon" / "nvd_cache" / "cves.txt"


@lru_cache(maxsize=1)
def _load_cache(path_str: str) -> frozenset[str]:
    """Read the cache file once. Lines are stripped, uppercased, and
    membership-checked as a frozenset. Comments (``# ...``) ignored."""
    p = Path(path_str)
    if not p.exists():
        return frozenset()
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        logger.debug("CVE cache read failed: %s", exc)
        return frozenset()
    cves: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cves.add(line.upper())
    return frozenset(cves)


def cve_in_local_cache(cve_id: str, *, cache_path: Path | None = None) -> bool:
    """True iff ``cve_id`` is in the local NVD cache file. Empty
    cache (file missing) returns False — caller decides whether that
    counts as a soft pass."""
    if not cve_id:
        return False
    path = cache_path or _default_cache_path()
    return cve_id.strip().upper() in _load_cache(str(path))


def is_valid_cve_id(cve_id: str, *, cache_path: Path | None = None) -> bool:
    """Full validity check. Format is always enforced. Local-cache
    enforcement is opt-in via ``KRYON_CVE_CACHE_REQUIRED=true``."""
    if not is_valid_cve_format(cve_id):
        return False
    if _env_true("KRYON_CVE_CACHE_REQUIRED"):
        return cve_in_local_cache(cve_id, cache_path=cache_path)
    return True


def validate_finding_cve(finding: dict | object) -> tuple[bool, str]:
    """Inspect a finding-shaped object/dict. Returns ``(ok, reason)``.

    ``ok=False`` only when the finding's ``rule_id`` LOOKS like a CVE
    (matches the prefix) but fails validation. Findings whose rule_id
    isn't CVE-shaped pass unconditionally — this gate is CVE-specific.

    When the global ``KRYON_CVE_VALIDATE=false`` env is set, every
    finding passes (escape hatch for research).
    """
    if not _env_true("KRYON_CVE_VALIDATE", default="true"):
        return True, "validation disabled via env"

    rule_id = ""
    if isinstance(finding, dict):
        rule_id = str(finding.get("rule_id", "") or "")
    else:
        rule_id = str(getattr(finding, "rule_id", "") or "")

    rule_id = rule_id.strip()
    if not rule_id:
        return True, "no rule_id to validate"

    # If it doesn't look like a CVE at all, this gate doesn't apply.
    if not rule_id.upper().startswith("CVE-"):
        return True, "rule_id is not CVE-shaped; gate does not apply"

    if not is_valid_cve_format(rule_id):
        return False, f"rule_id '{rule_id}' is CVE-shaped but format/year invalid"

    if _env_true("KRYON_CVE_CACHE_REQUIRED"):
        if not cve_in_local_cache(rule_id):
            return False, f"rule_id '{rule_id}' not in local NVD cache (KRYON_CVE_CACHE_REQUIRED=true)"

    return True, "CVE valid"
