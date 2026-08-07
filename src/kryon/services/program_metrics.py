"""Program-level security metrics — the XBOW shift from finding-COUNT to
VALIDATED-EXPLOITABLE.

When the pipeline finds a lot, "how many findings" becomes noise. The signal is a
funnel that narrows to what actually matters:

  Candidatos  → everything discovered
  Validados   → a detector CONFIRMED it (verification_level confirmed/
                judge-confirmed, not flagged for review) — ground truth
  Explotables → of the validated, those whose CWE reaches IMPACT (rce / db /
                account / admin / …) via the attack-path model — a proven path
                to impact, not just a real-but-inert finding (an info-leak or a
                cookie flag is validated but NOT exploitable)
  Mitigados   → remediated

The Validados→Explotables split is the XBOW distinction: a confirmed CWE-1004
cookie flag is validated but never exploitable; a confirmed CWE-89 SQLi is both.

Pure: the caller supplies already-parsed finding dicts (severity /
verification_level / needs_verification / status / cwe). No I/O, fully testable.
"""

from __future__ import annotations

from collections import Counter

from kryon.intelligence.attack_path import cwe_reaches_impact

_SEVERITIES = ("critical", "high", "medium", "low", "info")
# Verification bands shown to the client. "judge-confirmed" (a finding-judge
# promotion) is a distinct, model-adjudicated band — kept separate so it is never
# silently conflated with a re-probed "confirmed".
_VLEVELS = ("confirmed", "judge-confirmed", "heuristic", "inferred")
# Levels that count as VALIDATED (ground truth for the funnel).
_VALIDATED_LEVELS = frozenset({"confirmed", "judge-confirmed"})
_STATUSES = ("open", "remediated", "accepted", "false_positive")


def _norm_sev(value: object) -> str:
    v = str(value or "info").lower()
    for s in _SEVERITIES:
        if v.startswith(s[:4]):
            return s
    return "info"


def _norm_vlevel(value: object) -> str:
    # Fail-CLOSED: a malformed/unknown level → the LOWEST band ("inferred"), not
    # the highest, so broken metadata never inflates the "explotables" headline.
    # (An ABSENT level is defaulted to "confirmed" by the caller, matching the
    # Finding dataclass default; this only guards unexpected VALUES.)
    v = str(value or "confirmed").lower()
    return v if v in _VLEVELS else "inferred"


def compute_program_metrics(records: list[dict]) -> dict:
    """Compute the program funnel + validated-exploitable view.

    Each record is a dict with (all optional except by convention):
      - ``severity``: critical/high/medium/low/info
      - ``verification_level``: confirmed/judge-confirmed/heuristic/inferred
      - ``needs_verification``: bool
      - ``status``: open/remediated/accepted/false_positive
      - ``cwe``: e.g. "CWE-89" — used to classify exploitability
    """
    total = len(records)
    sev: Counter[str] = Counter()
    vlevel: Counter[str] = Counter()
    status: Counter[str] = Counter()
    validated = 0
    exploitable = 0
    needs_verif = 0

    for r in records:
        sev[_norm_sev(r.get("severity"))] += 1
        vl = _norm_vlevel(r.get("verification_level", "confirmed"))
        vlevel[vl] += 1
        status[str(r.get("status", "open")).lower()] += 1
        nv = bool(r.get("needs_verification", False))
        if nv:
            needs_verif += 1
        is_validated = vl in _VALIDATED_LEVELS and not nv
        if is_validated:
            validated += 1
            # Validated-exploitable: the CWE reaches an IMPACT capability. This
            # is the XBOW headline — a proven path to impact, not just a
            # confirmed-but-inert finding.
            if cwe_reaches_impact(r.get("cwe", "")):
                exploitable += 1

    remediated = status.get("remediated", 0)
    open_count = status.get("open", 0)
    # Fix-verification proxy: of the findings that reached a terminal
    # open/remediated decision, how many are remediated. (A dedicated retest
    # loop refines this; this is the store-derived approximation.)
    decided = open_count + remediated
    fix_rate = round(remediated / decided, 3) if decided else 0.0

    # Headline rate: of everything found, how much is proven EXPLOITABLE — the
    # ratio that separates signal from noise.
    exploitable_rate = round(exploitable / total, 3) if total else 0.0
    validated_rate = round(validated / total, 3) if total else 0.0

    return {
        "total": total,
        "by_severity": {s: sev.get(s, 0) for s in _SEVERITIES},
        # JSON-key uses underscore for judge-confirmed so the dashboard reads it cleanly.
        "by_verification": {
            "confirmed": vlevel.get("confirmed", 0),
            "judge_confirmed": vlevel.get("judge-confirmed", 0),
            "heuristic": vlevel.get("heuristic", 0),
            "inferred": vlevel.get("inferred", 0),
        },
        "validated": validated,
        "validated_exploitable": exploitable,
        # Headline % tracks the EXPLOITABLE ratio (matches the headline count).
        "validated_rate": exploitable_rate,
        "validated_ground_truth_rate": validated_rate,
        "needs_verification": needs_verif,
        "by_status": {s: status.get(s, 0) for s in _STATUSES},
        "fix_verification_rate": fix_rate,
        # The funnel the client sees: each stage narrows toward proven impact.
        "funnel": [
            {"stage": "Candidatos", "count": total},
            {"stage": "Validados", "count": validated},
            {"stage": "Explotables (path a impacto)", "count": exploitable},
            {"stage": "Mitigados", "count": remediated},
        ],
    }
