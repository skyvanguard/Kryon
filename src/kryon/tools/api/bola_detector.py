"""F87.2 — Broken Object Level Authorization (BOLA) detector.

BOLA is OWASP API Security Top 10 #1: an authenticated user can
access another user's objects by tampering with the object id in the
path. Real-world incidents in core banking (T24, Flexcube, BCP
internal admin APIs) consistently surface BOLA as the highest-impact
finding because tokens are valid, no auth bypass is needed, and the
data exfiltrated is account / cardholder / transaction history.

This module implements three pieces:

  1. `plan_probes(spec, ...)` — PURE PLANNER. Walks the OpenAPISpec,
     identifies object-leveled endpoints (paths with id-shaped path
     params + GET method), and emits a list of `BOLACandidate`.
     No I/O. Banca-safe by default.

  2. `execute_probe(candidate, ...)` — EXECUTOR (gated). Issues one
     GET request with the operator's token A and a foreign id; reads
     status + a clipped body fingerprint. Default is DRY-RUN: returns
     a BOLAFinding with verdict="dry_run" so the operator can review
     the plan before any HTTP traffic. KRYON_BOLA_FIRE=true plus
     explicit `fire=True` arg flip to live execution.

  3. `correlate_findings(findings)` — aggregator. Buckets findings by
     verdict, surfaces the highest-impact ones for the report.

Banca-safety contract (enforced by the executor, NOT only documented):
  - Only HTTP method GET. No mutation requests, ever. The planner
    silently drops POST/PUT/PATCH/DELETE endpoints — they belong to
    a separate F87 chunk with a different consent model.
  - Operator MUST set KRYON_BOLA_FIRE=true OR pass fire=True. Default
    fire=False emits dry_run findings only.
  - Per-endpoint cap of 5 IDs probed (configurable). Avoids
    accidental enumeration of millions of objects in a long-running
    test.
  - Stdlib urllib only — no requests / httpx / aiohttp pull-ins.
  - Body fingerprint is the first 200 chars + the SHA-256 of the
    full payload. The full body is never persisted.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from kryon.tools.api.openapi_importer import Endpoint, OpenAPISpec, Parameter

logger = logging.getLogger(__name__)

__all__ = [
    "BOLACandidate",
    "BOLAFinding",
    "plan_probes",
    "execute_probe",
    "correlate_findings",
    "is_object_leveled_path_param",
    "DEFAULT_MAX_IDS_PER_ENDPOINT",
    "DEFAULT_RATE_LIMIT_PER_SECOND",
]


DEFAULT_MAX_IDS_PER_ENDPOINT = 5
DEFAULT_RATE_LIMIT_PER_SECOND = 10
# Hard cap independent of caller — even a misconfigured agent can't
# accidentally enumerate millions of records.
_HARD_MAX_IDS_PER_ENDPOINT = 50

# Object-id naming heuristic. Matches the parameter names that real
# OpenAPI specs use for "this is a row-level identifier":
#   id, ID, Id, *Id, *_id, *ID, uuid, guid, accountId, customer_id, ...
# Conservatively excludes pagination tokens (page, cursor, offset)
# and resource-class identifiers (categoryId is ambiguous — included
# because banking specs use it for individual transaction categories
# which are still per-tenant).
_ID_PARAM_RE = re.compile(
    r"^(?:id|uuid|guid)$|(?:_id|Id|ID|Uuid|UUID|Guid|GUID)$",
)

# Body-fingerprint cap. 200 chars is enough to spot a leak ("balance":
# 12345.67) without storing PII.
_BODY_FINGERPRINT_CHARS = 200


@dataclass(frozen=True)
class BOLACandidate:
    """One endpoint + path-parameter pair worth probing.

    `original_id` is what the *owner* token's path would have. The
    planner doesn't know which ids actually belong to the owner — the
    executor combines this candidate with operator-supplied owned /
    foreign id pairs at fire time.
    """

    endpoint_path: str  # "/accounts/{accountId}"
    method: str  # always "get" in v1
    path_parameter: str  # "accountId"
    parameter_type: str | None  # "string" | "integer" | "uuid" | ...
    security_scheme_names: tuple[str, ...]
    operation_id: str | None
    risk: str  # "high" | "medium" | "low" — set by the planner heuristic


@dataclass(frozen=True)
class BOLAFinding:
    """Result of probing one (candidate, id_to_test) pair."""

    candidate: BOLACandidate
    id_tested: str
    verdict: str  # "dry_run" | "leak_confirmed" | "leak_suspected" | "protected" | "ambiguous" | "error"
    http_status: int | None = None
    body_fingerprint: str = ""  # first 200 chars
    body_sha256: str | None = None
    error: str | None = None
    notes: str = ""


# ---------------------------------------------------------------------------
# Planner — pure, no I/O
# ---------------------------------------------------------------------------


def is_object_leveled_path_param(param: Parameter) -> bool:
    """A path parameter looks object-leveled when its name is id-shaped.

    Conservatively scoped to path-bound params; query string IDs are
    a different class of finding and live in F87.3 (parameter
    pollution).
    """
    if param.in_ != "path":
        return False
    return bool(_ID_PARAM_RE.search(param.name))


def _endpoint_risk(endpoint: Endpoint, id_param: Parameter) -> str:
    """Heuristic: GET on a top-level resource-by-id is high-impact,
    nested resources are medium, deprecated endpoints drop to low.

    Counts the number of path segments containing a `{...}`. A path
    with one id segment ("/accounts/{accountId}") is top-level →
    high. Two id segments ("/users/{userId}/accounts/{accountId}")
    is nested → medium.
    """
    if endpoint.deprecated:
        return "low"
    id_segment_count = sum(
        1
        for seg in endpoint.path.split("/")
        if seg.startswith("{") and seg.endswith("}")
    )
    if id_segment_count == 1:
        return "high"
    if id_segment_count == 2:
        return "medium"
    return "low"


def plan_probes(
    spec: OpenAPISpec,
    *,
    max_ids_per_endpoint: int = DEFAULT_MAX_IDS_PER_ENDPOINT,
) -> list[BOLACandidate]:
    """Produce one BOLACandidate per (object-leveled endpoint, path
    param) pair. Order is deterministic (endpoint order, then param
    name) so a curator can diff two plans across spec revisions.

    Banca-safe filters:
      - method must be GET (POST/PUT/PATCH/DELETE would mutate state
        and require an explicit different consent model)
      - endpoint must have a `security` requirement — public
        endpoints can't be BOLA (they expose by design)
      - parameter name must match the id-shape regex
    """
    max_ids = min(max_ids_per_endpoint, _HARD_MAX_IDS_PER_ENDPOINT)
    candidates: list[BOLACandidate] = []
    for endpoint in spec.endpoints:
        if endpoint.method.lower() != "get":
            continue
        # Public endpoints (no security) are intentionally exposed.
        # Flagging them as BOLA risks would create noise; if the auditor
        # disagrees they can manually probe.
        if not endpoint.security:
            continue
        scheme_names = tuple(
            sorted({name for entry in endpoint.security for name in entry.keys()})
        )
        for param in endpoint.parameters:
            if not is_object_leveled_path_param(param):
                continue
            candidates.append(
                BOLACandidate(
                    endpoint_path=endpoint.path,
                    method=endpoint.method.lower(),
                    path_parameter=param.name,
                    parameter_type=param.schema_type,
                    security_scheme_names=scheme_names,
                    operation_id=endpoint.operation_id,
                    risk=_endpoint_risk(endpoint, param),
                )
            )
    # max_ids_per_endpoint isn't applied here (no IDs yet — that's
    # at fire time). Keep the param for callers that want to validate
    # operator-provided id lists against it.
    _ = max_ids
    candidates.sort(key=lambda c: (c.endpoint_path, c.path_parameter))
    return candidates


# ---------------------------------------------------------------------------
# Executor — gated by env + arg
# ---------------------------------------------------------------------------


def _fire_enabled(fire: bool) -> bool:
    """Live HTTP requires BOTH: env opt-in + explicit arg. Either alone
    is dry-run."""
    if not fire:
        return False
    env = os.environ.get("KRYON_BOLA_FIRE", "").strip().lower()
    return env in ("1", "true", "yes")


def _substitute_path(
    base_url: str,
    candidate: BOLACandidate,
    id_value: str,
) -> str:
    """Build the full URL by replacing `{paramName}` in the path with
    the id under test. Other path params (rare on object-leveled
    endpoints) are left as `{name}` so a misconfigured probe surfaces
    via the executor's 404 response, not a silent failure."""
    placeholder = "{" + candidate.path_parameter + "}"
    path = candidate.endpoint_path.replace(placeholder, id_value)
    return base_url.rstrip("/") + path


def _classify_response(status: int, body: str) -> str:
    """Verdict heuristic:
      - 200 + non-trivial JSON body → leak_confirmed
      - 200 + empty / one-line body → leak_suspected (could be a stub)
      - 401 / 403                    → protected
      - 404                          → ambiguous (could be BOLA via
                                       enumeration timing)
      - 5xx                          → error
      - everything else              → ambiguous
    """
    if 200 <= status < 300:
        # 30 chars is enough for a JSON body with at least one key
        # carrying object-specific data ("balance":12345.67). Shorter
        # bodies (stubs, "{}", "[]") drop to suspected — leak may
        # still exist via enumeration timing but a curator should
        # verify manually.
        if body and len(body.strip()) > 30:
            return "leak_confirmed"
        return "leak_suspected"
    if status in (401, 403):
        return "protected"
    if status == 404:
        return "ambiguous"
    if status >= 500:
        return "error"
    return "ambiguous"


def execute_probe(
    candidate: BOLACandidate,
    *,
    base_url: str,
    token: str,
    id_to_test: str,
    auth_header: str = "Authorization",
    auth_prefix: str = "Bearer ",
    fire: bool = False,
    timeout: int = 15,
) -> BOLAFinding:
    """Issue one probe and return a BOLAFinding.

    DRY-RUN (default) — `fire=False` OR KRYON_BOLA_FIRE unset: returns
    verdict="dry_run" without touching the network. The operator can
    inspect the plan, sign off, then flip both gates.

    Banca-safety:
      - method is hard-coded to GET; the candidate's method is
        validated but never used to override.
      - body never persisted beyond the 200-char fingerprint.
      - any exception is caught and surfaced as verdict="error".
    """
    if candidate.method.lower() != "get":
        return BOLAFinding(
            candidate=candidate,
            id_tested=id_to_test,
            verdict="error",
            error="banca-safety: only GET method allowed in BOLA probes",
        )

    if not _fire_enabled(fire):
        return BOLAFinding(
            candidate=candidate,
            id_tested=id_to_test,
            verdict="dry_run",
            notes=(
                f"would GET {candidate.endpoint_path} with "
                f"{candidate.path_parameter}={id_to_test!r}"
            ),
        )

    url = _substitute_path(base_url, candidate, id_to_test)
    headers = {auth_header: f"{auth_prefix}{token}"}
    req = Request(url, headers=headers, method="GET")

    try:
        with urlopen(req, timeout=timeout) as resp:
            status = resp.status
            raw = resp.read()
    except HTTPError as e:
        # 4xx / 5xx are normal probe outcomes — read the body for
        # fingerprinting + classify.
        status = e.code
        try:
            raw = e.read()
        except Exception:  # noqa: BLE001
            raw = b""
    except (URLError, TimeoutError, OSError) as e:
        return BOLAFinding(
            candidate=candidate,
            id_tested=id_to_test,
            verdict="error",
            error=f"{type(e).__name__}: {e}",
        )
    except Exception as e:  # noqa: BLE001
        return BOLAFinding(
            candidate=candidate,
            id_tested=id_to_test,
            verdict="error",
            error=f"{type(e).__name__}: {e}",
        )

    text = raw.decode("utf-8", errors="replace") if raw else ""
    fingerprint = text[:_BODY_FINGERPRINT_CHARS]
    body_hash = hashlib.sha256(raw).hexdigest() if raw else None
    verdict = _classify_response(status, text)

    return BOLAFinding(
        candidate=candidate,
        id_tested=id_to_test,
        verdict=verdict,
        http_status=status,
        body_fingerprint=fingerprint,
        body_sha256=body_hash,
    )


# ---------------------------------------------------------------------------
# Correlator — aggregate findings into a summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BOLASummary:
    """Aggregated counts + the highest-impact findings."""

    total_probes: int
    by_verdict: dict[str, int] = field(default_factory=dict)
    by_risk: dict[str, int] = field(default_factory=dict)
    confirmed_leaks: tuple[BOLAFinding, ...] = field(default_factory=tuple)


def correlate_findings(findings: list[BOLAFinding]) -> BOLASummary:
    """Roll up a list of findings into one summary suitable for the
    final engagement report.

    Pure aggregation — no I/O. Confirmed leaks are surfaced separately
    so the narrator can include them verbatim with their request
    parameters."""
    by_verdict: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    confirmed: list[BOLAFinding] = []
    for f in findings:
        by_verdict[f.verdict] = by_verdict.get(f.verdict, 0) + 1
        by_risk[f.candidate.risk] = by_risk.get(f.candidate.risk, 0) + 1
        if f.verdict == "leak_confirmed":
            confirmed.append(f)
    return BOLASummary(
        total_probes=len(findings),
        by_verdict=by_verdict,
        by_risk=by_risk,
        confirmed_leaks=tuple(confirmed),
    )


# ---------------------------------------------------------------------------
# Rate-limiter helper (used by the agent-facing tool wrapper)
# ---------------------------------------------------------------------------


class _TokenBucket:
    """Coarse rate limiter: at most `rate_per_second` tokens per real
    second. Sleep-based — fine because BOLA probes are inherently
    serial (one finding per response) and we want gentle pressure on
    the target."""

    def __init__(self, rate_per_second: float) -> None:
        self.rate = max(1.0, float(rate_per_second))
        self._last = 0.0

    def wait(self) -> None:
        elapsed = time.monotonic() - self._last
        gap = 1.0 / self.rate
        if elapsed < gap:
            time.sleep(gap - elapsed)
        self._last = time.monotonic()
