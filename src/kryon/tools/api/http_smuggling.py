"""F105 — HTTP Request Smuggling Probe Analyzer.

Static analyzer for HTTP Request Smuggling. The operator submits
crafted payloads (CL.TE / TE.CL / TE.TE / TE.0) using a low-level
HTTP socket — and captures the response (status code, timing, body
fingerprint, second-response fragment if any). This module
INTERPRETS those captured responses without performing any live
attack itself.

Banca safety: smuggling tests can break upstream proxies. NEVER
send the actual smuggling payloads from inside Kryon — operator
runs them under explicit written authorization in a dedicated test
window.

Stable rule IDs:

  SMG-001  CL.TE desync confirmed (Content-Length + Transfer-Encoding both
           accepted; front-end uses CL, back-end uses TE) — CRITICAL
  SMG-002  TE.CL desync confirmed (front-end TE, back-end CL) — CRITICAL
  SMG-003  TE.TE desync via header obfuscation — HIGH
  SMG-004  TE.0 desync (HTTP/2 → HTTP/1.1 downgrade smuggling) — CRITICAL
  SMG-005  Server accepts both CL + TE on same request (RFC violation) — HIGH
  SMG-006  Timing-based detection: probe with 'Transfer-Encoding: chunked'
           caused 5+s delay → likely TE-vulnerable backend behind CL frontend — MEDIUM
  SMG-007  HTTP/2 to HTTP/1.1 downgrade ambiguity — HIGH
  SMG-008  Suspicious response body fragmentation observed across probes — LOW

Probe shapes the operator should submit are documented in the
`smuggling-probes` playbook (skill F89 sibling). This module just
classifies the captured outcomes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "SmugglingProbe",
    "SmugglingFinding",
    "SmugglingAnalysis",
    "analyze_probes",
    "ALL_SMG_RULES",
]


ALL_SMG_RULES: frozenset[str] = frozenset({f"SMG-{n:03d}" for n in range(1, 9)})


# Probe-type identifiers the operator tags each probe with.
_KNOWN_PROBE_TYPES: frozenset[str] = frozenset(
    {
        "cl.te",
        "te.cl",
        "te.te",
        "te.0",
        "te.zero",
        "both-headers",
        "te-timing",
        "h2-downgrade",
    }
)


# A "smuggled" response looks like a second HTTP message embedded in
# the body or sent as a follow-up. Detection: response body contains
# what looks like another HTTP response start line.
_EMBEDDED_RESPONSE_RE = re.compile(r"HTTP/1\.[01]\s+\d{3}\s+", re.MULTILINE)


@dataclass(frozen=True)
class SmugglingProbe:
    """One operator-submitted smuggling probe + captured outcome."""

    probe_type: str  # "cl.te", "te.cl", "te.te", "te.0", "both-headers", "te-timing", "h2-downgrade"
    http_status: int = 0
    response_time_seconds: float = 0.0
    body_fingerprint: str = ""  # first ~500 chars of response body
    additional_responses_observed: int = 0  # if pipelined, count of extra responses
    notes: str = ""


@dataclass(frozen=True)
class SmugglingFinding:
    rule_id: str
    severity: str
    title: str
    detail: str
    remediation: str
    probe_type: str = ""


@dataclass(frozen=True)
class SmugglingAnalysis:
    total_probes: int
    findings: tuple[SmugglingFinding, ...] = field(default_factory=tuple)


def _embedded_response_count(body: str) -> int:
    """How many HTTP response start lines appear in the body."""
    return len(_EMBEDDED_RESPONSE_RE.findall(body))


def _classify_probe(probe: SmugglingProbe) -> list[SmugglingFinding]:
    """Classify a single probe outcome. May produce 0..N findings."""
    findings: list[SmugglingFinding] = []
    ptype = probe.probe_type.strip().lower()

    embedded = _embedded_response_count(probe.body_fingerprint)
    has_smuggled_response = embedded > 0 or probe.additional_responses_observed > 0

    if ptype == "cl.te":
        # CL.TE: front-end honors CL, back-end honors TE. The
        # back-end treats the extra data as the start of a new
        # request → the *next* legitimate response gets contaminated
        # with the smuggled prefix.
        if has_smuggled_response:
            findings.append(
                SmugglingFinding(
                    rule_id="SMG-001",
                    severity="CRITICAL",
                    title="CL.TE desync confirmed",
                    detail=(
                        "Front-end proxy uses Content-Length but the "
                        "back-end uses Transfer-Encoding: chunked. "
                        "Attacker can smuggle a request that "
                        "contaminates the next victim's response. "
                        "Direct path to cache poisoning, credential "
                        "theft, full request hijack."
                    ),
                    remediation=(
                        "Reject ambiguous requests upstream. nginx + "
                        "many WAFs ship a flag (`reject_ambiguous`). "
                        "Standardize on HTTP/2 end-to-end and disable "
                        "downgrade if possible."
                    ),
                    probe_type=ptype,
                )
            )

    elif ptype == "te.cl":
        if has_smuggled_response:
            findings.append(
                SmugglingFinding(
                    rule_id="SMG-002",
                    severity="CRITICAL",
                    title="TE.CL desync confirmed",
                    detail=(
                        "Front-end proxy uses Transfer-Encoding while "
                        "the back-end uses Content-Length. Same impact "
                        "as CL.TE — attacker contaminates the next "
                        "response in the pipeline."
                    ),
                    remediation=(
                        "Reject requests that include both CL and TE. Standardize on a single framing semantics."
                    ),
                    probe_type=ptype,
                )
            )

    elif ptype == "te.te":
        # TE.TE: header obfuscation (e.g. "Transfer-Encoding:\r\n  chunked"
        # or "Transfer-Encoding : chunked" — different proxies parse
        # differently). If embedded response appears, vulnerable.
        if has_smuggled_response:
            findings.append(
                SmugglingFinding(
                    rule_id="SMG-003",
                    severity="HIGH",
                    title="TE.TE desync via obfuscated header",
                    detail=(
                        "Front-end and back-end parse the Transfer-"
                        "Encoding header differently when whitespace, "
                        "alternate casing, or duplicate headers are "
                        "used. Splits a single request into two on the "
                        "back-end."
                    ),
                    remediation=(
                        "Normalize / canonicalize header parsing across the entire chain. Reject duplicate TE headers."
                    ),
                    probe_type=ptype,
                )
            )

    elif ptype in ("te.0", "te.zero"):
        if has_smuggled_response:
            findings.append(
                SmugglingFinding(
                    rule_id="SMG-004",
                    severity="CRITICAL",
                    title="TE.0 desync (HTTP/2 → HTTP/1.1 downgrade)",
                    detail=(
                        "Front-end accepts HTTP/2 but downgrades to "
                        "HTTP/1.1 to the origin; TE: chunked with "
                        "trailing 0-byte chunk smuggles a second "
                        "request. Major risk class against most HTTP/2 "
                        "front-ends not pinning HTTP/1.1 framing."
                    ),
                    remediation=(
                        "Keep HTTP/2 end-to-end OR strip Transfer-Encoding "
                        "at the downgrade boundary. Block TE in HTTP/2 "
                        "explicitly."
                    ),
                    probe_type=ptype,
                )
            )

    elif ptype == "both-headers":
        # Some servers ACCEPT requests that have BOTH CL and TE — that
        # itself is an RFC violation. Even without exploit, this is a
        # config bug.
        if probe.http_status and probe.http_status < 400:
            findings.append(
                SmugglingFinding(
                    rule_id="SMG-005",
                    severity="HIGH",
                    title="Server accepts both Content-Length and Transfer-Encoding",
                    detail=(
                        "RFC 7230 §3.3.3 states: a request that "
                        "specifies both headers must be rejected. The "
                        "server returned a success status to a probe "
                        "containing both."
                    ),
                    remediation=(
                        "Configure the server / proxy to reject requests with conflicting framing headers (return 400)."
                    ),
                    probe_type=ptype,
                )
            )

    elif ptype == "te-timing":
        # Timing-based detection: a TE chunked-encoded request that
        # the back-end thinks is incomplete will hang waiting for the
        # next chunk → 5+s delay. Indicates TE is honored by the
        # back-end, useful when the front-end isn't transparent.
        if probe.response_time_seconds >= 5.0:
            findings.append(
                SmugglingFinding(
                    rule_id="SMG-006",
                    severity="MEDIUM",
                    title="Timing-based evidence of TE handling on back-end",
                    detail=(
                        f"Probe took {probe.response_time_seconds:.1f}s — "
                        "consistent with a back-end honoring Transfer-"
                        "Encoding: chunked and waiting for further "
                        "chunks. Not direct proof of desync but strong "
                        "indicator the back-end is TE-aware."
                    ),
                    remediation=(
                        "Combine with a content-based probe (CL.TE / TE.CL) "
                        "for definitive proof. Then remediate per RFC 7230."
                    ),
                    probe_type=ptype,
                )
            )

    elif ptype == "h2-downgrade":
        if has_smuggled_response:
            findings.append(
                SmugglingFinding(
                    rule_id="SMG-007",
                    severity="HIGH",
                    title="HTTP/2 to HTTP/1.1 downgrade ambiguity confirmed",
                    detail=(
                        "Pseudo-header smuggling: the front-end accepts "
                        "HTTP/2 framing but the origin parses the "
                        "downgraded HTTP/1.1 request differently. "
                        "Enables h2c smuggling."
                    ),
                    remediation=(
                        "Disable HTTP/1.1 backend OR enforce strict pseudo-header validation at the front-end."
                    ),
                    probe_type=ptype,
                )
            )

    else:
        # Unknown probe type — fall back to body-fragmentation observation.
        if embedded > 0:
            findings.append(
                SmugglingFinding(
                    rule_id="SMG-008",
                    severity="LOW",
                    title="Suspicious response body fragmentation",
                    detail=(
                        f"Response body contained {embedded} HTTP response "
                        "start lines — fragmentation pattern that may "
                        "indicate proxy desync. Probe type was "
                        f"unrecognized ({probe.probe_type!r}); manual "
                        "review needed."
                    ),
                    remediation=("Re-probe with a documented technique (CL.TE / TE.CL / TE.TE) to confirm + classify."),
                    probe_type=ptype,
                )
            )

    return findings


def analyze_probes(probes: list[SmugglingProbe]) -> SmugglingAnalysis:
    findings: list[SmugglingFinding] = []
    for probe in probes:
        findings.extend(_classify_probe(probe))
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 99), f.rule_id))
    return SmugglingAnalysis(total_probes=len(probes), findings=tuple(findings))
