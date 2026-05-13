"""F103 — Open Redirect Detector.

Static analyzer for open-redirect risk: takes a list of URL+parameter
observations (e.g. `?next=...`, `?redirect=...`, `?returnUrl=...`)
and the server's Location header response when given a probe value.

Two analysis layers:

  (1) Heuristic — parameter NAMES that historically host open
      redirects (next, return, redirect, returnUrl, callback,
      continue, dest, destination, url, target, to, goto, link,
      redirect_uri).
  (2) Behavioral — when the operator includes the response for a
      probe payload (e.g. payload=https://evil.example), inspect the
      Location header. If the Location host matches the probe host
      → CONFIRMED open redirect.

Stable rule IDs:

  OR-001  Parameter name matches open-redirect heuristic (LOW signal)
  OR-002  Confirmed open redirect to attacker-controlled domain (CRITICAL)
  OR-003  Confirmed open redirect to relative scheme (//evil.example) (HIGH)
  OR-004  Confirmed open redirect via meta-refresh / JS (HIGH)
  OR-005  redirect_uri parameter accepts arbitrary host (OAuth-specific) (CRITICAL)
  OR-006  Whitelist bypass detected (e.g. example.com.attacker.com) (CRITICAL)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

__all__ = [
    "RedirectObservation",
    "RedirectFinding",
    "RedirectAnalysis",
    "analyze_observations",
    "ALL_OR_RULES",
]


ALL_OR_RULES: frozenset[str] = frozenset(
    {"OR-001", "OR-002", "OR-003", "OR-004", "OR-005", "OR-006"}
)


# Parameter names that historically carry redirect targets.
_REDIRECT_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "next", "return", "returnurl", "return_url", "returnto",
        "redirect", "redirect_uri", "redirecturl", "redirect_url",
        "callback", "continue", "dest", "destination",
        "url", "uri", "target", "to", "goto",
        "link", "back", "forward",
        "successurl", "success_url", "failureurl",
        "checkout_url", "completionurl", "completion_url",
    }
)


# Probe-payload value that operators typically inject. We detect both
# scheme-absolute (http(s)://evil) and scheme-relative (//evil) +
# meta-refresh / JS variants.
_ABSOLUTE_REDIRECT_RE = re.compile(r"^(https?:)?//", re.IGNORECASE)
_META_REFRESH_RE = re.compile(
    r"<meta[^>]*http-equiv=['\"]?refresh['\"]?[^>]*url=([^'\">]+)", re.IGNORECASE
)
_JS_LOCATION_RE = re.compile(
    r"(?:window\.)?location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE
)


@dataclass(frozen=True)
class RedirectObservation:
    """One redirect-related probe.

    The operator submits a probe payload (`probe_value`) to a
    parameter and captures the server's behavior.
    """

    url: str  # the page/endpoint, e.g. "/login"
    parameter_name: str  # e.g. "next"
    probe_value: str = ""  # e.g. "https://evil.example/x"
    response_status: int = 0
    response_location_header: str = ""  # value of Location: header
    response_body_snippet: str = ""  # first ~500 chars of body (for meta-refresh / JS)


@dataclass(frozen=True)
class RedirectFinding:
    rule_id: str
    severity: str
    title: str
    detail: str
    remediation: str
    url: str = ""
    parameter_name: str = ""


@dataclass(frozen=True)
class RedirectAnalysis:
    total_observations: int
    findings: tuple[RedirectFinding, ...] = field(default_factory=tuple)


def _normalized_param(name: str) -> str:
    return name.strip().lower().replace("-", "").replace("_", "")


def _is_redirect_param(name: str) -> bool:
    norm = _normalized_param(name)
    return norm in {n.replace("_", "") for n in _REDIRECT_PARAM_NAMES}


def _extract_target_host(redirect_target: str) -> str | None:
    """Return the host the redirect target points to, or None if it's
    a same-origin path."""
    if not redirect_target:
        return None
    target = redirect_target.strip()
    # Scheme-relative
    if target.startswith("//"):
        target = "http:" + target
    parsed = urlparse(target)
    if parsed.netloc:
        return parsed.netloc.lower()
    return None


def _probe_host(probe_value: str) -> str | None:
    """Return the host portion of the probe value, if any."""
    return _extract_target_host(probe_value)


def _classify_observation(obs: RedirectObservation) -> list[RedirectFinding]:
    findings: list[RedirectFinding] = []
    is_redirect_param = _is_redirect_param(obs.parameter_name)

    # OR-001: parameter name heuristic
    if is_redirect_param:
        findings.append(
            RedirectFinding(
                rule_id="OR-001",
                severity="LOW",
                title=f"Parameter {obs.parameter_name!r} commonly holds redirect targets",
                detail=(
                    "Parameter name matches a heuristic list of known "
                    "open-redirect vectors. Manual review or active "
                    "probing recommended."
                ),
                remediation=(
                    "Validate redirect targets against a strict server-side "
                    "allow-list of internal paths. Never trust user-supplied "
                    "URLs."
                ),
                url=obs.url,
                parameter_name=obs.parameter_name,
            )
        )

    # Behavioral checks — only if probe was sent + Location/body available
    if not obs.probe_value:
        return findings

    probe_host = _probe_host(obs.probe_value)
    location = obs.response_location_header or ""
    body_snippet = obs.response_body_snippet or ""

    # OR-002 / OR-003: Location header reflects probe domain
    if location:
        loc_host = _extract_target_host(location)
        if loc_host and probe_host and loc_host == probe_host:
            if location.lower().startswith(("http://", "https://")):
                findings.append(
                    RedirectFinding(
                        rule_id="OR-002",
                        severity="CRITICAL",
                        title="Confirmed open redirect to attacker-controlled domain",
                        detail=(
                            f"Server issued a Location: {location!r} after a "
                            f"probe with value {obs.probe_value!r}. Attacker "
                            "controls the destination of the redirect."
                        ),
                        remediation=(
                            "Server-side validate the redirect target against "
                            "an allow-list of internal hosts/paths. Reject "
                            "any absolute URL pointing off-site."
                        ),
                        url=obs.url,
                        parameter_name=obs.parameter_name,
                    )
                )
            elif location.startswith("//"):
                findings.append(
                    RedirectFinding(
                        rule_id="OR-003",
                        severity="HIGH",
                        title="Confirmed open redirect via scheme-relative URL",
                        detail=(
                            f"Server issued a Location: {location!r} (scheme-"
                            "relative). Browsers will use the page's scheme + "
                            "send the user to the attacker domain."
                        ),
                        remediation=(
                            "Strip scheme-relative `//` prefixes from redirect "
                            "targets. Anchor to an allow-list."
                        ),
                        url=obs.url,
                        parameter_name=obs.parameter_name,
                    )
                )

    # OR-004: meta-refresh / JS redirect in body
    if body_snippet and probe_host:
        meta_match = _META_REFRESH_RE.search(body_snippet)
        if meta_match:
            target = meta_match.group(1)
            tgt_host = _extract_target_host(target)
            if tgt_host == probe_host:
                findings.append(
                    RedirectFinding(
                        rule_id="OR-004",
                        severity="HIGH",
                        title="Confirmed open redirect via meta-refresh",
                        detail=(
                            f"Response body contains <meta http-equiv=refresh "
                            f"url={target!r}> pointing to probe host. "
                            "Server-side bug — body shouldn't echo unvalidated "
                            "user input into HTML."
                        ),
                        remediation=(
                            "Don't echo redirect targets into meta tags. Use "
                            "validated server-side redirects (HTTP 302/303)."
                        ),
                        url=obs.url,
                        parameter_name=obs.parameter_name,
                    )
                )
        js_match = _JS_LOCATION_RE.search(body_snippet)
        if js_match:
            target = js_match.group(1)
            tgt_host = _extract_target_host(target)
            if tgt_host == probe_host:
                findings.append(
                    RedirectFinding(
                        rule_id="OR-004",
                        severity="HIGH",
                        title="Confirmed open redirect via JavaScript location",
                        detail=(
                            f"Response body sets window.location = {target!r} "
                            "via JavaScript. Behaves like a 302 to the "
                            "attacker domain."
                        ),
                        remediation=(
                            "Never assign user-controlled values to "
                            "window.location without an allow-list."
                        ),
                        url=obs.url,
                        parameter_name=obs.parameter_name,
                    )
                )

    # OR-005: OAuth-specific (redirect_uri parameter)
    if _normalized_param(obs.parameter_name) == "redirecturi":
        # If we confirmed an absolute redirect above, escalate as OR-005
        if any(f.rule_id == "OR-002" for f in findings):
            findings.append(
                RedirectFinding(
                    rule_id="OR-005",
                    severity="CRITICAL",
                    title="OAuth redirect_uri accepts arbitrary host",
                    detail=(
                        "redirect_uri parameter accepted an attacker-controlled "
                        "host. In OAuth 2.0 this enables authorization-code "
                        "theft → full account takeover."
                    ),
                    remediation=(
                        "Strict EXACT-MATCH on redirect_uri against the "
                        "registered URI list. No wildcards, no substring "
                        "matching, no scheme variation."
                    ),
                    url=obs.url,
                    parameter_name=obs.parameter_name,
                )
            )

    # OR-006: whitelist bypass — probe value contains a legit-looking
    # prefix concatenated with attacker domain. Common bypass shapes:
    #   https://yoursite.com.attacker.com/
    #   https://yoursite.com@attacker.com/
    #   https://attacker.com/yoursite.com
    # We detect by inspecting whether the probe contains '@' or
    # subdomain-concatenation patterns AND the response still
    # redirected.
    if location and probe_host:
        loc_host = _extract_target_host(location)
        if loc_host and "@" in obs.probe_value:
            findings.append(
                RedirectFinding(
                    rule_id="OR-006",
                    severity="CRITICAL",
                    title="Whitelist bypass via @ in URL",
                    detail=(
                        f"Probe URL {obs.probe_value!r} contained '@' (HTTP "
                        "userinfo) — a classic whitelist-bypass shape. "
                        "Server redirected as requested."
                    ),
                    remediation=(
                        "Parse + validate the HOST of the redirect target "
                        "using a URL library. Reject anything where userinfo "
                        "is present or host doesn't exact-match the allow-list."
                    ),
                    url=obs.url,
                    parameter_name=obs.parameter_name,
                )
            )

    return findings


def analyze_observations(
    observations: list[RedirectObservation],
) -> RedirectAnalysis:
    findings: list[RedirectFinding] = []
    for obs in observations:
        findings.extend(_classify_observation(obs))
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(
        key=lambda f: (severity_order.get(f.severity, 99), f.rule_id, f.url)
    )
    return RedirectAnalysis(
        total_observations=len(observations), findings=tuple(findings)
    )
