"""Deterministic verification oracles — turn a *candidate* web vuln into a
*confirmed* one without LLM judgment, killing false positives. SQL injection
(error / boolean / time), reflected XSS (unescaped reflection), and open redirect.

These send test payloads, so they are ACTIVE: ``run_verification`` is gated by
KRYON_RED_TEAM. The individual ``verify_*`` functions are pure logic over an
injectable request hook and are unit-testable offline.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from kryon.cli.engage import Finding, make_finding
from kryon.util.env import is_red_team

_T = 8.0


@dataclass(frozen=True)
class OracleVerdict:
    confirmed: bool
    technique: str
    evidence: str


def _request(url: str) -> tuple[int, dict[str, str], str, float] | None:
    """GET url (no redirects) → (status, headers_lower, body, elapsed_s) or None."""
    from kryon.cli.probe_http import request  # noqa: PLC0415

    r = request(url=url, follow_redirects=False, timeout=_T, max_body=20000, user_agent="kryon-oracle")
    return (r.status, r.headers, r.body, r.elapsed) if r else None


def _with_param(url: str, param: str, value: str) -> str:
    parts = urllib.parse.urlsplit(url)
    q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(q), parts.fragment))


_SQL_ERRORS = (
    "you have an error in your sql syntax", "warning: mysql", "mysqli", "unclosed quotation mark",
    "microsoft ole db provider", "odbc sql server driver", "postgresql query failed",
    "syntax error at or near", "ora-00933", "ora-01756", "sqlite_error", "unrecognized token",
    "supplied argument is not a valid mysql", "quoted string not properly terminated",
)


def verify_sqli(url: str, param: str, base_value: str = "1", request=_request) -> OracleVerdict:
    base = request(_with_param(url, param, base_value))
    if not base:
        return OracleVerdict(False, "sqli", "target unreachable")
    # 1) Error-based: a bare quote surfaces a DB error not in the baseline.
    err = request(_with_param(url, param, base_value + "'"))
    if err and any(s in err[2].lower() and s not in base[2].lower() for s in _SQL_ERRORS):
        sig = next(s for s in _SQL_ERRORS if s in err[2].lower())
        return OracleVerdict(True, "sqli-error", f"DB error '{sig}' surfaced by a single quote")
    # 2) Boolean-based: TRUE response ~ baseline, FALSE response diverges.
    t = request(_with_param(url, param, f"{base_value}' AND '1'='1"))
    fa = request(_with_param(url, param, f"{base_value}' AND '1'='2"))
    if t and fa:
        lt, lf, lb = len(t[2]), len(fa[2]), len(base[2])
        true_like = abs(lt - lb) <= max(20, lb * 0.05)
        false_diff = abs(lf - lt) > max(20, lt * 0.05) or t[0] != fa[0]
        if true_like and false_diff:
            return OracleVerdict(True, "sqli-boolean", f"AND 1=1 ~ baseline ({lt}B), AND 1=2 diverges ({lf}B)")
    # 3) Time-based: a SLEEP payload measurably delays the response.
    slow = request(_with_param(url, param, f"{base_value}' AND SLEEP(5)-- -"))
    if slow and slow[3] >= 4.5 and base[3] < 2.0:
        return OracleVerdict(True, "sqli-time", f"SLEEP(5) → {slow[3]:.1f}s vs baseline {base[3]:.1f}s")
    return OracleVerdict(False, "sqli", "no oracle confirmed injection")


_XSS_CANARY = 'kx9z"><svg/onload=alert(1337)>'


def verify_xss(url: str, param: str, request=_request) -> OracleVerdict:
    r = request(_with_param(url, param, _XSS_CANARY))
    if r and "<svg/onload=alert(1337)>" in r[2]:  # angle brackets reflected UNescaped
        return OracleVerdict(True, "xss-reflected", "canary reflected unescaped (<svg/onload> intact in response)")
    return OracleVerdict(False, "xss", "payload not reflected unescaped")


_REDIR_CANARY = "https://kryon-canary.example/x"


def verify_open_redirect(url: str, param: str, request=_request) -> OracleVerdict:
    r = request(_with_param(url, param, _REDIR_CANARY))
    if r and r[0] in (301, 302, 303, 307, 308):
        loc = r[1].get("location", "")
        if loc.startswith(_REDIR_CANARY) or loc.startswith("//kryon-canary.example"):
            return OracleVerdict(True, "open-redirect", f"Location → {loc[:80]} (attacker-controlled)")
    return OracleVerdict(False, "open-redirect", "redirect not attacker-controlled")


_TECH = {
    "sqli-error": ("CWE-89", "CRITICAL"), "sqli-boolean": ("CWE-89", "CRITICAL"), "sqli-time": ("CWE-89", "CRITICAL"),
    "xss-reflected": ("CWE-79", "HIGH"), "open-redirect": ("CWE-601", "MEDIUM"),
}


def to_finding(v: OracleVerdict, url: str, param: str, host: str) -> Finding | None:
    if not v.confirmed:
        return None
    cwe, sev = _TECH.get(v.technique, ("CWE-707", "HIGH"))
    return make_finding(cwe, sev, host, f"verified-{v.technique}",
                        f"CONFIRMADO {v.technique} en {url} (param {param}).",
                        evidence=f"Oráculo determinista: {v.evidence}",
                        remediation="Usar consultas parametrizadas / encoding contextual / allowlist de redirect; este hallazgo está verificado (no es FP).")


def run_verification(url: str, param: str, host: str) -> list[Finding]:
    """Run all oracles against a candidate URL+param. Gated by KRYON_RED_TEAM (active)."""
    if not is_red_team():
        return []
    out: list[Finding] = []
    for verify in (verify_sqli, verify_xss, verify_open_redirect):
        try:
            f = to_finding(verify(url, param), url, param, host)
            if f:
                out.append(f)
        except Exception:  # noqa: BLE001
            continue
    return out
