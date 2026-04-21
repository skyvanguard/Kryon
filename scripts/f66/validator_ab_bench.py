"""F67.6 / F66.2.c — validator A/B bench with request-shape replay.

Runs the legacy and deterministic validators over the same fixture
(3 real findings + 3 fake ones) and prints a precision / recall table.
Reals carry method/body/headers_json so the deterministic validator can
replay the exploit instead of bare GETting the URL.
"""
from __future__ import annotations

from kryon.webexploit.banking_probes import BankingFinding
from kryon.webexploit.orchestrator import validator_web
from kryon.webexploit.proxy import HttpSession


def sf() -> HttpSession:
    return HttpSession()


FINDINGS: list[BankingFinding] = [
    # REAL SQLi login bypass — now carries POST + JSON body.
    BankingFinding(
        probe_id="sqli_login_admin", cwe_id="CWE-89", severity="HIGH",
        title="SQLi admin bypass",
        url="http://juice.local:3000/rest/user/login",
        evidence="admin@juice-sh.op authenticated via SQLi",
        payload="admin'--", finding_type="confirmed",
        method="POST",
        body='{"email":"admin@juice-sh.op\'--","password":"x"}',
        headers_json='{"Content-Type":"application/json"}',
    ),
    # REAL: /metrics exposed (plain GET).
    BankingFinding(
        probe_id="metrics_exposed", cwe_id="CWE-200", severity="MEDIUM",
        title="Prometheus metrics",
        url="http://juice.local:3000/metrics",
        evidence="# HELP http_request_duration",
        finding_type="confirmed",
    ),
    # REAL: /rest/admin/application-configuration exposed.
    BankingFinding(
        probe_id="app_config_leak", cwe_id="CWE-200", severity="MEDIUM",
        title="App config leak",
        url="http://juice.local:3000/rest/admin/application-configuration",
        evidence="server config JSON",
        finding_type="confirmed",
    ),
    # FP: fake endpoint that returns 404.
    BankingFinding(
        probe_id="fake_sqli", cwe_id="CWE-89", severity="CRITICAL",
        title="Fake SQLi",
        url="http://juice.local:3000/nonexistent-sqli",
        evidence="fake", finding_type="confirmed",
    ),
    # FP: XSS claim at root, no reflection.
    BankingFinding(
        probe_id="fake_xss", cwe_id="CWE-79", severity="HIGH",
        title="Fake XSS",
        url="http://juice.local:3000/",
        evidence="fake", finding_type="confirmed",
    ),
    # FP: SSRF claim at read-only challenge list.
    BankingFinding(
        probe_id="fake_ssrf", cwe_id="CWE-918", severity="CRITICAL",
        title="Fake SSRF",
        url="http://juice.local:3000/api/Challenges",
        evidence="fake", finding_type="confirmed",
    ),
]


def _summary(results) -> dict:
    sums = {"CONFIRMED": 0, "CANDIDATE": 0, "FALSE_POSITIVE": 0, "ERROR": 0}
    for v in results:
        sums[v.status] = sums.get(v.status, 0) + 1
    return sums


def _is_fp(probe_id: str) -> bool:
    return probe_id.startswith("fake")


def main() -> int:
    print("=== LEGACY validator (re-GET, accept any live response) ===")
    legacy = validator_web(sf, FINDINGS, replays=1, deterministic=False)
    for v in legacy:
        label = "FP  " if _is_fp(v.finding.probe_id) else "REAL"
        print(f"  {label} {v.status:16} {v.finding.probe_id:22} "
              f"{v.validator_notes[:65]}")
    print(f"  totals: {_summary(legacy)}")

    print()
    print("=== DETERMINISTIC validator (F66.2.a + F67.6 replay) ===")
    deter = validator_web(sf, FINDINGS, deterministic=True)
    for v in deter:
        label = "FP  " if _is_fp(v.finding.probe_id) else "REAL"
        print(f"  {label} {v.status:16} {v.finding.probe_id:22} "
              f"{v.validator_notes[:75]}")
    print(f"  totals: {_summary(deter)}")

    print()
    print("=== precision / recall ===")
    total_reals = sum(1 for f in FINDINGS if not _is_fp(f.probe_id))
    total_fps = sum(1 for f in FINDINGS if _is_fp(f.probe_id))
    for label, results in (("legacy", legacy), ("deterministic", deter)):
        tp = sum(1 for v in results
                 if v.status == "CONFIRMED" and not _is_fp(v.finding.probe_id))
        fp = sum(1 for v in results
                 if v.status == "CONFIRMED" and _is_fp(v.finding.probe_id))
        prec = 100 * tp / max(tp + fp, 1)
        recall = 100 * tp / max(total_reals, 1)
        print(f"  {label:14} TP={tp}/{total_reals}  FP={fp}/{total_fps}  "
              f"precision={prec:.0f}%  recall={recall:.0f}%")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
