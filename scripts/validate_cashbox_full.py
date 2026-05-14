"""Loop-cerrado validation: corre F97/F98/F100/F101/F102/F104/F107
contra https://cashbox.britimp.com.py/ (target autorizado del operador,
sistemas@britimp.com.py).

Read-only: HEAD/GET sin payloads destructivos. F103 open-redirect y
F105 smuggling y F106 SSRF se omiten (requieren payloads activos o
source code, fuera del alcance de este pase)."""

from __future__ import annotations

import json
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from typing import Any

# Make src/ importable in case CWD differs.
sys.path.insert(0, "src")

from kryon.tools.api.cms_fingerprint import (
    FingerprintObservation,
    analyze_fingerprint,
)
from kryon.tools.api.cookie_security import (
    ParsedCookie,
    analyze_cookies,
)
from kryon.tools.api.dom_xss import JsSnippet, analyze_dom_xss
from kryon.tools.api.info_disclosure import (
    DisclosureProbe,
    analyze_probes as analyze_disclosure,
    default_probe_paths,
)
from kryon.tools.api.security_headers import (
    HTTPResponse,
    analyze_security_headers,
)
from kryon.tools.api.vuln_js_libs import (
    ScriptObservation,
    analyze_scripts,
)

TARGET = "https://cashbox.britimp.com.py"
UA = "Kryon-F101-F107-Validator/1.0 (authorized; sistemas@britimp.com.py)"
TIMEOUT = 8


def fetch(method: str, url: str, max_body: int = 8000) -> dict[str, Any]:
    """Read-only request. Returns dict with status, headers, body fragment."""
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            body = b""
            if method == "GET":
                body = r.read(max_body)
            return {
                "status": r.status,
                "headers": list(r.headers.items()),
                "body": body.decode("utf-8", errors="replace"),
                "final_url": r.geturl(),
            }
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(max_body)
        except Exception:
            pass
        return {
            "status": e.code,
            "headers": list(e.headers.items()) if e.headers else [],
            "body": body.decode("utf-8", errors="replace"),
            "final_url": url,
        }
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {
            "status": 0,
            "headers": [],
            "body": "",
            "final_url": url,
            "error": str(e),
        }


def extract_set_cookie_strings(headers: list[tuple[str, str]]) -> list[str]:
    """Return raw Set-Cookie header values."""
    return [v for k, v in headers if k.lower() == "set-cookie"]


def cookie_names_from_strings(set_cookies: list[str]) -> list[str]:
    """Return just the cookie names parsed from Set-Cookie strings."""
    names: list[str] = []
    for raw in set_cookies:
        ck = SimpleCookie()
        try:
            ck.load(raw)
        except Exception:
            continue
        names.extend(ck.keys())
    return names


def main() -> int:
    print("=" * 72)
    print(f"VALIDATION RUN — {TARGET}")
    print(f"timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 72)

    # ---- 1. Root page fetch (drives F97/F98/F104/F102 + JS extraction) -
    print("\n[1/7] GET /")
    root = fetch("GET", f"{TARGET}/")
    print(f"  status={root['status']}  final_url={root['final_url']}")
    if root["status"] == 0:
        print(f"  ERROR: {root.get('error')}")
        return 1

    # ---- F97 Security Headers --------------------------------------------
    print("\n[2/7] F97 Security Headers")
    # F97 expects headers as dict; later analyzers want tuple-of-tuples.
    headers_dict: dict[str, str] = {}
    for k, v in root["headers"]:
        # merge duplicate cookies / etc into a single value
        if k in headers_dict:
            headers_dict[k] = headers_dict[k] + ", " + v
        else:
            headers_dict[k] = v
    response = HTTPResponse(
        url=root["final_url"],
        method="GET",
        is_https=root["final_url"].startswith("https://"),
        headers=headers_dict,
    )
    hdr_analysis = analyze_security_headers(response)
    print(f"  findings: {len(hdr_analysis.findings)}")
    for f in hdr_analysis.findings[:8]:
        print(f"    [{f.severity:8s}] {f.rule_id}: {f.title}")
    if len(hdr_analysis.findings) > 8:
        print(f"    ... ({len(hdr_analysis.findings) - 8} more)")

    # ---- F98 Cookies -----------------------------------------------------
    print("\n[3/7] F98 Cookies")
    set_cookie_strings = extract_set_cookie_strings(root["headers"])
    cook_analysis = analyze_cookies(set_cookie_strings, is_https=True)
    print(f"  Set-Cookie headers: {len(set_cookie_strings)}  findings: {len(cook_analysis.findings)}")
    for f in cook_analysis.findings[:8]:
        print(f"    [{f.severity:8s}] {f.rule_id}: {f.title}")

    # ---- F104 CMS Fingerprint -------------------------------------------
    print("\n[4/7] F104 CMS Fingerprint")
    # extract cookies names from Set-Cookie + body
    cookie_names = tuple(cookie_names_from_strings(set_cookie_strings))
    fp_obs = FingerprintObservation(
        url=root["final_url"],
        headers=tuple((k, v) for k, v in root["headers"]),
        body_snippet=root["body"][:5000],
        cookie_names=cookie_names,
    )
    fp_analysis = analyze_fingerprint(fp_obs)
    print(f"  findings: {len(fp_analysis.findings)}")
    for f in fp_analysis.findings:
        tech = f.detected_tech + (f" {f.detected_version}" if f.detected_version else "")
        print(f"    [{f.severity:8s}] {f.rule_id}: {f.title}  [{tech}]")

    # ---- F102 Vulnerable JS Libraries -----------------------------------
    print("\n[5/7] F102 Vulnerable JS Libs")
    import re

    script_urls = re.findall(
        r'<script[^>]*src=["\']([^"\']+)["\']', root["body"], re.IGNORECASE
    )
    print(f"  scripts found: {len(script_urls)}")
    js_obs: list[ScriptObservation] = []
    for src in script_urls[:20]:  # cap to 20 to be polite
        js_obs.append(ScriptObservation(src=src))
    js_analysis = analyze_scripts(js_obs)
    print(f"  findings: {len(js_analysis.findings)}")
    for f in js_analysis.findings:
        print(f"    [{f.severity:8s}] {f.rule_id}: {f.title}  ({f.script_src})")

    # ---- F101 Information Disclosure -----------------------------------
    print("\n[6/7] F101 Information Disclosure")
    probes_to_run = [
        "/.git/config",
        "/.env",
        "/.env.production",
        "/robots.txt",
        "/server-status",
        "/phpinfo.php",
        "/.DS_Store",
        "/package.json",
        "/Dockerfile",
        "/docker-compose.yml",
        "/swagger-ui.html",
        "/openapi.json",
        "/wp-admin/",
        "/administrator/",
        "/phpmyadmin/",
        "/composer.json",
    ]
    print(f"  probes: {len(probes_to_run)}")
    probes: list[DisclosureProbe] = []
    for path in probes_to_run:
        r = fetch("GET", f"{TARGET}{path}", max_body=500)
        probes.append(
            DisclosureProbe(
                path=path,
                http_status=r["status"],
                body_fingerprint=r["body"][:200],
            )
        )
    disc_analysis = analyze_disclosure(probes)
    print(f"  findings: {len(disc_analysis.findings)}")
    for f in disc_analysis.findings:
        print(f"    [{f.severity:8s}] {f.rule_id}: {f.title}  ({f.path})")

    # ---- F107 DOM XSS Sinks (in inline + first-script body) -------------
    print("\n[7/7] F107 DOM XSS Sinks")
    # Inline scripts in root HTML
    inline_scripts = re.findall(
        r"<script[^>]*>(.*?)</script>", root["body"], re.IGNORECASE | re.DOTALL
    )
    snippets: list[JsSnippet] = []
    for idx, body in enumerate(inline_scripts):
        if body.strip():
            snippets.append(JsSnippet(file_path=f"inline-{idx}", body=body))
    # Also fetch up to 3 external scripts and scan
    scanned_ext = 0
    for src in script_urls[:6]:
        if scanned_ext >= 3:
            break
        if src.startswith("//"):
            url = "https:" + src
        elif src.startswith("/"):
            url = TARGET + src
        elif src.startswith(("http://", "https://")):
            url = src
        else:
            url = TARGET + "/" + src
        r = fetch("GET", url, max_body=40000)
        if r["status"] == 200 and r["body"]:
            snippets.append(JsSnippet(file_path=src, body=r["body"]))
            scanned_ext += 1
    dom_analysis = analyze_dom_xss(snippets)
    print(f"  snippets analyzed: {len(snippets)}  findings: {len(dom_analysis.findings)}")
    for f in dom_analysis.findings[:10]:
        print(f"    [{f.severity:8s}] {f.rule_id}: {f.file_path}:{f.line} — {f.snippet}")
    if len(dom_analysis.findings) > 10:
        print(f"    ... ({len(dom_analysis.findings) - 10} more)")

    # ---- Aggregate summary ----------------------------------------------
    print("\n" + "=" * 72)
    print("AGGREGATE SUMMARY")
    print("=" * 72)
    all_findings = (
        list(hdr_analysis.findings)
        + list(cook_analysis.findings)
        + list(fp_analysis.findings)
        + list(js_analysis.findings)
        + list(disc_analysis.findings)
        + list(dom_analysis.findings)
    )
    by_sev: dict[str, int] = {}
    for f in all_findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in by_sev:
            print(f"  {sev:8s}: {by_sev[sev]}")
    print(f"  TOTAL  : {len(all_findings)}")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
