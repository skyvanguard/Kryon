"""F186 — Pre-hook output truncation + imperative prompt tests.

F185.C bench showed pre_hooks fire 3/3 but only 1/3 runs converted
the output to structured findings — the other two saw verbose
nuclei/nikto dumps and got lost in the noise.

F186 introduces ``summarize_pre_hook_output`` which:
* Detects the tool by inject_as name or content signature
* Parses nuclei / nikto / generic JSON output into a structured
  finding list (capped to top N by severity)
* Drops verbose noise (templates loaded, scan metadata, banners)
* Returns a compact markdown summary the model can convert to
  findings JSON without re-parsing

Plus ``imperative_findings_suffix`` — a short directive appended
after the evidence block: "Convert each item above into a finding
JSON entry. Do NOT re-invoke these tools."
"""

from __future__ import annotations

import pytest

from kryon.skills.pre_hook_output_processor import (
    imperative_findings_suffix,
    summarize_pre_hook_output,
)


# ---------------------------------------------------------------------------
# nuclei output summarization
# ---------------------------------------------------------------------------


_NUCLEI_SAMPLE = """\
                     __     _
   ____  __  _______/ /__  (_)
  / __ \\/ / / / ___/ / _ \\/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\\__,_/\\___/_/\\___/_/   v3.8.0
[INF] Current nuclei version: v3.8.0
[INF] Templates loaded: 9000
[INF] Targets loaded: 1
[INF] Scan started

[exposed-files] [http] [low] http://x/.htpasswd
[exposed-files] [http] [low] http://x/.bash_history
[missing-headers] [http] [info] http://x/ ["X-Frame-Options"]
[xss-reflected] [http] [high] http://x/search?q=<script>alert(1)</script>
[sql-injection] [http] [critical] http://x/api?id=1' OR 1=1--

[INF] Scan completed in 12s
"""


def test_nuclei_summary_keeps_severity_findings():
    out = summarize_pre_hook_output("nuclei_pre_scan", _NUCLEI_SAMPLE)
    # Severity-bearing lines preserved.
    assert "xss-reflected" in out
    assert "sql-injection" in out
    assert "exposed-files" in out
    # Banner / template-loaded lines stripped.
    assert "Templates loaded" not in out
    assert "Scan started" not in out
    assert "v3.8.0" not in out


def test_nuclei_summary_truncates_to_top_n():
    # Generate 60 findings of varied severity.
    payload = "\n".join(
        f"[template-{i}] [http] [info] http://x/path-{i}" for i in range(60)
    )
    out = summarize_pre_hook_output("nuclei_pre_scan", payload, max_items=30)
    # Cap respected.
    finding_lines = [line for line in out.splitlines() if line.startswith("[")]
    assert len(finding_lines) <= 30


def test_nuclei_summary_prioritizes_critical_high():
    payload = (
        "[t1] [http] [info] http://x/1\n"
        "[t2] [http] [low] http://x/2\n"
        "[t3] [http] [critical] http://x/3\n"
        "[t4] [http] [high] http://x/4\n"
        "[t5] [http] [info] http://x/5\n"
    )
    out = summarize_pre_hook_output("nuclei_pre_scan", payload, max_items=3)
    # Critical + high must survive even when there are also info/low lines.
    assert "[critical]" in out
    assert "[high]" in out


# ---------------------------------------------------------------------------
# nikto output summarization
# ---------------------------------------------------------------------------


_NIKTO_SAMPLE = """\
- Nikto v2.6.0
---------------------------------------------------------------------------
+ Target IP:          172.21.0.3
+ Target Hostname:    juice_shop
+ Target Port:        3000
+ Start Time:         2026-05-16 14:00:00
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ /robots.txt: contains 1 entry which should be manually viewed.
+ /.htpasswd: This file contains usernames and password hashes.
+ /api/: API endpoint may be exposed; verify access controls.
+ /admin: Possible admin URI.
+ OSVDB-3092: /admin/: This might be interesting.
---------------------------------------------------------------------------
+ 1 host(s) tested
End Time: 2026-05-16 14:01:00
"""


def test_nikto_summary_keeps_plus_findings():
    out = summarize_pre_hook_output("nikto_pre_scan", _NIKTO_SAMPLE)
    assert "/robots.txt" in out
    assert "/.htpasswd" in out
    assert "/admin" in out
    # Banner / metadata stripped.
    assert "Nikto v2.6.0" not in out
    assert "Start Time" not in out
    assert "host(s) tested" not in out


def test_nikto_summary_truncates_to_top_n():
    payload = "\n".join(f"+ /path-{i}: Finding {i}." for i in range(80))
    out = summarize_pre_hook_output("nikto_pre_scan", payload, max_items=30)
    finding_lines = [line for line in out.splitlines() if line.startswith("+ /")]
    assert len(finding_lines) <= 30


_NIKTO_V26_SAMPLE = """\
- Nikto v2.6.0
+ Target IP:          172.21.0.3
+ Target Hostname:    juice_shop
+ Server: No banner retrieved
+ [999986] /: Retrieved access-control-allow-origin header: *.
+ [999996] /robots.txt: contains 1 entry which should be manually viewed.
+ [013587] /: Suggested security header missing: permissions-policy.
+ [013587] /: Suggested security header missing: strict-transport-security.
+ [013587] /: Suggested security header missing: content-security-policy.
+ Scan terminated: 1 error and 7 items reported.
+ End Time:           2026-05-16 19:59:59
"""


def test_nikto_v26_bracketed_id_lines_recognized():
    """F186.B regression — nikto v2.6+ emits findings as
    ``+ [NNNNNN] /path: ...`` with an OSVDB-style id. The original
    F186 regex only accepted ``+ /path: ...`` so it dropped every
    real finding from nikto v2.6 — the bench saw nikto_pre_scan
    return 2122 chars but the model received "" as the parsed
    summary."""
    out = summarize_pre_hook_output("nikto_pre_scan", _NIKTO_V26_SAMPLE)
    # The bracketed-id findings must survive.
    assert "[999986]" in out
    assert "[999996]" in out
    assert "/robots.txt" in out
    # Metadata lines stripped (Target IP, Server: No banner, Scan
    # terminated, End Time).
    assert "Target IP" not in out
    assert "No banner retrieved" not in out
    assert "Scan terminated" not in out
    assert "End Time" not in out


def test_nikto_v26_metadata_lines_filtered():
    """``+ Server: ...``, ``+ Target IP: ...``, etc. start with ``+ Word:``
    (no leading slash). Must NOT match the finding regex."""
    payload = (
        "+ Target IP:          1.2.3.4\n"
        "+ Server: nginx/1.20\n"
        "+ [999986] /api: real finding\n"
    )
    out = summarize_pre_hook_output("nikto_pre_scan", payload)
    assert "real finding" in out
    assert "Target IP" not in out
    assert "Server: nginx" not in out


# ---------------------------------------------------------------------------
# sqlmap summarization (F187)
# ---------------------------------------------------------------------------


_SQLMAP_VULNERABLE_SAMPLE = """\
[*] starting @ 21:16:01

[21:16:01] [INFO] testing connection to the target URL
[21:16:01] [INFO] testing if GET parameter 'q' is dynamic
[21:16:25] [INFO] checking if the injection point on POST parameter 'JSON email' is a false positive
(custom) POST parameter 'JSON email' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 411 HTTP(s) requests:
---
Parameter: JSON email ((custom) POST)
    Type: boolean-based blind
    Title: SQLite AND boolean-based blind - WHERE, HAVING, GROUP BY or HAVING clause (JSON)
    Payload: {"email":"test' AND CASE WHEN 3293=3293 THEN 3293 ELSE JSON(CHAR(104,81,72,106)) END AND 'mmuj'='mmuj","password":"test"}
---
[21:16:26] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[21:16:26] [WARNING] HTTP error codes detected during run: 401 - 310 times
"""


def test_sqlmap_vulnerable_finding_preserved():
    out = summarize_pre_hook_output(
        "sqlmap_rest_login_pre_scan", _SQLMAP_VULNERABLE_SAMPLE
    )
    # The injection point block + parameter type + payload + DBMS line
    # are the four things the model needs to emit a CWE-89 finding.
    assert "injection point" in out
    assert "Parameter: JSON email" in out
    assert "Type: boolean-based blind" in out
    assert "Payload:" in out
    assert "back-end DBMS: SQLite" in out
    # Verbose [INFO] testing lines stripped.
    assert "testing connection" not in out
    assert "testing if GET parameter" not in out


_SQLMAP_NEGATIVE_SAMPLE = """\
[*] starting @ 21:15:19
[21:15:19] [INFO] testing connection to the target URL
[21:15:20] [INFO] testing if GET parameter 'q' is dynamic
[21:15:20] [WARNING] GET parameter 'q' does not seem to be injectable
[21:15:20] [ERROR] all tested parameters do not appear to be injectable.
"""


def test_sqlmap_negative_compact_message():
    """When sqlmap finds nothing, the model still needs to know the
    probe ran (so it doesn't re-invoke sqlmap or claim "we didn't
    test SQLi"). A single negative line suffices."""
    out = summarize_pre_hook_output(
        "sqlmap_rest_login_pre_scan", _SQLMAP_NEGATIVE_SAMPLE
    )
    assert "no injection" in out.lower() or "not vulnerable" in out.lower()
    # Don't include the verbose testing trail.
    assert "testing if GET parameter" not in out


# ---------------------------------------------------------------------------
# Unknown / generic output → length cap only
# ---------------------------------------------------------------------------


def test_unknown_tool_falls_back_to_length_cap():
    payload = "x" * 20000
    out = summarize_pre_hook_output("custom_pre_scan", payload)
    # Hard cap so the context window doesn't blow up.
    assert len(out) <= 9000


def test_empty_payload_returns_empty():
    assert summarize_pre_hook_output("anything", "") == ""
    assert summarize_pre_hook_output("anything", None) == ""  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# imperative_findings_suffix
# ---------------------------------------------------------------------------


def test_imperative_suffix_contains_action_verb():
    suf = imperative_findings_suffix()
    # The model must be told to CONVERT (not just describe).
    lowered = suf.lower()
    assert "convert" in lowered or "emit" in lowered or "produce" in lowered
    # And told NOT to re-run the tools — accept either the English
    # ``do not`` / ``DO NOT`` or the Spanish negative imperative
    # ``no re-invoc``.
    assert (
        "do not" in lowered
        or "DO NOT" in suf
        or "no re-invoc" in lowered
        or "no re-run" in lowered
    )


def test_imperative_suffix_short():
    """Must stay short so it doesn't drown the actual evidence."""
    assert len(imperative_findings_suffix()) <= 800
