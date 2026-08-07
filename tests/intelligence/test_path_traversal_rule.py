"""Static-file path traversal / filter-bypass rule (CWE-22).

Juice Shop's traversal is a poison-null-byte filter bypass on /ftp: a blocked backup extension
(``package.json.bak`` → 403) becomes readable via ``package.json.bak%2500.md`` → 200. The proof is
the CONTRAST (blocked without the bypass, served with it), plus a direct ../ read of /etc/passwd for
apps that don't sanitize traversal. curl-provable, unlike the DOM-XSS case.
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import _rule_path_traversal_files
from kryon.intelligence.fact_extractor import ExtractedFacts

_WEB = ExtractedFacts(services=((80, "http"),), hosts=("shop.thm",), paths=("/ftp",))


def test_path_traversal_closes_nullbyte_and_passwd_proof():
    rec = _rule_path_traversal_files(_WEB, [], "")
    assert rec is not None
    # poison null byte filter bypass + proof-by-contrast (blocked without it)
    assert "%2500.md" in rec.args
    assert "TRAVERSAL-NULLBYTE" in rec.args
    assert "sin bypass=" in rec.args  # the contrast is logged
    # direct traversal to /etc/passwd via several encodings
    assert "TRAVERSAL-PASSWD" in rec.args
    assert "root:.*:0:0:" in rec.args
    assert "%252f" in rec.args  # double-encoded traversal variant
    # canonical file-serving endpoint present
    assert "/ftp" in rec.args
    # hostlist real, no literal placeholder; guards heredados
    assert "<target>" not in rec.args
    assert "shop.thm" in rec.args
    assert "|| true" in rec.args
    assert "<(!doctype|html" in rec.args  # SPA/HTML fallback filtered out


def test_path_traversal_abstains_without_web_or_surface():
    # no web port
    assert _rule_path_traversal_files(ExtractedFacts(hosts=("x",), paths=("/ftp",)), [], "") is None
    # no discovered web surface
    assert _rule_path_traversal_files(ExtractedFacts(services=((80, "http"),), hosts=("x",)), [], "") is None
    # already invoked
    assert _rule_path_traversal_files(_WEB, ["traversal_files ran"], "") is None
