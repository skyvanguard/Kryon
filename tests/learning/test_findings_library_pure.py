"""Pure tests for kryon.learning.findings_library helpers.

`url_shape` and the content-fingerprint logic are deterministic and
don't touch ChromaDB. They run in any environment, no extras required.

The DB-backed surface (add_finding, recall_similar, etc.) lives in
`test_findings_library.py` with `pytest.importorskip("chromadb")`.
"""

from __future__ import annotations

import pytest

from kryon.learning.findings_library import _content_fingerprint, url_shape

# ---------- url_shape: integer-id normalization ----------


def test_url_shape_normalizes_integer_id_segments() -> None:
    assert url_shape("https://bank.com/api/account/12345") == "/api/account/<int>"


def test_url_shape_keeps_named_segments() -> None:
    assert url_shape("https://bank.com/api/account/list") == "/api/account/list"


# ---------- url_shape: UUID normalization ----------


def test_url_shape_normalizes_uuid_segment() -> None:
    url = "https://bank.com/user/550e8400-e29b-41d4-a716-446655440000/profile"
    assert url_shape(url) == "/user/<uuid>/profile"


# ---------- url_shape: hex token normalization ----------


def test_url_shape_normalizes_long_hex_token() -> None:
    # 16+ hex chars → <hex>
    url = "https://api.example.com/session/abcdef0123456789abcdef/details"
    assert url_shape(url) == "/session/<hex>/details"


def test_url_shape_short_hex_left_alone() -> None:
    # < 16 chars → not classified as hex token
    assert url_shape("https://x.com/v1/abc123") == "/v1/abc123"


# ---------- url_shape: mixed alnum (account/order ids) ----------


def test_url_shape_normalizes_mixed_alnum_with_long_numeric_run() -> None:
    """Common LATAM banking shape: acct_12345 → acct_<n>."""
    assert url_shape("https://bank.com/cuentas/acct_98765/detalle") == "/cuentas/acct_<n>/detalle"


def test_url_shape_keeps_short_numeric_in_versions() -> None:
    # API version (`v1`, `v2`) — only 1-3 digits, NOT masked.
    assert url_shape("https://api.bank.com/v1/users") == "/v1/users"
    assert url_shape("https://api.bank.com/v2/users/100") == "/v2/users/<int>"


# ---------- url_shape: query parameters ----------


def test_url_shape_masks_query_param_values() -> None:
    assert url_shape("https://shop.com/search?q=test&page=2") == "/search?q=<n>&page=<n>"


def test_url_shape_handles_query_param_without_value() -> None:
    assert url_shape("https://x.com/a?flag&q=1") == "/a?flag&q=<n>"


def test_url_shape_path_only_no_query() -> None:
    assert url_shape("https://x.com/api/users") == "/api/users"


# ---------- url_shape: edge cases ----------


def test_url_shape_returns_input_on_unparseable() -> None:
    # urlparse is lenient; truly malformed strings degrade gracefully.
    out = url_shape("not a url at all")
    # Not a hard contract — just must not crash.
    assert isinstance(out, str)


def test_url_shape_root_only() -> None:
    assert url_shape("https://x.com/") == "/"


def test_url_shape_normalizes_consistently_across_hosts() -> None:
    """Two findings on different banks but same path shape collapse."""
    a = url_shape("https://bcp.com.py/api/account/12345")
    b = url_shape("https://citibank.com/api/account/67890")
    assert a == b == "/api/account/<int>"


# ---------- content fingerprint determinism ----------


def test_fingerprint_is_deterministic_for_same_inputs() -> None:
    finding = {
        "cwe_id": "CWE-89",
        "probe_id": "sqli-union",
        "url": "https://x.com/api/u/100",
        "host": "x.com",
    }
    assert _content_fingerprint(finding) == _content_fingerprint(finding)


def test_fingerprint_collapses_same_url_shape() -> None:
    """Same CWE + probe + url_shape + host = same fingerprint = dedup."""
    a = {"cwe_id": "CWE-89", "probe_id": "p", "url": "https://x.com/u/1", "host": "x.com"}
    b = {"cwe_id": "CWE-89", "probe_id": "p", "url": "https://x.com/u/2", "host": "x.com"}
    # Different ints in the URL — but url_shape collapses them, so same fp.
    assert _content_fingerprint(a) == _content_fingerprint(b)


def test_fingerprint_different_when_cwe_differs() -> None:
    a = {"cwe_id": "CWE-89", "probe_id": "p", "url": "https://x.com/u", "host": "x.com"}
    b = {"cwe_id": "CWE-79", "probe_id": "p", "url": "https://x.com/u", "host": "x.com"}
    assert _content_fingerprint(a) != _content_fingerprint(b)


def test_fingerprint_different_when_host_differs() -> None:
    a = {"cwe_id": "CWE-89", "probe_id": "p", "url": "https://x.com/u", "host": "x.com"}
    b = {"cwe_id": "CWE-89", "probe_id": "p", "url": "https://x.com/u", "host": "y.com"}
    assert _content_fingerprint(a) != _content_fingerprint(b)


def test_fingerprint_format() -> None:
    fp = _content_fingerprint({"cwe_id": "CWE-89", "host": "x.com"})
    assert fp.startswith("fnd_")
    assert len(fp) == 4 + 14  # "fnd_" + 14 hex chars
