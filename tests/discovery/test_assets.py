"""F139 — Asset discovery tests."""

from __future__ import annotations

import json
from unittest.mock import patch

from kryon.discovery.assets import (
    DiscoveredAsset,
    DiscoveryReport,
    discover_cloud_assets,
    discover_subdomains,
    discover_subnet,
    is_valid_target,
    merge_assets,
)

# ---------------------------------------------------------------------------
# DiscoveredAsset + DiscoveryReport
# ---------------------------------------------------------------------------


def test_asset_to_dict():
    a = DiscoveredAsset(target="1.2.3.4", kind="host", source="nmap")
    d = a.to_dict()
    assert d["target"] == "1.2.3.4"
    assert d["kind"] == "host"


def test_report_to_dict():
    r = DiscoveryReport(assets=[DiscoveredAsset(target="a.example.com", kind="subdomain", source="crt.sh")])
    d = r.to_dict()
    assert d["count"] == 1
    assert d["assets"][0]["target"] == "a.example.com"


def test_report_to_targets_dedupes_and_preserves_order():
    r = DiscoveryReport(
        assets=[
            DiscoveredAsset(target="a", kind="host", source="nmap"),
            DiscoveredAsset(target="b", kind="subdomain", source="crt.sh"),
            DiscoveredAsset(target="a", kind="subdomain", source="crt.sh"),  # dup target
        ]
    )
    targets = r.to_targets()
    assert targets == ["a", "b"]


# ---------------------------------------------------------------------------
# discover_subnet (nmap parsing)
# ---------------------------------------------------------------------------


_FAKE_NMAP_OUTPUT = """\
Starting Nmap 7.94 ( https://nmap.org ) at 2026-05-14 18:00 UTC
Nmap scan report for 192.168.1.1
Host is up.
Nmap scan report for gateway.local (192.168.1.254)
Host is up.
Nmap done: 256 IP addresses (2 hosts up) scanned in 5.20 seconds
"""


def _fake_run_ok(*args, **kwargs):
    class _R:
        stdout = _FAKE_NMAP_OUTPUT
        returncode = 0

    return _R()


def _fake_run_timeout(*args, **kwargs):
    raise __import__("subprocess").TimeoutExpired(cmd="nmap", timeout=1)


def test_subnet_parses_ips_and_hostnames():
    with patch("kryon.discovery.assets.subprocess.run", side_effect=_fake_run_ok):
        result = discover_subnet("192.168.1.0/24")
    assert len(result) == 2
    ips = {a.target for a in result}
    assert ips == {"192.168.1.1", "192.168.1.254"}
    # Hostname captured in extra.
    gw = next(a for a in result if a.target == "192.168.1.254")
    assert gw.extra["hostname"] == "gateway.local"


def test_subnet_returns_empty_on_timeout():
    with patch("kryon.discovery.assets.subprocess.run", side_effect=_fake_run_timeout):
        result = discover_subnet("192.168.1.0/24", timeout_s=1)
    assert result == []


def test_subnet_skips_cidr_header_lines():
    output = "Nmap scan report for 192.168.1.0/24\nNmap scan report for 10.0.0.5\n"
    with patch(
        "kryon.discovery.assets.subprocess.run",
        side_effect=lambda *a, **k: type("R", (), {"stdout": output, "returncode": 0})(),
    ):
        result = discover_subnet("192.168.1.0/24")
    targets = {a.target for a in result}
    assert "10.0.0.5" in targets
    assert "192.168.1.0/24" not in targets


# ---------------------------------------------------------------------------
# discover_subdomains (crt.sh)
# ---------------------------------------------------------------------------


_FAKE_CRT_JSON = json.dumps(
    [
        {"name_value": "www.example.com\ncashbox.example.com"},
        {"name_value": "*.example.com"},
        {"name_value": "admin.example.com"},
    ]
).encode("utf-8")


def _fake_urlopen_crt(*args, **kwargs):
    class _R:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return _FAKE_CRT_JSON

    return _R()


def _fake_urlopen_error(*args, **kwargs):
    raise __import__("urllib.error").error.URLError("network down")


def test_subdomains_dedupes_and_skips_wildcards():
    with patch("kryon.discovery.assets.urllib.request.urlopen", side_effect=_fake_urlopen_crt):
        result = discover_subdomains("example.com")
    targets = {a.target for a in result}
    assert "www.example.com" in targets
    assert "cashbox.example.com" in targets
    assert "admin.example.com" in targets
    assert "*.example.com" not in targets  # wildcard skipped


def test_subdomains_empty_domain_returns_empty():
    assert discover_subdomains("") == []


def test_subdomains_network_error_returns_empty():
    with patch("kryon.discovery.assets.urllib.request.urlopen", side_effect=_fake_urlopen_error):
        assert discover_subdomains("x.com") == []


# ---------------------------------------------------------------------------
# Cloud + merge
# ---------------------------------------------------------------------------


def test_cloud_assets_stub_returns_empty():
    assert discover_cloud_assets() == []


def test_merge_dedupes_by_target_and_kind():
    a = [DiscoveredAsset(target="x", kind="host", source="nmap")]
    b = [
        DiscoveredAsset(target="x", kind="host", source="nmap"),  # dup
        DiscoveredAsset(target="x", kind="subdomain", source="crt.sh"),  # different kind ok
    ]
    report = merge_assets(a, b)
    assert len(report.assets) == 2
    kinds = {asset.kind for asset in report.assets}
    assert kinds == {"host", "subdomain"}


def test_merge_empty_lists_returns_empty_report():
    report = merge_assets([], [])
    assert report.assets == []
    assert report.to_dict()["count"] == 0


# ---------------------------------------------------------------------------
# is_valid_target
# ---------------------------------------------------------------------------


def test_valid_ip():
    assert is_valid_target("1.2.3.4") is True


def test_valid_cidr():
    assert is_valid_target("10.0.0.0/24") is True


def test_valid_hostname():
    assert is_valid_target("www.example.com") is True


def test_invalid_empty():
    assert is_valid_target("") is False


def test_invalid_no_dots():
    assert is_valid_target("localhost") is False


def test_invalid_cidr_mask():
    assert is_valid_target("1.2.3.4/99") is False


def test_invalid_whitespace():
    assert is_valid_target("with space") is False
