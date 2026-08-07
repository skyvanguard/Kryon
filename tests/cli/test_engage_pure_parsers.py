"""Pure-function coverage for engage.py parsers/detectors.

engage.py is ~5.7k lines and largely untested. These target the *pure*
building blocks (deterministic input → output, no network / LLM / subprocess
/ filesystem): the nmap XML parser, the semver parser, and the EOL
web-server detector. They are used by the discovery + Phase-2 check paths.
"""

from __future__ import annotations

import pytest

from kryon.cli.engage import (
    DiscoveredService,
    _check_webserver_eol,
    _parse_nmap_xml,
    _parse_semver,
)

# --- _parse_semver -----------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (("1", "14", "0"), (1, 14, 0)),
        (("1", "14", None), (1, 14, 0)),  # patch defaults to 0
        (("9", None, None), (9, 0, 0)),  # minor + patch default
        (("2", "4", ""), (2, 4, 0)),  # empty patch (IIS-style banner) → 0
        ((None, None, None), None),  # banner without any version
        (("nginx", "14", "0"), None),  # unparsable major → None (no raise)
    ],
)
def test_parse_semver(args, expected):
    assert _parse_semver(*args) == expected


# --- _parse_nmap_xml ---------------------------------------------------------

_NMAP_XML = """<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="HTTP" product="nginx" version="1.14.0"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


@pytest.mark.unit
def test_parse_nmap_xml_extracts_services():
    services = _parse_nmap_xml(_NMAP_XML, "192.0.2.5")
    assert len(services) == 2

    ssh, http = services
    assert (ssh.host, ssh.port, ssh.state) == ("192.0.2.5", 22, "open")
    assert (ssh.service, ssh.product, ssh.version) == ("ssh", "OpenSSH", "7.4")
    # service name is lower-cased even when the banner reports "HTTP".
    assert http.service == "http"
    assert (http.product, http.version) == ("nginx", "1.14.0")


@pytest.mark.unit
def test_parse_nmap_xml_no_ports_returns_empty():
    assert _parse_nmap_xml("<nmaprun></nmaprun>", "10.0.0.1") == []


@pytest.mark.unit
def test_parse_nmap_xml_port_without_service_attrs():
    xml = '<port protocol="tcp" portid="3306"><state state="filtered"/></port>'
    services = _parse_nmap_xml(xml, "10.0.0.9")
    assert len(services) == 1
    svc = services[0]
    assert svc.port == 3306
    assert svc.state == "filtered"
    assert svc.service == "" and svc.product == "" and svc.version == ""


# --- _check_webserver_eol ----------------------------------------------------


def _http_svc():
    return DiscoveredService(host="10.0.0.5", port=80, state="open", service="http")


@pytest.mark.unit
def test_eol_flags_outdated_apache():
    # Apache 2.4.52 < min supported 2.4.62 → HIGH EOL finding.
    finding = _check_webserver_eol(_http_svc(), "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n")
    assert finding is not None
    assert finding.severity == "HIGH"
    assert finding.cwe == "CWE-1104"
    assert finding.host == "10.0.0.5:80"
    assert finding.rule_id == "apache-httpd-version-eol"
    assert "2.4.52" in (finding.message + finding.evidence)


@pytest.mark.unit
def test_eol_passes_supported_apache():
    finding = _check_webserver_eol(_http_svc(), "Server: Apache/2.4.62\r\n")
    assert finding is None


@pytest.mark.unit
def test_eol_no_server_header_returns_none():
    finding = _check_webserver_eol(_http_svc(), "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n")
    assert finding is None


@pytest.mark.unit
def test_eol_server_without_version_returns_none():
    # Banner present but no parseable version → no EOL claim.
    finding = _check_webserver_eol(_http_svc(), "Server: nginx\r\n")
    assert finding is None
