"""Deterministic version→CVE→exploit correlation engine."""

from __future__ import annotations

from kryon.cli.version_cve import correlate, correlate_banner, parse_version


def _cves(banner):
    return {h.cve for h in correlate(banner)}


def test_parse_version():
    assert parse_version("Apache Tomcat/7.0.34") == (7, 0, 34)
    assert parse_version("OpenSSH_9.6p1") == (9, 6)
    assert parse_version("no version here") is None


def test_openssh_regresshion_in_range():
    assert "CVE-2024-6387" in _cves("SSH-2.0-OpenSSH_9.6p1")


def test_openssh_out_of_range():
    assert "CVE-2024-6387" not in _cves("SSH-2.0-OpenSSH_9.8p1")


def test_tomcat_ghostcat():
    assert "CVE-2020-1938" in _cves("Apache Tomcat/7.0.34")


def test_vsftpd_backdoor():
    hits = correlate("vsftpd 2.3.4")
    assert any(h.cve == "CVE-2011-2523" and h.exploit for h in hits)


def test_apache_path_traversal_exact_version():
    assert "CVE-2021-41773" in _cves("Apache/2.4.49 (Unix)")
    assert "CVE-2021-41773" not in _cves("Apache/2.4.48 (Unix)")


def test_proftpd_modcopy():
    assert "CVE-2015-3306" in _cves("ProFTPD 1.3.5")


def test_no_version_no_hits():
    assert correlate("nginx") == []


def test_product_mismatch_no_hit():
    # Tomcat CVE shouldn't match an nginx banner even if the version is in range.
    assert "CVE-2020-1938" not in _cves("nginx/7.0.34")


def test_to_findings_shape():
    out = correlate_banner("Apache Tomcat/7.0.34", "10.0.0.9", 8080)
    assert out and out[0].rule_id == "cve-cve-2020-1938" and out[0].cwe == "CWE-1395"
    assert "exploit público" in out[0].message and "10.0.0.9" in out[0].message


def test_correlate_banner_graceful_on_junk():
    assert correlate_banner("", "h", 1) == []
