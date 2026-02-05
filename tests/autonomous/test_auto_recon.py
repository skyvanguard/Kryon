"""
Tests for KRYON Auto-Reconnaissance Module
============================================

Tests for autonomous reconnaissance and enumeration capabilities.
"""

from unittest.mock import Mock, patch

import pytest

from kryon.tools.autonomous.auto_recon import (
    _detect_services,
    _enumerate_web,
    _fallback_port_scan,
    _fallback_web_enum,
    _grab_banner,
    _parse_gobuster_output,
    _parse_nmap_output,
    _quick_port_scan,
    _vulnerability_assessment,
    deep_recon,
    full_auto_enumeration,
    quick_recon,
)


class TestFullAutoEnumeration:
    """Test complete autonomous enumeration."""

    @patch("kryon.tools.autonomous.auto_recon._quick_port_scan")
    @patch("kryon.tools.autonomous.auto_recon._detect_services")
    def test_basic_enumeration_success(self, mock_detect, mock_scan):
        """Test basic enumeration completes successfully."""
        # Mock port scan result
        mock_scan.return_value = {
            "success": True,
            "ports": [
                {
                    "port": 80,
                    "service": "http",
                    "version": "Apache 2.4",
                    "state": "open",
                    "protocol": "tcp",
                },
                {
                    "port": 22,
                    "service": "ssh",
                    "version": "OpenSSH 7.6",
                    "state": "open",
                    "protocol": "tcp",
                },
            ],
            "os": {"type": "Linux"},
        }

        # Mock service detection
        mock_detect.return_value = {
            "services": [
                {
                    "name": "http",
                    "port": 80,
                    "version": "Apache 2.4",
                    "banner": None,
                    "protocol": "tcp",
                },
                {
                    "name": "ssh",
                    "port": 22,
                    "version": "OpenSSH 7.6",
                    "banner": "SSH-2.0-OpenSSH_7.6",
                    "protocol": "tcp",
                },
            ]
        }

        result = full_auto_enumeration("10.10.10.5", deep_scan=False, timeout=60)

        assert result["success"] is True
        assert len(result["open_ports"]) == 2
        assert len(result["services_detected"]) == 2
        assert result["os_detection"]["type"] == "Linux"
        assert result["error"] is None

    @patch("kryon.tools.autonomous.auto_recon._quick_port_scan")
    def test_enumeration_no_open_ports(self, mock_scan):
        """Test enumeration when no ports are found."""
        mock_scan.return_value = {"success": False, "ports": [], "os": {}}

        result = full_auto_enumeration("10.10.10.5")

        assert result["success"] is False
        assert result["error"] == "Port scan failed"
        assert len(result["open_ports"]) == 0

    @patch("kryon.tools.autonomous.auto_recon._quick_port_scan")
    @patch("kryon.tools.autonomous.auto_recon._detect_services")
    @patch("kryon.tools.autonomous.auto_recon._enumerate_web")
    def test_web_enumeration_triggered(self, mock_web, mock_detect, mock_scan):
        """Test web enumeration is triggered for HTTP services."""
        mock_scan.return_value = {
            "success": True,
            "ports": [
                {
                    "port": 80,
                    "service": "http",
                    "version": "nginx 1.18",
                    "state": "open",
                    "protocol": "tcp",
                }
            ],
            "os": {},
        }

        mock_detect.return_value = {
            "services": [
                {
                    "name": "http",
                    "port": 80,
                    "version": "nginx 1.18",
                    "banner": None,
                    "protocol": "tcp",
                }
            ]
        }

        mock_web.return_value = {
            "success": True,
            "endpoints": ["http://10.10.10.5:80/admin", "http://10.10.10.5:80/api"],
            "vulnerabilities": [],
        }

        result = full_auto_enumeration("10.10.10.5", deep_scan=False, timeout=300)

        assert result["success"] is True
        assert len(result["http_endpoints"]) == 2
        assert mock_web.called

    @patch("kryon.tools.autonomous.auto_recon._quick_port_scan")
    @patch("kryon.tools.autonomous.auto_recon._detect_services")
    @patch("kryon.tools.autonomous.auto_recon._vulnerability_assessment")
    def test_vulnerability_assessment_in_deep_scan(self, mock_vuln, mock_detect, mock_scan):
        """Test vulnerability assessment runs in deep scan mode."""
        mock_scan.return_value = {
            "success": True,
            "ports": [
                {
                    "port": 80,
                    "service": "http",
                    "version": "Apache 2.4.49",
                    "state": "open",
                    "protocol": "tcp",
                }
            ],
            "os": {},
        }

        mock_detect.return_value = {
            "services": [
                {
                    "name": "http",
                    "port": 80,
                    "version": "Apache 2.4.49",
                    "banner": None,
                    "protocol": "tcp",
                }
            ]
        }

        mock_vuln.return_value = {
            "vulnerabilities": [{"service": "http", "port": 80, "cve": "CVE-2021-41773", "severity": "critical"}]
        }

        result = full_auto_enumeration("10.10.10.5", deep_scan=True, timeout=300)

        assert result["success"] is True
        assert len(result["vulnerabilities"]) == 1
        assert mock_vuln.called


class TestPortScanning:
    """Test port scanning functionality."""

    @patch("subprocess.check_output")
    def test_quick_port_scan_nmap(self, mock_subprocess):
        """Test quick port scan with nmap."""
        nmap_output = """
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.10.10.5
Host is up (0.050s latency).
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.6
80/tcp  open  http    Apache httpd 2.4.49
443/tcp open  https   nginx 1.18
"""
        mock_subprocess.return_value = nmap_output

        result = _quick_port_scan("10.10.10.5", deep=False)

        assert result["success"] is True
        assert len(result["ports"]) == 3
        assert any(p["port"] == 22 and p["service"] == "ssh" for p in result["ports"])
        assert any(p["port"] == 80 and p["service"] == "http" for p in result["ports"])

    def test_parse_nmap_output(self):
        """Test parsing nmap output."""
        nmap_output = """
22/tcp  open  ssh     OpenSSH 7.6
80/tcp  open  http    Apache httpd 2.4.49
443/tcp open  https   nginx 1.18
3306/tcp open mysql   MySQL 5.7.0
"""
        ports = _parse_nmap_output(nmap_output)

        assert len(ports) == 4
        assert ports[0]["port"] == 22
        assert ports[0]["service"] == "ssh"
        assert ports[0]["version"] == "OpenSSH 7.6"
        assert ports[1]["port"] == 80
        assert "Apache" in ports[1]["version"]

    @patch("socket.socket")
    def test_fallback_port_scan(self, mock_socket):
        """Test fallback port scanner when nmap unavailable."""
        # Mock successful connection on port 80
        mock_sock_instance = Mock()
        mock_sock_instance.connect_ex.side_effect = lambda addr: 0 if addr[1] == 80 else 1
        mock_socket.return_value = mock_sock_instance

        result = _fallback_port_scan("10.10.10.5")

        assert result["success"] is True
        assert len(result["ports"]) >= 1
        assert any(p["port"] == 80 for p in result["ports"])

    @patch("subprocess.check_output")
    def test_nmap_timeout(self, mock_subprocess):
        """Test handling of nmap timeout."""
        import subprocess

        mock_subprocess.side_effect = subprocess.TimeoutExpired("nmap", 300)

        result = _quick_port_scan("10.10.10.5")

        assert result["success"] is False
        assert "error" in result


class TestServiceDetection:
    """Test service detection and banner grabbing."""

    def test_detect_services_basic(self):
        """Test basic service detection."""
        ports = [
            {"port": 80, "service": "http", "version": "Apache 2.4", "protocol": "tcp"},
            {"port": 22, "service": "ssh", "version": "OpenSSH 7.6", "protocol": "tcp"},
        ]

        with patch("kryon.tools.autonomous.auto_recon._grab_banner") as mock_banner:
            mock_banner.return_value = "SSH-2.0-OpenSSH_7.6"

            result = _detect_services("10.10.10.5", ports)

            assert len(result["services"]) == 2
            assert result["services"][0]["name"] == "http"
            assert result["services"][0]["port"] == 80

    @patch("socket.socket")
    def test_grab_banner_success(self, mock_socket):
        """Test successful banner grabbing."""
        mock_sock = Mock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_7.6p1\n"
        mock_socket.return_value = mock_sock

        banner = _grab_banner("10.10.10.5", 22, "ssh")

        assert banner == "SSH-2.0-OpenSSH_7.6p1"
        mock_sock.connect.assert_called_once()

    @patch("socket.socket")
    def test_grab_banner_http(self, mock_socket):
        """Test banner grabbing for HTTP service."""
        mock_sock = Mock()
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\nServer: Apache/2.4.49\n"
        mock_socket.return_value = mock_sock

        banner = _grab_banner("10.10.10.5", 80, "http")

        assert "Apache" in banner or "HTTP" in banner
        mock_sock.send.assert_called()

    @patch("socket.socket")
    def test_grab_banner_timeout(self, mock_socket):
        """Test banner grab timeout handling."""
        mock_sock = Mock()
        mock_sock.connect.side_effect = TimeoutError()
        mock_socket.return_value = mock_sock

        banner = _grab_banner("10.10.10.5", 22, "ssh")

        assert banner is None


class TestWebEnumeration:
    """Test web enumeration functionality."""

    @patch("subprocess.check_output")
    def test_enumerate_web_gobuster(self, mock_subprocess):
        """Test web enumeration with gobuster."""
        gobuster_output = """
/admin                (Status: 200) [Size: 1234]
/api                  (Status: 200) [Size: 567]
/login                (Status: 302) [Size: 0]
/.git                 (Status: 403) [Size: 287]
"""
        mock_subprocess.return_value = gobuster_output

        result = _enumerate_web("10.10.10.5", 80, "http", timeout=300)

        assert result["success"] is True
        assert len(result["endpoints"]) >= 3
        assert any("/admin" in ep for ep in result["endpoints"])

    def test_parse_gobuster_output(self):
        """Test parsing gobuster output."""
        gobuster_output = """
/admin                (Status: 200) [Size: 1234]
/api                  (Status: 301) [Size: 567]
/config               (Status: 403) [Size: 0]
"""
        base_url = "http://10.10.10.5:80"

        endpoints = _parse_gobuster_output(gobuster_output, base_url)

        assert len(endpoints) == 3
        assert f"{base_url}/admin" in endpoints
        assert f"{base_url}/api" in endpoints

    @patch("requests.get")
    def test_fallback_web_enum(self, mock_get):
        """Test fallback web enumeration."""

        # Mock responses for common paths
        def mock_response(url, **kwargs):
            response = Mock()
            if "/admin" in url:
                response.status_code = 200
            elif "/api" in url:
                response.status_code = 200
            elif "/.git" in url:
                response.status_code = 200
            else:
                response.status_code = 404
            return response

        mock_get.side_effect = mock_response

        result = _fallback_web_enum("http://10.10.10.5:80")

        assert result["success"] is True
        assert len(result["endpoints"]) >= 2
        # Should detect exposed .git
        assert len(result["vulnerabilities"]) >= 1

    @patch("subprocess.check_output")
    def test_web_enum_timeout(self, mock_subprocess):
        """Test web enumeration timeout handling."""
        import subprocess

        mock_subprocess.side_effect = subprocess.TimeoutExpired("gobuster", 300)

        result = _enumerate_web("10.10.10.5", 80, "http", timeout=60)

        # Should fall back to basic enumeration
        assert isinstance(result, dict)


class TestVulnerabilityAssessment:
    """Test vulnerability assessment functionality."""

    def test_vulnerability_assessment_apache(self):
        """Test vulnerability detection for Apache 2.4.49."""
        services = [{"name": "http", "port": 80, "version": "Apache 2.4.49", "banner": None}]

        result = _vulnerability_assessment("10.10.10.5", services)

        assert len(result["vulnerabilities"]) >= 1
        vuln = result["vulnerabilities"][0]
        assert vuln["cve"] == "CVE-2021-41773"
        assert vuln["severity"] == "critical"
        assert vuln["service"] == "http"

    def test_vulnerability_assessment_openssh(self):
        """Test vulnerability detection for OpenSSH."""
        services = [{"name": "ssh", "port": 22, "version": "OpenSSH 7.6", "banner": None}]

        result = _vulnerability_assessment("10.10.10.5", services)

        assert len(result["vulnerabilities"]) >= 1
        vuln = result["vulnerabilities"][0]
        assert "CVE" in vuln["cve"]
        assert vuln["service"] == "ssh"

    def test_vulnerability_assessment_no_vulns(self):
        """Test when no known vulnerabilities found."""
        services = [{"name": "http", "port": 80, "version": "Apache 2.4.52", "banner": None}]

        result = _vulnerability_assessment("10.10.10.5", services)

        # Should not find vulnerabilities for patched version
        assert len(result["vulnerabilities"]) == 0

    def test_vulnerability_assessment_multiple_services(self):
        """Test assessment with multiple vulnerable services."""
        services = [
            {"name": "http", "port": 80, "version": "Apache 2.4.49", "banner": None},
            {"name": "ssh", "port": 22, "version": "OpenSSH 7.6", "banner": None},
            {"name": "mysql", "port": 3306, "version": "MySQL 5.7", "banner": None},
        ]

        result = _vulnerability_assessment("10.10.10.5", services)

        # Should find vulnerabilities in multiple services
        assert len(result["vulnerabilities"]) >= 2


class TestConvenienceFunctions:
    """Test convenience wrapper functions."""

    @patch("kryon.tools.autonomous.auto_recon.full_auto_enumeration")
    def test_quick_recon(self, mock_full):
        """Test quick_recon wrapper."""
        mock_full.return_value = {"success": True}

        result = quick_recon("10.10.10.5")

        mock_full.assert_called_once_with("10.10.10.5", deep_scan=False, timeout=300)
        assert result["success"] is True

    @patch("kryon.tools.autonomous.auto_recon.full_auto_enumeration")
    def test_deep_recon(self, mock_full):
        """Test deep_recon wrapper."""
        mock_full.return_value = {"success": True}

        result = deep_recon("10.10.10.5")

        mock_full.assert_called_once_with("10.10.10.5", deep_scan=True, timeout=1800)
        assert result["success"] is True


class TestEdgeCases:
    """Test edge cases and error handling."""

    @patch("kryon.tools.autonomous.auto_recon._quick_port_scan")
    def test_exception_handling(self, mock_scan):
        """Test exception handling in enumeration."""
        mock_scan.side_effect = Exception("Network error")

        result = full_auto_enumeration("10.10.10.5")

        assert result["success"] is False
        assert result["error"] == "Network error"
        assert result["enumeration_time"] >= 0

    def test_empty_nmap_output(self):
        """Test parsing empty nmap output."""
        ports = _parse_nmap_output("")

        assert len(ports) == 0

    def test_malformed_nmap_output(self):
        """Test parsing malformed nmap output."""
        malformed_output = "This is not valid nmap output"

        ports = _parse_nmap_output(malformed_output)

        # Should handle gracefully
        assert isinstance(ports, list)

    @patch("socket.socket")
    def test_fallback_scan_all_ports_closed(self, mock_socket):
        """Test fallback scanner when all ports are closed."""
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 1  # Connection refused
        mock_socket.return_value = mock_sock

        result = _fallback_port_scan("10.10.10.5")

        assert result["success"] is False
        assert len(result["ports"]) == 0


class TestPerformance:
    """Test performance characteristics."""

    @patch("kryon.tools.autonomous.auto_recon._enumerate_web")  # Correct function name
    @patch("kryon.tools.autonomous.auto_recon._quick_port_scan")
    @patch("kryon.tools.autonomous.auto_recon._detect_services")
    def test_timeout_respected(self, mock_detect, mock_scan, mock_web):
        """Test that timeout is respected."""
        import time

        mock_scan.return_value = {
            "success": True,
            "ports": [
                {
                    "port": 80,
                    "service": "http",
                    "version": "Apache 2.4",
                    "state": "open",
                    "protocol": "tcp",
                }
            ],
            "os": {},
        }

        mock_detect.return_value = {"services": []}
        mock_web.return_value = {"directories": [], "files": []}  # Mock web enum to avoid gobuster

        start = time.time()
        result = full_auto_enumeration("10.10.10.5", timeout=2)
        elapsed = time.time() - start

        # Should complete within timeout (with some margin)
        assert elapsed < 5
        assert result["enumeration_time"] < 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
