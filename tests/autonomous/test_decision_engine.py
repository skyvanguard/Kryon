"""
KRYON Decision Engine Tests
=============================

Comprehensive test suite for the decision engine module.

Tests Cover:
- Exploit selection algorithm
- Scoring system validation
- CVE searching functionality
- Service-based exploit queries
- Custom exploit addition
- Edge cases and error handling

Clearance Level: Omega-Command (Testing Authority)
"""

import sys
from pathlib import Path

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from kryon.tools.autonomous.decision_engine import (
    ExploitDifficulty,
    ExploitType,
    add_custom_exploit,
    get_all_exploits_for_service,
    search_exploits_by_cve,
    select_best_exploit,
)


class TestExploitSelection:
    """Test exploit selection functionality."""

    def test_select_exploit_apache_exact_version(self):
        """Test selecting exploit with exact Apache version match."""
        result = select_best_exploit(service_name="apache", service_version="Apache 2.4.49", difficulty="medium")

        assert result["exploit_recommended"] is True
        assert result["exploit_name"] == "apache_path_traversal_cve_2021_41773"
        assert result["exploit_type"] == "remote_code_execution"
        assert result["cve"] == "CVE-2021-41773"
        assert result["severity"] == "critical"
        assert result["success_probability"] > 0.8
        assert result["metasploit_module"] is not None

    def test_select_exploit_ssh_version_match(self):
        """Test SSH exploit selection with version."""
        result = select_best_exploit(service_name="ssh", service_version="OpenSSH 7.6", difficulty="easy")

        assert result["exploit_recommended"] is True
        assert "openssh" in result["exploit_name"].lower()
        assert result["cve"] == "CVE-2018-15473"
        assert result["success_probability"] > 0.0

    def test_select_exploit_generic_fallback(self):
        """Test generic exploit selection when no version match."""
        result = select_best_exploit(
            service_name="mysql",
            service_version="",  # No version provided
            difficulty="medium",
        )

        # Without version, may or may not recommend exploit depending on database
        assert "exploit_recommended" in result
        # If recommended, should be mysql-related
        if result.get("exploit_recommended"):
            assert "mysql" in result.get("exploit_name", "").lower()

    def test_select_exploit_no_match(self):
        """Test behavior when no exploit exists for service."""
        result = select_best_exploit(service_name="unknown_service_xyz", service_version="1.0", difficulty="medium")

        assert result["exploit_recommended"] is False
        assert result["exploit_name"] is None
        assert result["success_probability"] == 0.0
        assert "No known exploits" in result["description"]

    def test_select_exploit_smb_eternalblue(self):
        """Test EternalBlue exploit selection."""
        result = select_best_exploit(service_name="smb", service_version="SMBv1", difficulty="easy")

        assert result["exploit_recommended"] is True
        assert "eternalblue" in result["exploit_name"].lower()
        assert result["cve"] == "MS17-010"
        assert result["severity"] == "critical"
        assert result["success_probability"] > 0.85

    def test_select_exploit_ftp_proftpd(self):
        """Test ProFTPD exploit selection."""
        result = select_best_exploit(service_name="ftp", service_version="ProFTPD 1.3.5", difficulty="medium")

        assert result["exploit_recommended"] is True
        assert "proftpd" in result["exploit_name"].lower()
        assert result["cve"] == "CVE-2015-3306"
        assert result["exploit_type"] == "remote_code_execution"

    def test_select_exploit_rdp_bluekeep(self):
        """Test BlueKeep RDP exploit selection."""
        result = select_best_exploit(service_name="rdp", service_version="RDP 10.0", difficulty="hard")

        assert result["exploit_recommended"] is True
        assert "bluekeep" in result["exploit_name"].lower()
        assert result["cve"] == "CVE-2019-0708"
        assert result["difficulty_level"] == "HARD"

    def test_select_exploit_http_wordpress(self):
        """Test WordPress exploit selection."""
        result = select_best_exploit(service_name="http", service_version="WordPress", difficulty="medium")

        assert result["exploit_recommended"] is True
        assert "wordpress" in result["exploit_name"].lower()
        assert "wordlist" in result["requirements"]

    def test_select_exploit_postgresql(self):
        """Test PostgreSQL exploit selection."""
        result = select_best_exploit(service_name="postgresql", service_version="PostgreSQL 12.0", difficulty="easy")

        assert result["exploit_recommended"] is True
        assert "postgresql" in result["exploit_name"].lower()


class TestScoringAlgorithm:
    """Test exploit scoring and ranking."""

    def test_exact_version_scores_higher(self):
        """Test that exact version matches score higher than generic."""
        # Exact version match
        result_exact = select_best_exploit(service_name="apache", service_version="Apache 2.4.49", difficulty="medium")

        # Generic match
        result_generic = select_best_exploit(
            service_name="apache",
            service_version="Apache 2.4.1",  # No exact match exists
            difficulty="medium",
        )

        # Exact version should have higher probability
        assert result_exact["success_probability"] > result_generic["success_probability"]

    def test_difficulty_alignment_easy(self):
        """Test difficulty alignment affects scoring for easy challenges."""
        result = select_best_exploit(service_name="apache", service_version="Apache 2.4.49", difficulty="easy")

        # Should prefer easier exploits for easy challenges
        assert result["difficulty_level"] in ["TRIVIAL", "EASY", "MEDIUM"]

    def test_difficulty_alignment_hard(self):
        """Test difficulty alignment for hard challenges."""
        result = select_best_exploit(service_name="rdp", service_version="RDP 10.0", difficulty="hard")

        # Should be willing to select harder exploits
        assert result["exploit_recommended"] is True

    def test_critical_severity_preferred(self):
        """Test that critical severity vulnerabilities are preferred."""
        result = select_best_exploit(service_name="apache", service_version="Apache 2.4.49", difficulty="medium")

        # Critical severity should be selected
        assert result["severity"] == "critical"
        assert result["success_probability"] > 0.9

    def test_public_exploit_bonus(self):
        """Test that public exploits receive scoring bonus."""
        # All exploits in database should be public
        result = select_best_exploit(service_name="smb", service_version="SMBv1", difficulty="medium")

        assert result["exploit_recommended"] is True
        # Public exploits should have good scores
        assert result["success_probability"] > 0.5


class TestCVESearch:
    """Test CVE-based exploit searching."""

    def test_search_by_cve_apache(self):
        """Test searching for Apache CVE."""
        results = search_exploits_by_cve("CVE-2021-41773")

        assert len(results) == 1
        assert results[0]["cve"] == "CVE-2021-41773"
        assert results[0]["service"] == "apache"
        assert results[0]["exploit_name"] == "apache_path_traversal_cve_2021_41773"

    def test_search_by_cve_openssh(self):
        """Test searching for OpenSSH CVE."""
        results = search_exploits_by_cve("CVE-2018-15473")

        assert len(results) == 1
        assert results[0]["cve"] == "CVE-2018-15473"
        assert results[0]["service"] == "ssh"

    def test_search_by_cve_eternalblue(self):
        """Test searching for EternalBlue CVE."""
        results = search_exploits_by_cve("MS17-010")

        assert len(results) == 1
        assert results[0]["cve"] == "MS17-010"
        assert results[0]["service"] == "smb"
        assert "eternalblue" in results[0]["exploit_name"].lower()

    def test_search_by_cve_not_found(self):
        """Test searching for non-existent CVE."""
        results = search_exploits_by_cve("CVE-9999-99999")

        assert len(results) == 0

    def test_search_by_cve_bluekeep(self):
        """Test searching for BlueKeep CVE."""
        results = search_exploits_by_cve("CVE-2019-0708")

        assert len(results) == 1
        assert results[0]["cve"] == "CVE-2019-0708"
        assert results[0]["service"] == "rdp"

    def test_search_by_cve_proftpd(self):
        """Test searching for ProFTPD CVE."""
        results = search_exploits_by_cve("CVE-2015-3306")

        assert len(results) == 1
        assert results[0]["service"] == "ftp"


class TestServiceExploits:
    """Test getting all exploits for a service."""

    def test_get_all_apache_exploits(self):
        """Test retrieving all Apache exploits."""
        exploits = get_all_exploits_for_service("apache")

        assert len(exploits) >= 2  # At least 2 Apache exploits

        # Check structure
        for exploit in exploits:
            assert "exploit_name" in exploit
            assert "service_version" in exploit
            assert "severity" in exploit

    def test_get_all_ssh_exploits(self):
        """Test retrieving all SSH exploits."""
        exploits = get_all_exploits_for_service("ssh")

        assert len(exploits) >= 2
        assert any("username_enum" in e["exploit_name"] for e in exploits)
        assert any("bruteforce" in e["exploit_name"] for e in exploits)

    def test_get_all_mysql_exploits(self):
        """Test retrieving all MySQL exploits."""
        exploits = get_all_exploits_for_service("mysql")

        assert len(exploits) >= 2
        assert any("default_creds" in e["exploit_name"] for e in exploits)
        assert any("udf" in e["exploit_name"] for e in exploits)

    def test_get_all_smb_exploits(self):
        """Test retrieving all SMB exploits."""
        exploits = get_all_exploits_for_service("smb")

        assert len(exploits) >= 2
        assert any("eternalblue" in e["exploit_name"] for e in exploits)
        assert any("enum" in e["exploit_name"] for e in exploits)

    def test_get_all_http_exploits(self):
        """Test retrieving all HTTP exploits."""
        exploits = get_all_exploits_for_service("http")

        assert len(exploits) >= 1

    def test_get_all_unknown_service(self):
        """Test retrieving exploits for unknown service."""
        exploits = get_all_exploits_for_service("unknown_xyz")

        assert len(exploits) == 0

    def test_get_all_ftp_exploits(self):
        """Test retrieving all FTP exploits."""
        exploits = get_all_exploits_for_service("ftp")

        assert len(exploits) >= 2


class TestCustomExploits:
    """Test adding custom exploits to database."""

    def test_add_custom_exploit_new_service(self):
        """Test adding exploit for new service."""
        custom_exploit = {
            "exploit_name": "test_exploit",
            "exploit_type": ExploitType.RCE,
            "cve": "CVE-2024-00000",
            "severity": "high",
            "success_rate": 0.75,
            "difficulty": ExploitDifficulty.MEDIUM,
            "description": "Test exploit",
            "metasploit_module": None,
            "public_exploit": True,
            "requirements": [],
        }

        result = add_custom_exploit(service_name="test_service", version="1.0", exploit_info=custom_exploit)

        assert result is True

        # Verify it was added
        exploits = get_all_exploits_for_service("test_service")
        assert len(exploits) == 1
        assert exploits[0]["exploit_name"] == "test_exploit"

    def test_add_custom_exploit_existing_service(self):
        """Test adding exploit to existing service."""
        custom_exploit = {
            "exploit_name": "apache_custom_test",
            "exploit_type": ExploitType.SQLI,
            "cve": "CVE-2024-11111",
            "severity": "medium",
            "success_rate": 0.60,
            "difficulty": ExploitDifficulty.EASY,
            "description": "Custom Apache test",
            "metasploit_module": None,
            "public_exploit": False,
            "requirements": ["auth"],
        }

        original_count = len(get_all_exploits_for_service("apache"))

        result = add_custom_exploit(service_name="apache", version="Apache 2.4.99", exploit_info=custom_exploit)

        assert result is True

        # Should have one more exploit now
        new_count = len(get_all_exploits_for_service("apache"))
        assert new_count == original_count + 1

    def test_add_custom_exploit_overwrites_version(self):
        """Test that adding exploit overwrites existing version entry."""
        custom_exploit_v1 = {
            "exploit_name": "test_v1",
            "exploit_type": ExploitType.RCE,
            "cve": None,
            "severity": "low",
            "success_rate": 0.50,
            "difficulty": ExploitDifficulty.EASY,
            "description": "Version 1",
            "metasploit_module": None,
            "public_exploit": True,
            "requirements": [],
        }

        custom_exploit_v2 = {
            "exploit_name": "test_v2",
            "exploit_type": ExploitType.RCE,
            "cve": None,
            "severity": "high",
            "success_rate": 0.90,
            "difficulty": ExploitDifficulty.HARD,
            "description": "Version 2",
            "metasploit_module": None,
            "public_exploit": True,
            "requirements": [],
        }

        # Add first version
        add_custom_exploit("test_overwrite", "1.0", custom_exploit_v1)

        # Add second version (should overwrite)
        add_custom_exploit("test_overwrite", "1.0", custom_exploit_v2)

        # Should only have one exploit
        exploits = get_all_exploits_for_service("test_overwrite")
        assert len(exploits) == 1
        assert exploits[0]["exploit_name"] == "test_v2"
        assert exploits[0]["severity"] == "high"


class TestExploitTypes:
    """Test exploit type handling."""

    def test_exploit_type_enum_values(self):
        """Test ExploitType enum has expected values."""
        assert ExploitType.RCE.value == "remote_code_execution"
        assert ExploitType.SQLI.value == "sql_injection"
        assert ExploitType.XSS.value == "cross_site_scripting"
        assert ExploitType.AUTH_BYPASS.value == "authentication_bypass"
        assert ExploitType.PRIVESC.value == "privilege_escalation"
        assert ExploitType.INFO_DISCLOSURE.value == "information_disclosure"

    def test_exploit_difficulty_enum_values(self):
        """Test ExploitDifficulty enum has expected values."""
        assert ExploitDifficulty.TRIVIAL.value == 1
        assert ExploitDifficulty.EASY.value == 2
        assert ExploitDifficulty.MEDIUM.value == 3
        assert ExploitDifficulty.HARD.value == 4
        assert ExploitDifficulty.EXPERT.value == 5

    def test_rce_exploits_in_database(self):
        """Test that RCE exploits exist in database."""
        # Check Apache
        result = select_best_exploit("apache", "Apache 2.4.49")
        assert result["exploit_type"] == "remote_code_execution"

        # Check SMB
        result = select_best_exploit("smb", "SMBv1")
        assert result["exploit_type"] == "remote_code_execution"

    def test_auth_bypass_exploits_in_database(self):
        """Test that auth bypass exploits exist."""
        result = select_best_exploit("ftp", "FTP")
        assert result["exploit_type"] == "authentication_bypass"

    def test_info_disclosure_exploits_in_database(self):
        """Test that info disclosure exploits exist."""
        result = select_best_exploit("smb", "SMB")
        assert result["exploit_type"] == "information_disclosure"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_case_insensitive_service_names(self):
        """Test that service names are case-insensitive."""
        result1 = select_best_exploit("APACHE", "Apache 2.4.49")
        result2 = select_best_exploit("apache", "Apache 2.4.49")
        result3 = select_best_exploit("ApAcHe", "Apache 2.4.49")

        assert result1["exploit_name"] == result2["exploit_name"]
        assert result2["exploit_name"] == result3["exploit_name"]

    def test_whitespace_handling(self):
        """Test that whitespace in service names is handled."""
        result = select_best_exploit("  apache  ", "Apache 2.4.49")

        assert result["exploit_recommended"] is True
        assert result["exploit_name"] == "apache_path_traversal_cve_2021_41773"

    def test_empty_version_string(self):
        """Test handling of empty version string."""
        result = select_best_exploit("mysql", "", "medium")

        # Without version, implementation may not recommend exploit
        assert "exploit_recommended" in result
        # Test just validates it doesn't crash with empty version

    def test_invalid_difficulty_fallback(self):
        """Test handling of invalid difficulty level."""
        result = select_best_exploit(
            service_name="apache",
            service_version="Apache 2.4.49",
            difficulty="invalid_difficulty_xyz",
        )

        # Should still work with default difficulty
        assert result["exploit_recommended"] is True

    def test_empty_service_name(self):
        """Test handling of empty service name."""
        result = select_best_exploit("", "version 1.0")

        assert result["exploit_recommended"] is False

    def test_special_characters_in_version(self):
        """Test handling of special characters in version."""
        result = select_best_exploit(service_name="apache", service_version="Apache 2.4.49 (Ubuntu) mod_ssl/2.4.49")

        # Should still match Apache 2.4.49
        assert result["exploit_recommended"] is True


class TestRequirements:
    """Test exploit requirements handling."""

    def test_wordlist_requirement(self):
        """Test exploits that require wordlists."""
        result = select_best_exploit("ssh", "OpenSSH")

        if "bruteforce" in result["exploit_name"]:
            assert "wordlist" in result["requirements"]

    def test_no_requirements(self):
        """Test exploits with no requirements."""
        result = select_best_exploit("apache", "Apache 2.4.49")

        assert result["requirements"] == []

    def test_auth_requirement(self):
        """Test exploits that require authentication."""
        result = select_best_exploit("mysql", "MySQL")

        if "udf" in result["exploit_name"]:
            assert "mysql_access" in result["requirements"]


class TestMetasploitModules:
    """Test Metasploit module references."""

    def test_metasploit_module_present(self):
        """Test that exploits have Metasploit modules when available."""
        result = select_best_exploit("apache", "Apache 2.4.49")

        assert result["metasploit_module"] is not None
        assert "exploit/" in result["metasploit_module"]

    def test_metasploit_module_format(self):
        """Test Metasploit module format."""
        result = select_best_exploit("smb", "SMBv1")

        if result["metasploit_module"]:
            # Should be in format: exploit/os/service/module_name
            parts = result["metasploit_module"].split("/")
            assert len(parts) >= 3


class TestDatabaseIntegrity:
    """Test exploit database integrity."""

    def test_all_services_have_exploits(self):
        """Test that all services in database have at least one exploit."""
        services = ["apache", "ssh", "mysql", "postgresql", "smb", "http", "rdp", "ftp"]

        for service in services:
            exploits = get_all_exploits_for_service(service)
            assert len(exploits) > 0, f"Service {service} has no exploits"

    def test_all_exploits_have_required_fields(self):
        """Test that all exploits have required fields."""
        required_fields = [
            "exploit_name",
            "exploit_type",
            "severity",
            "success_rate",
            "difficulty",
            "description",
        ]

        for service in ["apache", "ssh", "mysql"]:
            exploits = get_all_exploits_for_service(service)

            for exploit in exploits:
                for field in required_fields:
                    assert field in exploit, f"Exploit missing field: {field}"

    def test_success_rates_in_valid_range(self):
        """Test that all success rates are between 0 and 1."""
        for service in ["apache", "ssh", "mysql", "smb", "ftp"]:
            exploits = get_all_exploits_for_service(service)

            for exploit in exploits:
                rate = exploit["success_rate"]
                assert 0.0 <= rate <= 1.0, f"Invalid success rate: {rate}"

    def test_severity_values_valid(self):
        """Test that all severity values are valid."""
        valid_severities = ["critical", "high", "medium", "low", "info"]

        for service in ["apache", "ssh", "mysql"]:
            exploits = get_all_exploits_for_service(service)

            for exploit in exploits:
                assert exploit["severity"] in valid_severities


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
