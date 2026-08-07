"""F101 — TDD contract for the Information Disclosure scanner."""

from __future__ import annotations

import json

import pytest

from kryon.tools.api.info_disclosure import (
    ALL_DISCLOSURE_RULES,
    DisclosureAnalysis,
    DisclosureFinding,
    DisclosureProbe,
    _classify_probe,
    analyze_probes,
    default_probe_paths,
)


def _probe(path: str, status: int = 200, body: str = "") -> DisclosureProbe:
    return DisclosureProbe(path=path, http_status=status, body_fingerprint=body)


# =====================================================================
# Each rule POSITIVE + NEGATIVE
# =====================================================================


def test_info_001_git_config_critical():
    probe = _probe("/.git/config", 200, "[core]\n\trepositoryformatversion = 0")
    f = _classify_probe(probe)
    assert f is not None and f.rule_id == "INFO-001"
    assert f.severity == "CRITICAL"


def test_info_001_git_config_with_404_silent():
    assert _classify_probe(_probe("/.git/config", 404)) is None


def test_info_001_git_config_with_wrong_body_silent():
    """SPA returning shell HTML for every path → fingerprint won't
    match git config signature → no false positive."""
    assert _classify_probe(_probe("/.git/config", 200, "<html><body>404 not found</body></html>")) is None


def test_info_002_env_file_critical():
    f = _classify_probe(_probe("/.env", 200, "DB_PASSWORD=secret123\nAPI_KEY=xyz"))
    assert f is not None and f.rule_id == "INFO-002"
    assert f.severity == "CRITICAL"


def test_info_003_db_dump_critical():
    f = _classify_probe(_probe("/dump.sql", 200, "INSERT INTO users VALUES (1, 'admin'..."))
    assert f is not None and f.rule_id == "INFO-003"


def test_info_010_js_source_map_medium():
    f = _classify_probe(_probe("/main.abc123.js.map", 200))
    assert f is not None and f.rule_id == "INFO-010"
    assert f.severity == "MEDIUM"


def test_info_012_backup_file_high():
    f = _classify_probe(_probe("/config.php.bak", 200))
    assert f is not None and f.rule_id == "INFO-012"
    assert f.severity == "HIGH"


def test_info_013_ds_store_low():
    f = _classify_probe(_probe("/.DS_Store", 200, "Bud1..."))
    assert f is not None and f.rule_id == "INFO-013"


def test_info_014_dockerfile_medium():
    f = _classify_probe(_probe("/Dockerfile", 200, "FROM nginx:1.18\nRUN apt-get update"))
    assert f is not None and f.rule_id == "INFO-014"


def test_info_020_server_status_high():
    f = _classify_probe(_probe("/server-status", 200, "Apache Server Status for example.com"))
    assert f is not None and f.rule_id == "INFO-020"


def test_info_021_phpinfo_high():
    f = _classify_probe(_probe("/phpinfo.php", 200, "PHP Version 7.4.33"))
    assert f is not None and f.rule_id == "INFO-021"


def test_info_030_wp_admin_medium():
    f = _classify_probe(_probe("/wp-admin/", 200, "WordPress login page"))
    assert f is not None and f.rule_id == "INFO-030"


def test_info_031_phpmyadmin_medium():
    f = _classify_probe(_probe("/phpmyadmin/", 200, "phpMyAdmin 5.2 login"))
    assert f is not None and f.rule_id == "INFO-031"


def test_info_040_swagger_low():
    f = _classify_probe(_probe("/swagger-ui.html", 200, "swagger ui v3"))
    assert f is not None and f.rule_id == "INFO-040"


def test_info_050_robots_with_sensitive_paths():
    f = _classify_probe(_probe("/robots.txt", 200, "User-agent: *\nDisallow: /admin/\nDisallow: /api/"))
    assert f is not None and f.rule_id == "INFO-050"


def test_info_050_robots_without_sensitive_silent():
    """A robots.txt that just disallows /search/ shouldn't fire."""
    assert _classify_probe(_probe("/robots.txt", 200, "Disallow: /search/")) is None


def test_unknown_path_silent():
    """A 200 on a path not in our table should produce no finding."""
    assert _classify_probe(_probe("/some/random/path", 200, "anything")) is None


def test_403_status_silent():
    """Forbidden response = path exists but is access-controlled.
    Not a disclosure."""
    assert _classify_probe(_probe("/.env", 403, "Forbidden")) is None


# =====================================================================
# Aggregation
# =====================================================================


def test_analyze_probes_sorts_by_severity():
    probes = [
        _probe("/swagger-ui.html", 200, "swagger ui"),  # LOW
        _probe("/.env", 200, "DB_PASSWORD=xyz"),  # CRITICAL
        _probe("/server-status", 200, "Apache Server Status"),  # HIGH
    ]
    analysis = analyze_probes(probes)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranks = [severity_order[f.severity] for f in analysis.findings]
    assert ranks == sorted(ranks)


def test_analyze_probes_empty():
    analysis = analyze_probes([])
    assert analysis.total_probes == 0
    assert analysis.findings == ()


def test_default_probe_paths_returns_list():
    paths = default_probe_paths()
    assert "/.git/config" in paths
    assert "/.env" in paths
    assert "/wp-admin/" in paths


# =====================================================================
# Pin + frozen
# =====================================================================


def test_all_rules_pinned():
    expected = {
        "INFO-001",
        "INFO-002",
        "INFO-003",
        "INFO-004",
        "INFO-005",
        "INFO-007",
        "INFO-008",
        "INFO-010",
        "INFO-011",
        "INFO-012",
        "INFO-013",
        "INFO-014",
        "INFO-015",
        "INFO-016",
        "INFO-020",
        "INFO-021",
        "INFO-022",
        "INFO-023",
        "INFO-024",
        "INFO-025",
        "INFO-030",
        "INFO-031",
        "INFO-040",
        "INFO-041",
        "INFO-050",
    }
    assert expected == ALL_DISCLOSURE_RULES


# =====================================================================
# Expanded catalog — new rule coverage (F101 v2)
# =====================================================================


def test_info_001_git_index_critical():
    f = _classify_probe(_probe("/.git/index", 200, "DIRC\x00\x00\x00\x02..."))
    assert f is not None and f.rule_id == "INFO-001"
    assert f.severity == "CRITICAL"


def test_info_001_svn_wc_db_high():
    f = _classify_probe(_probe("/.svn/wc.db", 200, "SQLite format 3\x00"))
    assert f is not None and f.rule_id == "INFO-001"


def test_info_002_env_staging_critical():
    f = _classify_probe(_probe("/.env.staging", 200, "DB_HOST=localhost\nAPI_KEY=xxx"))
    assert f is not None and f.rule_id == "INFO-002"


def test_info_003_db_sql_critical():
    f = _classify_probe(_probe("/db.sql", 200, "CREATE TABLE users (id INT)"))
    assert f is not None and f.rule_id == "INFO-003"


def test_info_004_ssh_private_key_critical():
    f = _classify_probe(_probe("/id_rsa", 200, "-----BEGIN OPENSSH PRIVATE KEY-----"))
    assert f is not None and f.rule_id == "INFO-004"
    assert f.severity == "CRITICAL"


def test_info_004_tls_private_key_critical():
    f = _classify_probe(_probe("/privkey.pem", 200, "-----BEGIN RSA PRIVATE KEY-----"))
    assert f is not None and f.rule_id == "INFO-004"


def test_info_004_wrong_body_silent():
    """A 200 with HTML shell body should NOT fire INFO-004."""
    f = _classify_probe(_probe("/id_rsa", 200, "<html>not found</html>"))
    assert f is None


def test_info_005_aws_credentials_critical():
    f = _classify_probe(_probe("/.aws/credentials", 200, "[default]\naws_access_key_id = AKIA..."))
    assert f is not None and f.rule_id == "INFO-005"
    assert f.severity == "CRITICAL"


def test_info_005_docker_config_critical():
    f = _classify_probe(_probe("/.docker/config.json", 200, '{"auths":{"registry":{"auth":"..."}}}'))
    assert f is not None and f.rule_id == "INFO-005"


def test_info_005_npmrc_critical():
    f = _classify_probe(_probe("/.npmrc", 200, "//registry.npmjs.org/:_authToken=npm_xxx"))
    assert f is not None and f.rule_id == "INFO-005"


def test_info_007_terraform_state_critical():
    f = _classify_probe(_probe("/terraform.tfstate", 200, '{"terraform_version": "1.5.0", "resources": [...]'))
    assert f is not None and f.rule_id == "INFO-007"
    assert f.severity == "CRITICAL"


def test_info_008_rails_database_yml_critical():
    f = _classify_probe(_probe("/config/database.yml", 200, "production:\n  adapter: postgresql\n  password: secret"))
    assert f is not None and f.rule_id == "INFO-008"


def test_info_008_master_key_critical():
    f = _classify_probe(_probe("/config/master.key", 200, "0a1b2c3d4e5f6789abcdef0123456789"))
    assert f is not None and f.rule_id == "INFO-008"


def test_info_008_appsettings_high():
    f = _classify_probe(_probe("/appsettings.json", 200, '{"ConnectionStrings":{"Default":"Server=..."}}'))
    assert f is not None and f.rule_id == "INFO-008"


def test_info_008_spring_props_high():
    f = _classify_probe(_probe("/application.properties", 200, "spring.datasource.url=jdbc:postgresql://"))
    assert f is not None and f.rule_id == "INFO-008"


def test_info_015_gitlab_ci_medium():
    f = _classify_probe(_probe("/.gitlab-ci.yml", 200, "stages:\n  - build\n  - test\nimage: node:18"))
    assert f is not None and f.rule_id == "INFO-015"


def test_info_015_jenkinsfile_medium():
    f = _classify_probe(_probe("/Jenkinsfile", 200, "pipeline {\n  agent any\n  stages {"))
    assert f is not None and f.rule_id == "INFO-015"


def test_info_016_web_xml_high():
    f = _classify_probe(_probe("/WEB-INF/web.xml", 200, "<web-app><servlet><servlet-name>...</servlet-name>"))
    assert f is not None and f.rule_id == "INFO-016"


def test_info_022_wp_config_backup_critical():
    f = _classify_probe(_probe("/wp-config.php.bak", 200, "define('DB_PASSWORD', 'secret');"))
    assert f is not None and f.rule_id == "INFO-022"
    assert f.severity == "CRITICAL"


def test_info_023_tomcat_manager_high():
    f = _classify_probe(_probe("/manager/html", 200, "Apache Tomcat/9.0 Manager App"))
    assert f is not None and f.rule_id == "INFO-023"


def test_info_023_jmx_console_high():
    f = _classify_probe(_probe("/jmx-console/", 200, "<title>JMX Console</title>"))
    assert f is not None and f.rule_id == "INFO-023"


def test_info_024_pprof_medium():
    f = _classify_probe(_probe("/debug/pprof/", 200, "Types of profiles available:\ngoroutine\nheap\nthreadcreate"))
    assert f is not None and f.rule_id == "INFO-024"


def test_info_025_actuator_heapdump_critical():
    f = _classify_probe(_probe("/actuator/heapdump", 200, "JAVA PROFILE 1.0.2"))
    assert f is not None and f.rule_id == "INFO-025"
    assert f.severity == "CRITICAL"


def test_info_025_actuator_env_high():
    f = _classify_probe(_probe("/actuator/env", 200, '{"activeProfiles":[],"propertySources":[...]'))
    assert f is not None and f.rule_id == "INFO-025"
    assert f.severity == "HIGH"


def test_info_025_actuator_health_low():
    f = _classify_probe(_probe("/actuator/health", 200, '{"status":"UP"}'))
    assert f is not None and f.rule_id == "INFO-025"
    assert f.severity == "LOW"


def test_info_030_wp_login_medium():
    f = _classify_probe(_probe("/wp-login.php", 200, "WordPress\n<form name='loginform' user_login"))
    assert f is not None and f.rule_id == "INFO-030"


def test_info_031_pma_alt_path_medium():
    f = _classify_probe(_probe("/pma/", 200, "phpMyAdmin 5.2"))
    assert f is not None and f.rule_id == "INFO-031"


def test_info_041_graphql_endpoint_low():
    f = _classify_probe(_probe("/graphql", 200, '{"errors":[{"message":"Must provide query."}]}'))
    assert f is not None and f.rule_id == "INFO-041"


def test_info_041_graphiql_ui_medium():
    f = _classify_probe(_probe("/graphiql", 200, "<title>GraphiQL</title>"))
    assert f is not None and f.rule_id == "INFO-041"


# =====================================================================
# Default probe paths coverage
# =====================================================================


def test_default_probe_paths_includes_expanded_set():
    paths = set(default_probe_paths())
    # spot-check the new additions
    assert "/id_rsa" in paths
    assert "/.aws/credentials" in paths
    assert "/terraform.tfstate" in paths
    assert "/config/database.yml" in paths
    assert "/.gitlab-ci.yml" in paths
    assert "/WEB-INF/web.xml" in paths
    assert "/wp-config.php.bak" in paths
    assert "/manager/html" in paths
    assert "/debug/pprof/" in paths
    assert "/actuator/heapdump" in paths
    assert "/graphql" in paths
    assert len(paths) >= 80  # expanded catalog


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    p = DisclosureProbe(path="/x", http_status=200)
    with pytest.raises(FrozenInstanceError):
        p.path = "/y"  # type: ignore[misc]

    f = DisclosureFinding(rule_id="INFO-001", severity="CRITICAL", title="x", detail="x", remediation="x")
    with pytest.raises(FrozenInstanceError):
        f.severity = "LOW"  # type: ignore[misc]


# =====================================================================
# Tool wrapper
# =====================================================================


def test_tool_wrapper_handles_empty_input():
    """No probes -> 0 findings."""
    analysis = analyze_probes([])
    assert analysis.total_probes == 0


def test_realistic_disclosure_scan():
    """A site with .git exposed + admin paths + swagger = several findings."""
    probes = [
        _probe("/.git/config", 200, "[core]\nrepositoryformatversion=0"),
        _probe("/wp-admin/", 200, "WordPress login"),
        _probe("/swagger-ui.html", 200, "swagger v3"),
        _probe("/.env", 404),  # not exposed
        _probe("/random/path", 200, "<html>"),  # not interesting
    ]
    analysis = analyze_probes(probes)
    ids = {f.rule_id for f in analysis.findings}
    assert "INFO-001" in ids
    assert "INFO-030" in ids
    assert "INFO-040" in ids
    assert len(analysis.findings) == 3
