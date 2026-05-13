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
    expected = {f"INFO-00{i}" for i in range(1, 4)} | {f"INFO-01{i}" for i in range(0, 5)} | {"INFO-020", "INFO-021", "INFO-030", "INFO-031", "INFO-040", "INFO-050"}
    assert expected <= ALL_DISCLOSURE_RULES


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
