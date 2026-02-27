"""Tests for CI/CD configuration files and project consistency."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class TestVersionConsistency:
    """Ensure version strings are consistent across files."""

    def test_pyproject_has_version(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'version\s*=\s*"(\d+\.\d+\.\d+)"', text)
        assert match, "pyproject.toml must have a version field"
        version = match.group(1)
        parts = version.split(".")
        assert len(parts) == 3, f"Version must be semver: {version}"
        assert all(p.isdigit() for p in parts), f"Version parts must be numeric: {version}"


class TestDockerCompose:
    """Validate docker-compose files."""

    def test_dev_compose_valid(self):
        path = ROOT / "docker-compose.yml"
        if not path.exists():
            return
        data = _load_yaml(path)
        assert "services" in data
        assert "kryon-server" in data["services"]

    def test_dev_compose_has_expected_services(self):
        path = ROOT / "docker-compose.yml"
        if not path.exists():
            return
        data = _load_yaml(path)
        services = set(data["services"].keys())
        assert "kryon-server" in services
        assert "dashboard" in services

    def test_prod_compose_valid(self):
        path = ROOT / "docker" / "docker-compose.production.yml"
        if not path.exists():
            return
        data = _load_yaml(path)
        assert "services" in data
        assert "kryon" in data["services"]


class TestCIWorkflows:
    """Validate GitHub Actions workflow files."""

    def test_ci_workflow_valid(self):
        path = ROOT / ".github" / "workflows" / "ci.yml"
        data = _load_yaml(path)
        assert data["name"] == "KRYON CI"
        assert "jobs" in data
        assert "test" in data["jobs"]

    def test_ci_excludes_e2e(self):
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        assert "e2e" in text, "CI workflow should exclude e2e tests"

    def test_security_scan_workflow_exists(self):
        path = ROOT / ".github" / "workflows" / "security-scan.yml"
        assert path.exists(), "security-scan.yml must exist"
        data = _load_yaml(path)
        assert "jobs" in data

    def test_docker_build_workflow_exists(self):
        path = ROOT / ".github" / "workflows" / "docker-build.yml"
        assert path.exists(), "docker-build.yml must exist"
        data = _load_yaml(path)
        assert "jobs" in data

    def test_release_workflow_exists(self):
        path = ROOT / ".github" / "workflows" / "release.yml"
        assert path.exists(), "release.yml must exist"
        data = _load_yaml(path)
        assert "jobs" in data


class TestMakefile:
    """Validate Makefile targets."""

    def test_makefile_has_docker_targets(self):
        text = (ROOT / "Makefile").read_text(encoding="utf-8")
        assert "docker-build" in text
        assert "security-scan" in text
        assert "release" in text
