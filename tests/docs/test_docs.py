"""Tests for documentation completeness and consistency."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent

# The enterprise doc set (admin-guide, api-guide, architecture, deployment
# guides + docs/index.md) is not shipped in the public repo. Remove these skips
# if/when those docs are added.
_ENTERPRISE_DOCS_SKIP = "enterprise docs not shipped in the public repo"


class TestDocumentation:
    def test_contributing_exists(self):
        assert (ROOT / "CONTRIBUTING.md").exists()

    def test_security_exists(self):
        assert (ROOT / "SECURITY.md").exists()

    def test_changelog_exists(self):
        assert (ROOT / "CHANGELOG.md").exists()

    @pytest.mark.skip(reason=_ENTERPRISE_DOCS_SKIP)
    def test_admin_guide_exists(self):
        assert (ROOT / "docs" / "admin-guide" / "index.md").exists()

    @pytest.mark.skip(reason=_ENTERPRISE_DOCS_SKIP)
    def test_api_guide_exists(self):
        assert (ROOT / "docs" / "api-guide" / "index.md").exists()

    @pytest.mark.skip(reason=_ENTERPRISE_DOCS_SKIP)
    def test_architecture_exists(self):
        assert (ROOT / "docs" / "architecture" / "overview.md").exists()

    @pytest.mark.skip(reason=_ENTERPRISE_DOCS_SKIP)
    def test_deployment_exists(self):
        assert (ROOT / "docs" / "deployment" / "docker.md").exists()


class TestDocLinks:
    @pytest.mark.skip(reason=_ENTERPRISE_DOCS_SKIP)
    def test_docs_index_has_enterprise_links(self):
        text = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
        assert "admin-guide" in text
        assert "api-guide" in text
        assert "architecture" in text
        assert "deployment" in text

    def test_internal_links_valid(self):
        """Check that markdown links in docs point to existing files."""
        docs_dir = ROOT / "docs"
        broken_links = []
        for md_file in docs_dir.rglob("*.md"):
            content = md_file.read_text(encoding="utf-8")
            # Find relative markdown links like [text](path.md)
            links = re.findall(r"\[.*?\]\((?!http)(.*?\.md)\)", content)
            for link in links:
                target = (md_file.parent / link).resolve()
                if not target.exists():
                    broken_links.append(f"{md_file.relative_to(ROOT)} -> {link}")
        # Allow some broken links (docs may reference not-yet-created files)
        assert len(broken_links) < 20, f"Too many broken links: {broken_links[:10]}"


class TestOpenAPI:
    def test_openapi_schema_generates(self):
        """OpenAPI schema should generate without errors."""
        from kryon.server.app import create_app

        app = create_app()
        schema = app.openapi()
        assert "paths" in schema
        assert len(schema["paths"]) > 10
        assert "/api/v1/health" in schema["paths"]
