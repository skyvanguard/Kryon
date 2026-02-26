"""Tests for RBAC permission system."""

import pytest

from kryon.server.auth.rbac import PERMISSIONS, _has_permission


def test_admin_has_all_permissions():
    assert _has_permission("admin", "runs:write") is True
    assert _has_permission("admin", "admin:read") is True
    assert _has_permission("admin", "anything:at_all") is True


def test_analyst_can_write_scans():
    assert _has_permission("analyst", "scans:write") is True
    assert _has_permission("analyst", "runs:write") is True
    assert _has_permission("analyst", "engagements:write") is True


def test_analyst_cannot_read_admin():
    assert _has_permission("analyst", "admin:read") is False


def test_viewer_read_only():
    assert _has_permission("viewer", "runs:read") is True
    assert _has_permission("viewer", "scans:read") is True
    assert _has_permission("viewer", "runs:write") is False
    assert _has_permission("viewer", "scans:write") is False


def test_unknown_role_denied():
    assert _has_permission("unknown_role", "runs:read") is False


def test_viewer_cannot_write_engagements():
    assert _has_permission("viewer", "engagements:write") is False
