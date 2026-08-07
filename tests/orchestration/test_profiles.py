"""Tests for scan profiles."""

from kryon.server.profiles import SCAN_PROFILES, get_profile, list_profiles


def test_profiles_exist():
    assert len(SCAN_PROFILES) >= 4
    assert "quick" in SCAN_PROFILES
    assert "standard" in SCAN_PROFILES
    assert "deep" in SCAN_PROFILES
    assert "compliance" in SCAN_PROFILES


def test_get_profile():
    p = get_profile("quick")
    assert p is not None
    assert "agents" in p
    assert "description" in p


def test_get_nonexistent_profile():
    assert get_profile("nonexistent") is None


def test_list_profiles():
    profiles = list_profiles()
    assert len(profiles) >= 4
    names = [p["name"] for p in profiles]
    assert "quick" in names
    assert "deep" in names
