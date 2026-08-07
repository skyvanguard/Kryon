"""Tests for the CIS Controls v8.1 catalog (loaded from the validated YAML)."""

from __future__ import annotations

from collections import Counter

from kryon.compliance.cis_controls import (
    CIS_CONTROLS,
    FRAMEWORK_NAME,
    FRAMEWORK_VERSION,
)


class TestCISControlsV81Catalog:
    def test_153_safeguards(self):
        assert len(CIS_CONTROLS) == 153

    def test_framework_is_v81(self):
        assert FRAMEWORK_NAME == "CIS Controls v8.1"
        assert FRAMEWORK_VERSION == "8.1"

    def test_18_controls_present(self):
        controls = {c.safeguard.split(".")[0] for c in CIS_CONTROLS}
        assert controls == {str(i) for i in range(1, 19)}

    def test_control_15_present(self):
        """v8 catalog in Kryon was missing Control 15 (Service Provider Mgmt)."""
        c15 = [c for c in CIS_CONTROLS if c.safeguard.startswith("15.")]
        assert len(c15) == 7
        assert all("Proveedores" in c.category for c in c15)

    def test_govern_function_present(self):
        """v8.1 introduced the Govern security function (25 safeguards)."""
        govern = [c for c in CIS_CONTROLS if c.security_function == "Govern"]
        assert len(govern) == 25

    def test_documentation_asset_present(self):
        """v8.1 introduced the Documentation asset class (23 safeguards)."""
        docs = [c for c in CIS_CONTROLS if c.asset_type == "Documentation"]
        assert len(docs) == 23

    def test_security_functions_are_nist_csf_english(self):
        funcs = {c.security_function for c in CIS_CONTROLS}
        assert funcs == {"Identify", "Protect", "Detect", "Respond", "Recover", "Govern"}

    def test_implementation_group_distribution(self):
        dist = Counter(c.implementation_group for c in CIS_CONTROLS)
        # Canonical v8.1 IG1 count is 56; total = 153.
        assert dist[1] == 56
        assert dist[2] == 74
        assert dist[3] == 23

    def test_every_safeguard_fully_populated(self):
        for c in CIS_CONTROLS:
            assert c.id.startswith("CIS-")
            assert c.title.strip()
            assert c.description.strip()
            assert c.category.strip()
            assert c.implementation_group in (1, 2, 3)
            assert c.security_function
            assert c.asset_type
            assert c.safeguard and not c.safeguard.startswith("CIS-")
            assert c.verdict_mode == "manual"  # crosswalk flips to "auto" at audit time

    def test_ids_unique(self):
        ids = [c.id for c in CIS_CONTROLS]
        assert len(ids) == len(set(ids))
