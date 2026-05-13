"""F84.6 — Tests for the CISA ICS Advisories loader.

We pin the seed CSV behaviour: it must parse without errors, expose a
reasonable advisory count, and vendor-filter calls must return matches
for vendors common in LATAM banking infra (Siemens, Schneider, Fuji
Electric — all present in the 2026 seed).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kryon.knowledge.datasets import (
    DEFAULT_SEED_PATH,
    OPERATOR_FULL_PATH,
    Advisory,
    advisories_by_vendor,
    load_cisa_advisories,
)


@pytest.fixture(autouse=True)
def _clear_lru_cache():
    """The loader is lru_cache'd, which is great for production but
    poisons cross-test state when one test points at a temp CSV and
    the next expects the default. Clear before every test."""
    load_cisa_advisories.cache_clear()
    yield
    load_cisa_advisories.cache_clear()


def test_default_seed_path_exists():
    assert DEFAULT_SEED_PATH.is_file(), f"seed CSV missing at {DEFAULT_SEED_PATH}"


def test_seed_loads_without_error():
    advisories = load_cisa_advisories(DEFAULT_SEED_PATH)
    assert len(advisories) >= 100, f"seed has only {len(advisories)} advisories — upstream CSV truncated?"
    assert all(isinstance(a, Advisory) for a in advisories)


def test_advisory_is_frozen_and_hashable():
    """Frozen dataclasses must be usable as dict keys / set members.
    If someone removes frozen=True, callers that cache by Advisory
    object break silently."""
    advisories = load_cisa_advisories(DEFAULT_SEED_PATH)
    sample = advisories[0]
    with pytest.raises((AttributeError, Exception)):
        sample.advisory_id = "MUTATED"  # type: ignore[misc]
    # And hashing works
    assert hash(sample) == hash(sample)
    seen = {sample}
    assert sample in seen


def test_advisory_id_format_pin():
    """All advisory IDs in the source CSV follow ICSA-YY-NNN-NN or
    ICSMA-YY-NNN-NN. If upstream renames the schema, this catches it
    before the correlator misbehaves silently."""
    import re

    valid = re.compile(r"^(ICSA|ICSMA|ICSCAVD)-\d{2}-\d{3}-\d{2}$")
    advisories = load_cisa_advisories(DEFAULT_SEED_PATH)
    bad = [a.advisory_id for a in advisories if not valid.match(a.advisory_id)]
    # Allow ≤2% drift — upstream sometimes ships placeholder IDs.
    assert len(bad) / len(advisories) < 0.02, f"unexpected ID formats: {bad[:5]}"


def test_cves_are_split_into_tuples():
    """Multi-CVE rows in the source ("CVE-2026-X, CVE-2026-Y") must
    land as separate tuple entries — the correlator iterates over
    Advisory.cves expecting one CVE per element."""
    advisories = load_cisa_advisories(DEFAULT_SEED_PATH)
    multi_cve = [a for a in advisories if len(a.cves) >= 2]
    assert multi_cve, "seed contains no multi-CVE advisories — sample too narrow"
    for adv in multi_cve[:5]:
        for cve in adv.cves:
            assert cve.startswith("CVE-"), f"bad CVE format in {adv.advisory_id}: {cve!r}"


def test_cwes_are_split_into_tuples():
    advisories = load_cisa_advisories(DEFAULT_SEED_PATH)
    with_cwes = [a for a in advisories if a.cwes]
    assert with_cwes
    for adv in with_cwes[:5]:
        for cwe in adv.cwes:
            assert cwe.startswith("CWE-"), f"bad CWE format in {adv.advisory_id}: {cwe!r}"


def test_advisories_by_vendor_siemens():
    """Siemens dominates the corpus — must return matches. Casing
    must not matter."""
    siemens_upper = advisories_by_vendor("SIEMENS", path=DEFAULT_SEED_PATH)
    siemens_lower = advisories_by_vendor("siemens", path=DEFAULT_SEED_PATH)
    siemens_title = advisories_by_vendor("Siemens", path=DEFAULT_SEED_PATH)
    assert siemens_upper == siemens_lower == siemens_title, "vendor matching is case-sensitive — bug"
    assert siemens_upper, "no Siemens advisories in seed — corpus too narrow"


def test_advisories_by_vendor_empty_string():
    """Empty vendor must short-circuit to () — otherwise every advisory
    would match (the empty string is in every string)."""
    assert advisories_by_vendor("", path=DEFAULT_SEED_PATH) == ()
    assert advisories_by_vendor("   ", path=DEFAULT_SEED_PATH) == ()


def test_advisories_by_vendor_unknown():
    """A nonexistent vendor must return empty, not raise."""
    result = advisories_by_vendor("xyzzy-fake-vendor", path=DEFAULT_SEED_PATH)
    assert result == ()


def test_loader_prefers_operator_full_path_when_present(tmp_path, monkeypatch):
    """When ~/.kryon/datasets/cisa_ics_advisories.csv exists, the
    loader (called with path=None) must prefer it over the seed.
    This is what scripts/update_cisa_advisories.sh sets up."""
    kryon_home = tmp_path / "kryonhome"
    dataset_dir = kryon_home / "datasets"
    dataset_dir.mkdir(parents=True)
    fake_full = dataset_dir / "cisa_ics_advisories.csv"
    # Minimal valid CSV with one row — must be a different row than seed.
    fake_full.write_text(
        "icsad_ID,Original_Release_Date,Last_Updated,Year,ICS-CERT_Number,"
        "ICS-CERT_Advisory_Title,Vendor,Product,Products_Affected,CVE_Number,"
        "Cumulative_CVSS,CVSS_Severity,CWE_Number,Critical_Infrastructure_Sector,"
        "Product_Distribution,Company_Headquarters,License\n"
        "9999,1/1/2026,1/1/2026,2026,ICSA-26-001-99,"
        "Test Operator Override,Test Vendor,Test Product,"
        "Test Product: 1.0,CVE-2026-99999,7.5,High,CWE-79,Energy,Worldwide,Test,"
        "ODbL v1.0\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("KRYON_HOME", str(kryon_home))

    # Reload module to pick up new env. Cleared cache already by autouse fixture.
    import importlib

    import kryon.knowledge.datasets as ds

    importlib.reload(ds)

    advisories = ds.load_cisa_advisories()  # path=None on purpose
    assert len(advisories) == 1
    assert advisories[0].advisory_id == "ICSA-26-001-99"
    assert advisories[0].vendor == "Test Vendor"


def test_default_operator_full_path_under_dot_kryon():
    """Without KRYON_HOME override, OPERATOR_FULL_PATH lives under
    ~/.kryon. This is the contract scripts/update_cisa_advisories.sh
    assumes — any drift here breaks the refresh workflow silently."""
    assert OPERATOR_FULL_PATH.parts[-2:] == ("datasets", "cisa_ics_advisories.csv")
    assert ".kryon" in str(OPERATOR_FULL_PATH) or Path.home().name in str(OPERATOR_FULL_PATH)
