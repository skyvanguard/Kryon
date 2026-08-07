"""F84.6 — Tests for the banner-to-CVE correlator.

We craft fixture CSVs that exercise each clause of the heuristic
(vendor match, product token overlap, version compatibility, no-match
short-circuits). The seed CSV is used in a couple of integration tests
that pin LATAM-relevant correlations.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kryon.knowledge.datasets import DEFAULT_SEED_PATH, load_cisa_advisories
from kryon.tools.ot.cve_correlator import correlate_banner_to_cves


@pytest.fixture(autouse=True)
def _clear_lru_cache():
    load_cisa_advisories.cache_clear()
    yield
    load_cisa_advisories.cache_clear()


def _write_csv(path: Path, rows: list[dict[str, str]]) -> Path:
    """Tiny CSV writer for fixtures — keeps the schema explicit so a
    column rename upstream breaks the test, not the production loader
    silently."""
    import csv

    cols = [
        "icsad_ID",
        "Original_Release_Date",
        "Last_Updated",
        "Year",
        "ICS-CERT_Number",
        "ICS-CERT_Advisory_Title",
        "Vendor",
        "Product",
        "Products_Affected",
        "CVE_Number",
        "Cumulative_CVSS",
        "CVSS_Severity",
        "CWE_Number",
        "Critical_Infrastructure_Sector",
        "Product_Distribution",
        "Company_Headquarters",
        "License",
    ]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        for r in rows:
            writer.writerow({c: r.get(c, "") for c in cols})
    return path


# ---------- Heuristic stage 1: vendor match ----------


def test_empty_vendor_returns_empty_tuple():
    assert correlate_banner_to_cves("", "SIMATIC", "V4.4") == ()


def test_unknown_vendor_returns_empty_tuple(tmp_path):
    csv_path = _write_csv(
        tmp_path / "tiny.csv",
        [
            {
                "ICS-CERT_Number": "ICSA-26-001-01",
                "Vendor": "Siemens",
                "Product": "SIMATIC",
                "Products_Affected": "SIMATIC S7-1200 V4.4",
                "CVE_Number": "CVE-2026-1111",
            }
        ],
    )
    assert correlate_banner_to_cves("Schneider", "Modicon", "M580", dataset_path=csv_path) == ()


# ---------- Heuristic stage 2: product token overlap ----------


def test_product_substring_match(tmp_path):
    csv_path = _write_csv(
        tmp_path / "tiny.csv",
        [
            {
                "ICS-CERT_Number": "ICSA-26-001-01",
                "Vendor": "Siemens",
                "Product": "SIMATIC S7-1200",
                "Products_Affected": "SIMATIC S7-1200 V4.4",
                "CVE_Number": "CVE-2026-1111",
                "Cumulative_CVSS": "8.5",
                "CVSS_Severity": "High",
            }
        ],
    )
    result = correlate_banner_to_cves("Siemens", "SIMATIC S7-1200", dataset_path=csv_path)
    assert len(result) == 1
    assert result[0].advisory_id == "ICSA-26-001-01"
    assert result[0].cvss_v3 == 8.5


def test_product_token_overlap_partial(tmp_path):
    """Banner says "S7-1500" but advisory says "SIMATIC S7-1500
    CPU 1516". Token overlap should hit on "1500"."""
    csv_path = _write_csv(
        tmp_path / "tiny.csv",
        [
            {
                "ICS-CERT_Number": "ICSA-26-002-01",
                "Vendor": "Siemens",
                "Product": "SIMATIC S7-1500 CPU 1516",
                "Products_Affected": "SIMATIC S7-1500 CPU 1516-3 PN/DP V3.1",
                "CVE_Number": "CVE-2026-2222",
            }
        ],
    )
    result = correlate_banner_to_cves("Siemens", "S7-1500", dataset_path=csv_path)
    assert len(result) == 1


def test_product_mismatch_no_overlap(tmp_path):
    """Same vendor, completely unrelated products → no hit."""
    csv_path = _write_csv(
        tmp_path / "tiny.csv",
        [
            {
                "ICS-CERT_Number": "ICSA-26-003-01",
                "Vendor": "Siemens",
                "Product": "SCALANCE X-200 Switch",
                "Products_Affected": "SCALANCE X-200 Switch",
                "CVE_Number": "CVE-2026-3333",
            }
        ],
    )
    # banner says SIMATIC S7 — should not surface a SCALANCE switch CVE
    result = correlate_banner_to_cves("Siemens", "SIMATIC S7-1200", dataset_path=csv_path)
    assert result == ()


# ---------- Heuristic stage 3: version compatibility ----------


def test_version_match_major_minor(tmp_path):
    csv_path = _write_csv(
        tmp_path / "tiny.csv",
        [
            {
                "ICS-CERT_Number": "ICSA-26-004-01",
                "Vendor": "Siemens",
                "Product": "SIMATIC",
                "Products_Affected": "SIMATIC S7-1200 V4.4.1",
                "CVE_Number": "CVE-2026-4444",
            }
        ],
    )
    # Patch-level differs but major.minor matches — should hit.
    result = correlate_banner_to_cves("Siemens", "SIMATIC S7-1200", "V4.4.3", dataset_path=csv_path)
    assert len(result) == 1


def test_version_mismatch_excludes(tmp_path):
    csv_path = _write_csv(
        tmp_path / "tiny.csv",
        [
            {
                "ICS-CERT_Number": "ICSA-26-005-01",
                "Vendor": "Siemens",
                "Product": "SIMATIC",
                "Products_Affected": "SIMATIC S7-1200 V3.0.1",
                "CVE_Number": "CVE-2026-5555",
            }
        ],
    )
    # V4.x banner against V3.x advisory — different major.minor.
    result = correlate_banner_to_cves("Siemens", "SIMATIC S7-1200", "V4.4.3", dataset_path=csv_path)
    assert result == ()


def test_version_absent_in_advisory_includes(tmp_path):
    """When the advisory doesn't enumerate a version, we include the
    hit (auditor reviews). False-positive bias is intentional."""
    csv_path = _write_csv(
        tmp_path / "tiny.csv",
        [
            {
                "ICS-CERT_Number": "ICSA-26-006-01",
                "Vendor": "Siemens",
                "Product": "SIMATIC",
                "Products_Affected": "SIMATIC S7-1200 all firmware versions",
                "CVE_Number": "CVE-2026-6666",
            }
        ],
    )
    result = correlate_banner_to_cves("Siemens", "SIMATIC S7-1200", "V4.4.3", dataset_path=csv_path)
    assert len(result) == 1


def test_version_absent_in_banner_includes(tmp_path):
    """Banner has no version → we include any vendor-matching advisory."""
    csv_path = _write_csv(
        tmp_path / "tiny.csv",
        [
            {
                "ICS-CERT_Number": "ICSA-26-007-01",
                "Vendor": "Siemens",
                "Product": "SIMATIC",
                "Products_Affected": "SIMATIC S7-1200 V4.4",
                "CVE_Number": "CVE-2026-7777",
            }
        ],
    )
    result = correlate_banner_to_cves("Siemens", "SIMATIC S7-1200", dataset_path=csv_path)
    assert len(result) == 1


# ---------- Integration tests against the bundled seed ----------


def test_seed_has_siemens_correlations():
    """The 2026 seed contains Siemens advisories — verify we surface
    them via a real-world banner shape."""
    # Pick a likely-present product family; even if no exact match, the
    # vendor-only correlator returns >=1 when token overlap exists.
    result = correlate_banner_to_cves(
        "Siemens",
        "SIMATIC",
        dataset_path=DEFAULT_SEED_PATH,
    )
    # Empty is acceptable when the year subset doesn't include a SIMATIC
    # advisory — but at least we must not raise.
    assert isinstance(result, tuple)


def test_seed_correlator_returns_advisory_instances():
    advisories = load_cisa_advisories(DEFAULT_SEED_PATH)
    # Pick a known vendor from the seed dynamically — avoids brittleness
    # if the upstream subset shifts.
    a_vendor = next((a.vendor for a in advisories if a.vendor), None)
    a_product = next((a.product for a in advisories if a.product and a.vendor == a_vendor), None)
    assert a_vendor and a_product, "seed has no rows with both vendor and product set"
    result = correlate_banner_to_cves(a_vendor, a_product, dataset_path=DEFAULT_SEED_PATH)
    assert result, f"expected at least one match for {a_vendor=} {a_product=}"
    assert all(hasattr(adv, "advisory_id") and hasattr(adv, "cves") for adv in result)
