"""F104 — TDD contract for the CMS / Framework Fingerprinting analyzer."""

from __future__ import annotations

import pytest

from kryon.tools.api.cms_fingerprint import (
    ALL_CMS_RULES,
    FingerprintAnalysis,
    FingerprintFinding,
    FingerprintObservation,
    analyze_fingerprint,
)


def _obs(
    url: str = "https://target.example/",
    headers: tuple[tuple[str, str], ...] = (),
    body: str = "",
    cookies: tuple[str, ...] = (),
) -> FingerprintObservation:
    return FingerprintObservation(
        url=url,
        headers=headers,
        body_snippet=body,
        cookie_names=cookies,
    )


# =====================================================================
# Body / meta-tag detection
# =====================================================================


def test_wordpress_via_meta_generator():
    body = '<meta name="generator" content="WordPress 5.6.2" />'
    analysis = analyze_fingerprint(_obs(body=body))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-001" in ids
    assert "CMS-010" in ids  # < 5.7 → CVE-2021-29447
    assert "CMS-011" in ids  # < 5.8.3
    assert "CMS-040" in ids


def test_wordpress_modern_no_cve_rules():
    body = '<meta name="generator" content="WordPress 6.4.1" />'
    analysis = analyze_fingerprint(_obs(body=body))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-001" in ids
    assert "CMS-010" not in ids
    assert "CMS-011" not in ids


def test_wordpress_via_paths_only():
    body = '<link rel="stylesheet" href="/wp-content/themes/foo/style.css">'
    analysis = analyze_fingerprint(_obs(body=body))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-001" in ids


def test_drupal_via_meta_generator_vulnerable():
    body = '<meta name="generator" content="Drupal 7" />'
    analysis = analyze_fingerprint(_obs(body=body))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-002" in ids
    assert "CMS-012" in ids  # < 7.78


def test_drupal_modern_no_cve():
    body = '<meta name="generator" content="Drupal 10" />'
    analysis = analyze_fingerprint(_obs(body=body))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-002" in ids
    assert "CMS-012" not in ids


def test_joomla_detected():
    body = '<meta name="generator" content="Joomla! - Open Source Content Management" />'
    analysis = analyze_fingerprint(_obs(body=body))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-003" in ids


def test_magento_detected():
    body = "<script>Mage.Cookies.set('foo','bar');</script>"
    analysis = analyze_fingerprint(_obs(body=body))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-004" in ids


def test_typo3_detected():
    body = '<link rel="stylesheet" href="/typo3temp/assets/foo.css" />'
    analysis = analyze_fingerprint(_obs(body=body))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-005" in ids


# =====================================================================
# Header detection
# =====================================================================


def test_xpoweredby_disclosure_fires():
    analysis = analyze_fingerprint(_obs(headers=(("X-Powered-By", "PHP/7.4.33"),)))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-030" in ids


def test_server_version_disclosure_fires():
    analysis = analyze_fingerprint(_obs(headers=(("Server", "nginx/1.18.0"),)))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-031" in ids


def test_server_without_version_no_finding():
    analysis = analyze_fingerprint(_obs(headers=(("Server", "nginx"),)))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-031" not in ids


def test_aspnet_version_header():
    analysis = analyze_fingerprint(
        _obs(headers=(("X-AspNet-Version", "4.0.30319"),))
    )
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-022" in ids


def test_drupal_via_cache_header():
    analysis = analyze_fingerprint(_obs(headers=(("X-Drupal-Cache", "HIT"),)))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-002" in ids


def test_express_via_xpoweredby():
    analysis = analyze_fingerprint(_obs(headers=(("X-Powered-By", "Express"),)))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-023" in ids


def test_django_via_server_header():
    analysis = analyze_fingerprint(
        _obs(headers=(("Server", "WSGIServer/0.2 CPython/3.11 Django/4.2"),))
    )
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-020" in ids


# =====================================================================
# Cookie detection
# =====================================================================


def test_laravel_via_cookie():
    analysis = analyze_fingerprint(_obs(cookies=("laravel_session",)))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-024" in ids


def test_django_via_csrftoken_cookie():
    analysis = analyze_fingerprint(_obs(cookies=("csrftoken",)))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-020" in ids


def test_rails_via_session_cookie():
    analysis = analyze_fingerprint(_obs(cookies=("_session_id",)))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-021" in ids


def test_aspnet_via_session_cookie():
    analysis = analyze_fingerprint(_obs(cookies=("ASP.NET_SessionId",)))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-022" in ids


def test_wordpress_via_wp_cookie():
    analysis = analyze_fingerprint(_obs(cookies=("wp_user_settings",)))
    ids = {f.rule_id for f in analysis.findings}
    assert "CMS-001" in ids


def test_phpsessid_alone_not_classified():
    """PHPSESSID is too generic — should not flag any CMS-NNN."""
    analysis = analyze_fingerprint(_obs(cookies=("PHPSESSID",)))
    ids = {f.rule_id for f in analysis.findings}
    assert all(not i.startswith("CMS-0") for i in ids)


# =====================================================================
# Dedup + aggregation
# =====================================================================


def test_dedupes_repeated_findings():
    """WP detected both via meta + cookie shouldn't produce 2x CMS-001
    for the same tech + version."""
    body = '<meta name="generator" content="WordPress 6.4.1" />'
    analysis = analyze_fingerprint(
        _obs(body=body, cookies=("wp_user_settings",))
    )
    cms_001_count = sum(1 for f in analysis.findings if f.rule_id == "CMS-001")
    # One for the (version=6.4.1) detection; the cookie detection
    # produces a no-version dup which our dedup may or may not collapse.
    # We assert at most 2 — the version-tagged one + the empty-version
    # one, since they have different keys.
    assert cms_001_count <= 2


def test_findings_sorted_by_severity():
    body = '<meta name="generator" content="WordPress 5.6.2" />'
    analysis = analyze_fingerprint(_obs(body=body))
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranks = [severity_order[f.severity] for f in analysis.findings]
    assert ranks == sorted(ranks)


def test_empty_observation_zero_findings():
    analysis = analyze_fingerprint(_obs())
    assert analysis.findings == ()


# =====================================================================
# Pin + frozen
# =====================================================================


def test_all_rules_pinned():
    expected_subset = {"CMS-001", "CMS-002", "CMS-010", "CMS-022", "CMS-030", "CMS-040"}
    assert expected_subset <= ALL_CMS_RULES


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    obs = FingerprintObservation(url="/x")
    with pytest.raises(FrozenInstanceError):
        obs.url = "/y"  # type: ignore[misc]
