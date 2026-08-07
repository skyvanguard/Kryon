"""F102 — TDD contract for the Vulnerable JS Library detector."""

from __future__ import annotations

import pytest

from kryon.tools.api.vuln_js_libs import (
    ALL_VJS_RULES,
    JSLibAnalysis,
    JSLibFinding,
    ScriptObservation,
    _classify_observation,
    _identify_library,
    analyze_scripts,
)


def _obs(src: str, body: str = "") -> ScriptObservation:
    return ScriptObservation(src=src, body_fingerprint=body)


# =====================================================================
# Detection / identification
# =====================================================================


def test_identifies_jquery_from_url():
    result = _identify_library(_obs("/static/jquery-1.8.3.min.js"))
    assert result == ("jquery", (1, 8, 3))


def test_identifies_jquery_from_body_when_url_lacks_version():
    body = "/*! jQuery JavaScript Library v3.6.0 - sizzle.js | ..."
    result = _identify_library(_obs("/jquery.min.js", body))
    assert result == ("jquery", (3, 6, 0))


def test_identifies_lodash():
    result = _identify_library(_obs("/cdn/lodash-4.17.10.min.js"))
    assert result == ("lodash", (4, 17, 10))


def test_unknown_library_returns_none():
    result = _identify_library(_obs("/some-custom-lib-1.0.js"))
    assert result is None


# =====================================================================
# Vulnerability rules — each rule POSITIVE + NEGATIVE
# =====================================================================


def test_vjs_001_jquery_pre_350():
    findings = _classify_observation(_obs("/jquery-3.4.1.min.js"))
    ids = {f.rule_id for f in findings}
    assert "VJS-001" in ids


def test_vjs_001_jquery_350_safe():
    """Exactly 3.5.0 should not trip < 3.5.0 rule (VJS-001)."""
    findings = _classify_observation(_obs("/jquery-3.5.0.min.js"))
    ids = {f.rule_id for f in findings}
    assert "VJS-001" not in ids


def test_vjs_002_jquery_pre_340():
    findings = _classify_observation(_obs("/jquery-3.3.1.min.js"))
    ids = {f.rule_id for f in findings}
    assert "VJS-002" in ids


def test_vjs_002_jquery_340_safe():
    findings = _classify_observation(_obs("/jquery-3.4.0.min.js"))
    ids = {f.rule_id for f in findings}
    assert "VJS-002" not in ids


def test_vjs_003_angular_pre_180():
    findings = _classify_observation(_obs("/angular-1.7.9.min.js"))
    assert any(f.rule_id == "VJS-003" for f in findings)


def test_vjs_003_angular_180_safe():
    findings = _classify_observation(_obs("/angular-1.8.0.min.js"))
    assert not any(f.rule_id == "VJS-003" for f in findings)


def test_vjs_004_bootstrap_pre_431():
    findings = _classify_observation(_obs("/bootstrap-4.3.0.min.js"))
    assert any(f.rule_id == "VJS-004" for f in findings)


def test_vjs_005_bootstrap_pre_340():
    findings = _classify_observation(_obs("/bootstrap-3.3.7.min.js"))
    assert any(f.rule_id == "VJS-005" for f in findings)


def test_vjs_006_lodash_pre_41721():
    findings = _classify_observation(_obs("/lodash-4.17.20.min.js"))
    assert any(f.rule_id == "VJS-006" for f in findings)


def test_vjs_007_lodash_pre_41712():
    findings = _classify_observation(_obs("/lodash-4.17.11.min.js"))
    ids = {f.rule_id for f in findings}
    # 4.17.11 < 4.17.12 AND < 4.17.21, so both VJS-006 and VJS-007 fire
    assert "VJS-006" in ids
    assert "VJS-007" in ids


def test_vjs_008_moment_pre_2294():
    findings = _classify_observation(_obs("/moment-2.29.3.min.js"))
    assert any(f.rule_id == "VJS-008" for f in findings)


def test_vjs_009_underscore_pre_1121():
    findings = _classify_observation(_obs("/underscore-1.12.0.min.js"))
    assert any(f.rule_id == "VJS-009" for f in findings)


def test_vjs_010_axios_pre_0212():
    findings = _classify_observation(_obs("/axios-0.21.1.min.js"))
    assert any(f.rule_id == "VJS-010" for f in findings)


def test_vjs_013_dompurify_pre_2017():
    findings = _classify_observation(_obs("/dompurify-2.0.16.min.js"))
    assert any(f.rule_id == "VJS-013" for f in findings)


def test_vjs_014_handlebars_pre_477():
    findings = _classify_observation(_obs("/handlebars-4.7.6.min.js"))
    assert any(f.rule_id == "VJS-014" for f in findings)


def test_vjs_015_jquery_ui_pre_1130():
    findings = _classify_observation(_obs("/jquery-ui-1.12.1.min.js"))
    assert any(f.rule_id == "VJS-015" for f in findings)


def test_vjs_016_jquery_pre_300():
    findings = _classify_observation(_obs("/jquery-2.2.4.min.js"))
    ids = {f.rule_id for f in findings}
    assert "VJS-016" in ids


def test_modern_jquery_is_clean():
    findings = _classify_observation(_obs("/jquery-3.7.0.min.js"))
    assert findings == []


# =====================================================================
# Aggregation
# =====================================================================


def test_analyze_scripts_sorts_by_severity():
    scripts = [
        _obs("/jquery-3.4.1.min.js"),  # VJS-001 MEDIUM
        _obs("/lodash-4.17.10.min.js"),  # VJS-006 HIGH, VJS-007 HIGH
    ]
    analysis = analyze_scripts(scripts)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranks = [severity_order[f.severity] for f in analysis.findings]
    assert ranks == sorted(ranks)


def test_analyze_scripts_empty():
    analysis = analyze_scripts([])
    assert analysis.total_scripts == 0
    assert analysis.findings == ()


def test_analyze_scripts_unknown_library_silent():
    analysis = analyze_scripts([_obs("/proprietary-vendor-app.js")])
    assert analysis.findings == ()


# =====================================================================
# Realistic mixed scenario
# =====================================================================


def test_realistic_legacy_site_scan():
    """Old site with jQuery 1.x + outdated bootstrap + lodash."""
    scripts = [
        _obs("/static/jquery-1.11.3.min.js"),  # VJS-001, VJS-002, VJS-016
        _obs("/static/bootstrap-3.3.7.min.js"),  # VJS-005
        _obs("/static/lodash-4.17.5.min.js"),  # VJS-006, VJS-007
    ]
    analysis = analyze_scripts(scripts)
    rule_ids = {f.rule_id for f in analysis.findings}
    assert "VJS-001" in rule_ids
    assert "VJS-002" in rule_ids
    assert "VJS-005" in rule_ids
    assert "VJS-006" in rule_ids
    assert "VJS-007" in rule_ids
    assert "VJS-016" in rule_ids


# =====================================================================
# Pin + frozen
# =====================================================================


def test_all_rules_pinned():
    expected = {f"VJS-{n:03d}" for n in range(1, 51)}
    assert expected == ALL_VJS_RULES


# =====================================================================
# F102 v2 — expanded catalog tests
# =====================================================================


def test_vjs_017_vue_pre_270():
    findings = _classify_observation(_obs("/vue-2.6.14.min.js"))
    assert any(f.rule_id == "VJS-017" for f in findings)


def test_vjs_018_react_pre_1642():
    findings = _classify_observation(_obs("/react-16.4.1.min.js"))
    assert any(f.rule_id == "VJS-018" for f in findings)


def test_vjs_021_ember_pre_3240():
    findings = _classify_observation(_obs("/ember-3.20.0.min.js"))
    assert any(f.rule_id == "VJS-021" for f in findings)


def test_vjs_022_backbone_pre_141():
    findings = _classify_observation(_obs("/backbone-1.3.3.min.js"))
    assert any(f.rule_id == "VJS-022" for f in findings)


def test_vjs_024_prototype_pre_174_high():
    findings = _classify_observation(_obs("/prototype-1.7.3.min.js"))
    assert any(f.rule_id == "VJS-024" and f.severity == "HIGH" for f in findings)


def test_vjs_026_marked_pre_4010():
    findings = _classify_observation(_obs("/marked-4.0.9.min.js"))
    assert any(f.rule_id == "VJS-026" for f in findings)


def test_vjs_028_ejs_pre_317_critical():
    findings = _classify_observation(_obs("/ejs-3.1.6.min.js"))
    assert any(f.rule_id == "VJS-028" and f.severity == "CRITICAL" for f in findings)


def test_vjs_030_pug_pre_301_critical():
    findings = _classify_observation(_obs("/pug-3.0.0.min.js"))
    assert any(f.rule_id == "VJS-030" and f.severity == "CRITICAL" for f in findings)


def test_vjs_032_jsonwebtoken_pre_900_critical():
    findings = _classify_observation(_obs("/jsonwebtoken/8.5.1/index.js"))
    assert any(f.rule_id == "VJS-032" and f.severity == "CRITICAL" for f in findings)


def test_vjs_034_express_pre_4173():
    findings = _classify_observation(_obs("/express-4.17.0.min.js"))
    assert any(f.rule_id == "VJS-034" for f in findings)


def test_vjs_038_semver_pre_752():
    findings = _classify_observation(_obs("/semver-7.5.1.min.js"))
    assert any(f.rule_id == "VJS-038" for f in findings)


def test_vjs_040_crypto_js_pre_420():
    findings = _classify_observation(_obs("/crypto-js-4.1.1.min.js"))
    assert any(f.rule_id == "VJS-040" for f in findings)


def test_vjs_044_ckeditor_pre_4240():
    findings = _classify_observation(_obs("/ckeditor/4.22.1/ckeditor.js"))
    assert any(f.rule_id == "VJS-044" for f in findings)


def test_vjs_045_tinymce_pre_5100():
    findings = _classify_observation(_obs("/tinymce/5.9.0/tinymce.min.js"))
    assert any(f.rule_id == "VJS-045" for f in findings)


def test_vjs_046_chartjs_pre_294():
    findings = _classify_observation(_obs("/chart-2.9.3.min.js"))
    assert any(f.rule_id == "VJS-046" for f in findings)


def test_modern_versions_clean():
    """Each newer-than-fixed version should produce 0 findings."""
    clean_cases = [
        "/vue-3.4.0.min.js",
        "/react-18.2.0.min.js",
        "/marked-12.0.0.min.js",
        "/ejs-3.1.10.min.js",
        "/pug-3.0.3.min.js",
        "/express-5.0.0.min.js",
        "/semver-7.6.0.min.js",
        "/ckeditor/4.24.0/ckeditor.js",
        "/tinymce/6.0.0/tinymce.min.js",
        "/chart-4.4.0.min.js",
    ]
    for src in clean_cases:
        findings = _classify_observation(_obs(src))
        assert findings == [], f"Expected no findings for {src}, got {findings}"


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    obs = ScriptObservation(src="/x.js")
    with pytest.raises(FrozenInstanceError):
        obs.src = "/y.js"  # type: ignore[misc]


def test_version_tuple_padding():
    """3.4 should be treated as 3.4.0 — less than 3.4.1."""
    findings = _classify_observation(_obs("/jquery-3.4.min.js"))
    ids = {f.rule_id for f in findings}
    assert "VJS-001" in ids  # 3.4 < 3.5.0
    assert "VJS-002" not in ids  # 3.4 (= 3.4.0) is NOT < 3.4.0
