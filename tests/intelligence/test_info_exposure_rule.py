"""Sensitive information exposure rule (CWE-200).

Distinct from _rule_web_loot_credentials (which hunts creds/hashes in backups). This proves
disclosure of sensitive DATA that shouldn't be readable unauthenticated: confidential business docs,
app config/secrets, telemetry/actuator, and directory listings — each confirmed by a type-specific
marker in the body (not merely a 200). Validated shape against OWASP Juice Shop's exposed vectors.
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import _rule_info_exposure
from kryon.intelligence.fact_extractor import ExtractedFacts

_WEB = ExtractedFacts(services=((80, "http"),), hosts=("shop.thm",), paths=("/ftp",))


def test_info_exposure_closes_sensitive_disclosure():
    rec = _rule_info_exposure(_WEB, [], "")
    assert rec is not None
    assert "INFO-EXPOSURE" in rec.args
    # the four vectors confirmed live on Juice Shop
    assert "acquisitions.md" in rec.args  # confidential business document
    assert "application-configuration" in rec.args  # app config / secrets leak
    assert "/metrics" in rec.args  # exposed telemetry
    # type-specific proof classifiers (not just a 200)
    assert "do not distribute" in rec.args.lower() or "confidential" in rec.args.lower()
    assert "# (HELP|TYPE)" in rec.args or "HELP|TYPE" in rec.args  # prometheus format
    # hostlist real + guards heredados
    assert "<target>" not in rec.args
    assert "shop.thm" in rec.args
    assert "|| true" in rec.args
    assert "<(!doctype|html" in rec.args  # SPA/HTML fallback filtered on the config vector


def test_info_exposure_abstains_without_web_or_surface():
    assert _rule_info_exposure(ExtractedFacts(hosts=("x",), paths=("/ftp",)), [], "") is None
    assert _rule_info_exposure(ExtractedFacts(services=((80, "http"),), hosts=("x",)), [], "") is None
    assert _rule_info_exposure(_WEB, ["info_exposure ran"], "") is None
