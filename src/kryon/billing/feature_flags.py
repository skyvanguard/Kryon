"""Feature flags per license tier."""

from __future__ import annotations

FEATURE_FLAGS: dict[str, list[str]] = {
    "free": [
        "basic_scanning",
        "api_access",
    ],
    "standard": [
        "basic_scanning",
        "api_access",
        "engagements",
        "compliance_reports",
        "multi_agent",
    ],
    "enterprise": [
        "basic_scanning",
        "api_access",
        "engagements",
        "siem_integration",
        "custom_branding",
        "attack_paths",
        "compliance_reports",
        "multi_agent",
        "llm_security",
    ],
}


def get_tier_features(tier: str) -> list[str]:
    """Get enabled features for a tier."""
    return FEATURE_FLAGS.get(tier.lower(), FEATURE_FLAGS["free"])


def is_feature_available(tier: str, feature: str) -> bool:
    """Check if a feature is available in a tier."""
    return feature in get_tier_features(tier)
