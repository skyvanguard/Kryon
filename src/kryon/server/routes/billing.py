"""Billing and licensing API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from kryon.server.auth import require_api_key
from kryon.server.deps import get_store
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["billing"], dependencies=[Depends(require_api_key)])


class LicenseValidateBody(BaseModel):
    license_key: str = Field(..., min_length=1)


@router.post("/billing/license/validate")
async def validate_license(body: LicenseValidateBody) -> dict:
    """Validate a license key."""
    import os

    public_key = os.environ.get("KRYON_LICENSE_PUBLIC_KEY", "")
    if not public_key:
        return {"valid": False, "error": "License validation not configured"}

    from kryon.billing.license_validator import LicenseValidator

    validator = LicenseValidator(public_key=public_key)
    payload = validator.validate(body.license_key)

    if payload:
        logger.info("License validated: tenant=%s tier=%s", payload.get("tenant_id"), payload.get("tier"))
        return {
            "valid": True,
            "tenant_id": payload.get("tenant_id"),
            "tier": payload.get("tier"),
            "features": payload.get("features", []),
        }
    logger.warning("Invalid license validation attempt")
    return {"valid": False, "error": "Invalid or expired license"}


@router.get("/billing/usage")
async def get_usage(tenant_id: str = "", period: str = "") -> dict:
    """Get usage summary for a tenant."""
    store = get_store()
    from kryon.billing.metering import get_usage_summary

    summary = get_usage_summary(store, tenant_id=tenant_id, period=period)
    return {"tenant_id": tenant_id, "usage": summary}


@router.get("/billing/features")
async def get_features(tenant_id: str = "") -> dict:
    """Get enabled features for a tenant."""
    store = get_store()
    license_data = store.get_license(tenant_id) if tenant_id else None
    tier = license_data.get("tier", "free") if license_data else "free"

    from kryon.billing.feature_flags import get_tier_features

    return {"tenant_id": tenant_id, "tier": tier, "features": get_tier_features(tier)}


@router.get("/billing/limits")
async def get_limits(tenant_id: str = "") -> dict:
    """Get resource limits vs current usage."""
    store = get_store()
    license_data = store.get_license(tenant_id) if tenant_id else None
    tier = license_data.get("tier", "free") if license_data else "free"

    from kryon.billing.metering import TIER_LIMITS, check_limit

    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])

    result = {}
    for resource, max_val in limits.items():
        allowed, remaining = check_limit(store, tenant_id, resource, tier)
        result[resource] = {"limit": max_val, "remaining": remaining, "allowed": allowed}

    return {"tenant_id": tenant_id, "tier": tier, "limits": result}


@router.post("/billing/webhooks/stripe")
async def stripe_webhook() -> dict:
    """Stripe webhook receiver (future-ready stub)."""
    logger.info("Stripe webhook received")
    return {"received": True, "status": "not_implemented"}
