"""JWT-based license validation using RS256."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


class LicenseValidator:
    """Validate and generate JWT license keys using RS256."""

    def __init__(self, public_key: str = "", private_key: str = ""):
        self._public_key = public_key
        self._private_key = private_key

    def validate(self, license_key: str) -> dict | None:
        """Validate a license key. Returns decoded payload or None."""
        try:
            import jwt
        except ImportError as exc:
            raise ImportError("PyJWT is required. Install with: pip install PyJWT[crypto]") from exc

        if not self._public_key:
            logger.warning("No public key configured for license validation")
            return None

        try:
            payload = jwt.decode(
                license_key,
                self._public_key,
                algorithms=["RS256"],
                options={"require": ["tenant_id", "tier", "exp"]},
            )
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("License expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning("Invalid license: %s", e)
            return None

    def is_feature_enabled(self, license_payload: dict | None, feature: str) -> bool:
        """Check if a feature is enabled in the license."""
        if not license_payload:
            return False
        features = license_payload.get("features", [])
        return feature in features

    def generate_license(
        self,
        tenant_id: str,
        tier: str,
        features: list[str],
        expires_days: int = 365,
    ) -> str:
        """Generate a new license key (admin CLI use)."""
        try:
            import jwt
        except ImportError as exc:
            raise ImportError("PyJWT[crypto] is required for license generation") from exc

        if not self._private_key:
            raise ValueError("Private key required for license generation")

        now = datetime.now(timezone.utc)
        payload = {
            "tenant_id": tenant_id,
            "tier": tier,
            "features": features,
            "iat": now,
            "exp": now + timedelta(days=expires_days),
            "iss": "kryon-license-server",
        }

        return jwt.encode(payload, self._private_key, algorithm="RS256")
