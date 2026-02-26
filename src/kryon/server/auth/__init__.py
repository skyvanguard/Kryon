"""Authentication package — backward-compatible re-exports."""

from kryon.server.auth.api_key import configure_auth, require_api_key

__all__ = ["configure_auth", "require_api_key"]
