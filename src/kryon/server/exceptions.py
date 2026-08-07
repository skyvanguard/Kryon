"""Shared HTTP exception helpers for consistent API error responses."""

from __future__ import annotations

from fastapi import HTTPException


def not_found(resource: str, resource_id: str) -> HTTPException:
    """Return a 404 HTTPException with a standardized message."""
    return HTTPException(status_code=404, detail=f"{resource} '{resource_id}' not found")
