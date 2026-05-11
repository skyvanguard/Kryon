"""Tests for billing API routes."""

import pytest


def test_validate_license_no_key_configured(client):
    resp = client.post(
        "/api/v1/billing/license/validate",
        json={"license_key": "some.jwt.token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False


def test_get_usage(client):
    resp = client.get("/api/v1/billing/usage?tenant_id=t1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tenant_id"] == "t1"
    assert "usage" in data


def test_get_features_default(client):
    resp = client.get("/api/v1/billing/features")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tier"] == "free"
    assert isinstance(data["features"], list)


def test_get_features_with_tenant(client):
    resp = client.get("/api/v1/billing/features?tenant_id=unknown")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tier"] == "free"


def test_get_limits(client):
    resp = client.get("/api/v1/billing/limits")
    assert resp.status_code == 200
    data = resp.json()
    assert "limits" in data
    assert data["tier"] == "free"


def test_stripe_webhook_not_implemented(client):
    """The Stripe webhook receiver returns 501 by design — billing is
    BYO-keys-only in v2.1. Re-enable as an integration test when the
    receiver is wired up."""
    resp = client.post("/api/v1/billing/webhooks/stripe", json={})
    assert resp.status_code == 501
    assert "not implemented" in resp.json()["detail"].lower()
