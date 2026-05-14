"""F145 — REST API tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Skip the entire module if FastAPI isn't installed.
fastapi = pytest.importorskip("fastapi")
test_client_mod = pytest.importorskip("fastapi.testclient")


from kryon.api.rest import build_app  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("KRYON_API_TOKEN", raising=False)
    return test_client_mod.TestClient(build_app())


def _seed_state(tmp_path: Path, engagement_id: str = "eng-1") -> None:
    state_dir = tmp_path / ".kryon" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "x.com.json").write_text(
        json.dumps(
            {
                "target": "x.com",
                "last_engagement_id": engagement_id,
                "last_run_ts": "2026-05-14T18:00:00Z",
                "findings_path": "",
                "finding_count": 3,
            }
        ),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


def test_health_returns_check_results(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert "ok" in body
    assert "checks" in body


def test_health_requires_token_when_set(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KRYON_API_TOKEN", "secret")
    c = test_client_mod.TestClient(build_app())
    resp = c.get("/health")
    assert resp.status_code == 401
    resp_ok = c.get("/health", headers={"X-API-Token": "secret"})
    assert resp_ok.status_code == 200


# ---------------------------------------------------------------------------
# /engagements
# ---------------------------------------------------------------------------


def test_list_engagements_empty(client):
    resp = client.get("/engagements")
    assert resp.status_code == 200
    assert resp.json()["engagements"] == []


def test_list_engagements_returns_state_files(client, tmp_path):
    _seed_state(tmp_path)
    resp = client.get("/engagements")
    body = resp.json()
    assert body["count"] == 1
    assert body["engagements"][0]["last_engagement_id"] == "eng-1"


def test_get_engagement_by_id(client, tmp_path):
    _seed_state(tmp_path, engagement_id="eng-A")
    resp = client.get("/engagements/eng-A")
    assert resp.status_code == 200
    assert resp.json()["last_engagement_id"] == "eng-A"


def test_get_engagement_not_found(client):
    resp = client.get("/engagements/nope")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# /audit/summary
# ---------------------------------------------------------------------------


def test_audit_summary_empty_dir(client):
    resp = client.get("/audit/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["engagements"] == 0
    assert body["tool_calls"] == 0


# ---------------------------------------------------------------------------
# /schedule, /queue, /approvals
# ---------------------------------------------------------------------------


def test_schedule_empty(client):
    resp = client.get("/schedule")
    assert resp.status_code == 200
    assert resp.json()["jobs"] == []


def test_queue_empty(client):
    resp = client.get("/queue")
    assert resp.status_code == 200
    assert resp.json()["items"] == []


def test_approvals_empty(client):
    resp = client.get("/approvals")
    assert resp.status_code == 200
    assert resp.json()["pending"] == []


# ---------------------------------------------------------------------------
# /findings/<id>
# ---------------------------------------------------------------------------


def test_findings_not_found(client):
    resp = client.get("/findings/missing-eng")
    assert resp.status_code == 404
