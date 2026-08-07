"""Tests for the /reports/{filename}/download endpoint.

Exercises the endpoint function directly (fast, avoids TestClient lifespan).
Covers the happy path (streams a generated file) and the path-traversal /
bad-extension guards.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.responses import FileResponse

import kryon.reporting.export as export_mod
from kryon.server.routes.reports import download_report


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    """Point the reports store at a temp dir with one report file in it."""
    monkeypatch.setattr(export_mod, "_REPORTS_DIR", tmp_path)
    (tmp_path / "cliente_technical_20260728.html").write_text("<h1>report</h1>", encoding="utf-8")
    return tmp_path


async def test_download_streams_existing_report(reports_dir):
    resp = await download_report("cliente_technical_20260728.html")

    assert isinstance(resp, FileResponse)
    assert resp.media_type == "text/html"
    assert resp.status_code == 200


async def test_download_rejects_path_traversal(reports_dir):
    with pytest.raises(HTTPException) as exc:
        await download_report("../../secret.pdf")
    assert exc.value.status_code == 400


@pytest.mark.parametrize("bad", ["evil.txt", "evil.exe", "passwd", "report"])
async def test_download_rejects_disallowed_extensions(reports_dir, bad):
    with pytest.raises(HTTPException) as exc:
        await download_report(bad)
    assert exc.value.status_code == 400


async def test_download_missing_file_is_404(reports_dir):
    with pytest.raises(HTTPException) as exc:
        await download_report("does_not_exist.pdf")
    assert exc.value.status_code == 404
