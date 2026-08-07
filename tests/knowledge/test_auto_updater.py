"""Tests for refactored auto-updater using SCRAPER_REGISTRY."""

import importlib
from unittest.mock import MagicMock, patch

import pytest

try:
    _mod = importlib.import_module("kryon.knowledge.auto_updater")
    AutoUpdater = _mod.AutoUpdater
except (ImportError, ModuleNotFoundError):
    pytest.skip("RAG dependencies not installed", allow_module_level=True)


def test_auto_updater_init():
    updater = AutoUpdater()
    assert updater.running is False
    assert updater.last_update == {}
    assert len(updater.update_stats) == 0


def test_auto_updater_stats():
    updater = AutoUpdater()
    stats = updater.get_stats()
    assert stats["running"] is False
    assert stats["total_updates"] == 0


@patch("kryon.knowledge.auto_updater.AutoUpdater._update_from_source")
def test_run_once(mock_update):
    """run_once() should call _update_from_source for each source."""
    mock_update.return_value = 5

    updater = AutoUpdater()
    result = updater.run_once(sources=["nvd", "github"])

    assert result["total_added"] == 10
    assert result["sources"]["nvd"]["added"] == 5
    assert result["sources"]["github"]["added"] == 5
    assert mock_update.call_count == 2


@patch("kryon.knowledge.auto_updater.AutoUpdater._update_from_source")
def test_run_once_handles_errors(mock_update):
    """Errors in one source shouldn't stop others."""

    def side_effect(source):
        if source == "nvd":
            raise RuntimeError("API down")
        return 3

    mock_update.side_effect = side_effect

    updater = AutoUpdater()
    result = updater.run_once(sources=["nvd", "github"])

    assert result["total_added"] == 3
    assert result["sources"]["nvd"]["success"] is False
    assert "API down" in result["sources"]["nvd"]["error"]
    assert result["sources"]["github"]["success"] is True


def test_update_from_source_unknown():
    """Unknown source names should return 0."""
    updater = AutoUpdater()
    # Patch rag engine to avoid actual initialization
    with patch("kryon.knowledge.auto_updater.AutoUpdater._update_from_source") as mock:
        mock.return_value = 0
        result = updater.run_once(sources=["nonexistent-source-xyz"])
        # run_once delegates to _update_knowledge which calls _update_from_source
        # Since we mocked it, it returns 0

    # Test the real _update_from_source with unknown source
    with patch("kryon.knowledge.rag_engine.get_rag_engine") as mock_rag:
        added = updater._update_from_source("definitely-not-a-source")
        assert added == 0


@patch("kryon.knowledge.auto_updater.AutoUpdater._update_from_source")
def test_run_once_default_sources(mock_update):
    """Default sources should include all registered except static-seed."""
    mock_update.return_value = 0

    updater = AutoUpdater()
    updater.run_once()

    called_sources = [call.args[0] for call in mock_update.call_args_list]
    assert "static-seed" not in called_sources
    assert "nvd" in called_sources
    assert "github" in called_sources


@patch("kryon.knowledge.auto_updater.AutoUpdater._update_from_source")
def test_update_records_stats(mock_update):
    """Stats should be recorded after each update."""
    mock_update.return_value = 2

    updater = AutoUpdater()
    updater.run_once(sources=["nvd"])

    assert len(updater.update_stats) == 1
    assert updater.update_stats[0]["total_added"] == 2
    assert "elapsed_time" in updater.update_stats[0]
    assert "nvd" in updater.last_update
