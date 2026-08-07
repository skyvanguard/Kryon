"""Test that TUI modules can be imported."""

import pytest

pytest.importorskip("textual")  # requires the optional `tui` extra


def test_import_tui_package():
    from kryon.tui import KryonTUI

    assert KryonTUI is not None


def test_import_widgets():
    from kryon.tui.widgets.agent_sidebar import AgentSidebar
    from kryon.tui.widgets.chat_panel import ChatPanel
    from kryon.tui.widgets.cost_panel import CostPanel
    from kryon.tui.widgets.log_panel import LogPanel
    from kryon.tui.widgets.status_bar import StatusBar

    assert all([ChatPanel, AgentSidebar, CostPanel, LogPanel, StatusBar])


def test_import_hooks():
    from kryon.tui.hooks import TUIRunHooks

    assert TUIRunHooks is not None
