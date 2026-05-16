"""F164 — ``nuclei_scan`` must strip LLM-invented bare keyword templates.

Both gpt-oss-20b and kryon-14b sometimes pass ``templates="web"`` or
``templates="all"`` thinking those are nuclei categories. They aren't —
nuclei rejects them with ``[ERR] Could not find template 'web'`` and the
whole scan never runs. The benches F163-F164 both stalled on this.

The fix: validate before the ``-t`` flag is added. Real nuclei templates
contain a ``/`` (directory) or end in ``.yaml`` (single file). Bare
keywords are silently dropped so the scan falls through to nuclei's
auto-selected default template set, which is the right choice for
recon anyway.

These tests pin the behavior with a mock ``run_command`` so we don't
need an actual nuclei binary.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from kryon.tools.web import nuclei as nuclei_module


def _captured_command():
    """Return ``(command_str,)`` actually passed to ``run_command``."""
    return getattr(nuclei_module.run_command, "_captured", None)


@pytest.fixture(autouse=True)
def _clear_scan_cache():
    """The ``@cache_scan_result`` decorator on ``nuclei_scan`` would
    otherwise reuse a result from a prior test, never invoking the
    recorded ``run_command`` and leaving ``captured["cmd"]`` empty."""
    from kryon.cache import scan_cache as sc_module
    from kryon.cache.cache_manager import CacheManager

    fresh = CacheManager(enable_persistence=False)

    class _FreshScanCache(sc_module.ScanCache):
        def __init__(self):
            super().__init__(cache_manager=fresh)

    import pytest as _pytest

    mp = _pytest.MonkeyPatch()
    mp.setattr(sc_module, "_global_scan_cache", None)
    mp.setattr(sc_module, "ScanCache", _FreshScanCache)
    yield
    mp.undo()


@pytest.fixture
def fake_run_command(monkeypatch):
    """Replace ``run_command`` with a recorder. The wrapped tool returns
    the captured command string so the test can assert on it directly."""
    captured: dict[str, str] = {}

    def _fake(command, *args, **kwargs):
        captured["cmd"] = command
        # Return a benign success-shaped output so the failure-detector
        # in the tool wrapper doesn't wrap it.
        return "[INF] Templates loaded: 100\nNo results found."

    monkeypatch.setattr(nuclei_module, "run_command", _fake)
    return captured


# ---------------------------------------------------------------------------
# Bare keywords from real F163/F164 benches → must be dropped
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_value", ["web", "all", "default", "web-templates"])
def test_bare_keyword_templates_stripped(bad_value, fake_run_command):
    nuclei_module.nuclei_scan._raw_fn(
        target="http://x.example", templates=bad_value, stats=False
    )
    cmd = fake_run_command["cmd"]
    # The "-t" flag must NOT appear with the bad value.
    assert f"-t {bad_value}" not in cmd, (
        f"Bare keyword {bad_value!r} should have been stripped; got: {cmd!r}"
    )
    # And no "-t" at all (since there's no workflow/auto fallback path
    # in this scenario — falls through to nuclei's default set).
    assert " -t " not in cmd, (
        f"No -t flag expected when templates is a bare keyword; got: {cmd!r}"
    )


# ---------------------------------------------------------------------------
# Real template directories must still be passed through
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "good_value",
    ["cves/", "vulnerabilities/", "default-logins/", "exposures/", "/custom/path/"],
)
def test_directory_templates_passed_through(good_value, fake_run_command):
    nuclei_module.nuclei_scan._raw_fn(
        target="http://x.example", templates=good_value, stats=False
    )
    cmd = fake_run_command["cmd"]
    assert f"-t {good_value}" in cmd


# ---------------------------------------------------------------------------
# Single template file (.yaml) must also pass through
# ---------------------------------------------------------------------------


def test_yaml_template_file_passed_through(fake_run_command):
    nuclei_module.nuclei_scan._raw_fn(
        target="http://x.example",
        templates="custom-sqli-check.yaml",
        stats=False,
    )
    cmd = fake_run_command["cmd"]
    assert "-t custom-sqli-check.yaml" in cmd


# ---------------------------------------------------------------------------
# Empty templates → no -t flag (default behavior preserved)
# ---------------------------------------------------------------------------


def test_empty_templates_no_t_flag(fake_run_command):
    nuclei_module.nuclei_scan._raw_fn(
        target="http://x.example", templates="", stats=False
    )
    cmd = fake_run_command["cmd"]
    assert " -t " not in cmd


# ---------------------------------------------------------------------------
# Relative path with "./" prefix accepted
# ---------------------------------------------------------------------------


def test_relative_path_templates_accepted(fake_run_command):
    nuclei_module.nuclei_scan._raw_fn(
        target="http://x.example", templates="./local-templates", stats=False
    )
    cmd = fake_run_command["cmd"]
    assert "-t ./local-templates" in cmd
