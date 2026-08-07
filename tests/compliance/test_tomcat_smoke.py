"""F200.A — Apache Tomcat compliance smoke tests.

Verifies:
  1. All 8 TOMCAT-* check modules import cleanly and self-register.
  2. The framework prefix filter selects only TOMCAT-* IDs.
  3. Sample parsers produce the right verdict against synthetic
     TomcatFingerprint inputs.
  4. The Protocol contract (title/severity/remediation) is satisfied.
"""

from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.compliance.checks.base import CheckContext
from kryon.compliance.runner import _import_all_checks, registered_checks
from kryon.tools.web.tomcat_recon import TomcatFingerprint


@pytest.fixture(scope="module", autouse=True)
def _ensure_checks_loaded() -> None:
    _import_all_checks()


def _ids_with_prefix(prefix: str) -> list[str]:
    return [c.control_id for c in registered_checks() if c.control_id.startswith(prefix)]


def _ctx() -> CheckContext:
    return CheckContext(host="10.0.0.5", transport="local")


def _fp(**overrides) -> TomcatFingerprint:
    """Build a TomcatFingerprint with defaults that make sense for a
    healthy Tomcat 9 install (so override only what each test cares
    about)."""
    defaults = {
        "host": "10.0.0.5",
        "port": 8080,
        "is_tomcat": True,
        "version": "9.0.91",
        "server_header": "",  # suppressed
        "manager_status": 404,
        "host_manager_status": 404,
        "docs_status": 404,
        "examples_status": 404,
        "ajp_open": False,
        "error_page_leaks_version": False,
    }
    defaults.update(overrides)
    return TomcatFingerprint(**defaults)


def _patch_fp(monkeypatch, fp: TomcatFingerprint) -> None:
    """Patch the lru_cached `fingerprint` to return our test FP.

    We patch the helper at the symbol each check imported it from —
    individual check modules `from kryon.compliance.checks.tomcat._common
    import fingerprint`, so we set the attribute on the check module.
    """
    # Reset lru_cache so the patched value flows through.
    from kryon.compliance.checks.tomcat import _common as common_mod

    common_mod.fingerprint.cache_clear()
    monkeypatch.setattr(common_mod, "fingerprint", lambda *a, **kw: fp)
    # Each check module imported `fingerprint` as a local name — patch
    # those references too.
    from kryon.compliance.checks.tomcat import (
        c_tomcat_1_1_version_eol,
        c_tomcat_1_2_ajp_ghostcat,
        c_tomcat_1_3_manager_exposed,
        c_tomcat_1_4_host_manager_exposed,
        c_tomcat_2_1_error_page_version_leak,
        c_tomcat_2_2_server_header_disclosure,
        c_tomcat_2_3_docs_accessible,
        c_tomcat_2_4_examples_accessible,
    )

    for mod in (
        c_tomcat_1_1_version_eol,
        c_tomcat_1_2_ajp_ghostcat,
        c_tomcat_1_3_manager_exposed,
        c_tomcat_1_4_host_manager_exposed,
        c_tomcat_2_1_error_page_version_leak,
        c_tomcat_2_2_server_header_disclosure,
        c_tomcat_2_3_docs_accessible,
        c_tomcat_2_4_examples_accessible,
    ):
        monkeypatch.setattr(mod, "fingerprint", lambda *a, **kw: fp)


# ---------------------------------------------------------------------------
# Registration + protocol contract
# ---------------------------------------------------------------------------


def test_all_8_tomcat_checks_registered() -> None:
    ids = _ids_with_prefix("TOMCAT-")
    expected = {
        "TOMCAT-1.1",
        "TOMCAT-1.2",
        "TOMCAT-1.3",
        "TOMCAT-1.4",
        "TOMCAT-2.1",
        "TOMCAT-2.2",
        "TOMCAT-2.3",
        "TOMCAT-2.4",
    }
    assert set(ids) == expected, f"missing or extra: {set(ids) ^ expected}"


def test_protocol_contract_satisfied() -> None:
    for c in registered_checks():
        if not c.control_id.startswith("TOMCAT-"):
            continue
        assert c.control_title
        assert c.section
        assert c.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert c.remediation_static


def test_framework_prefix_aliases() -> None:
    from kryon.tools.appsec.compliance_audit import _FRAMEWORK_PREFIX

    assert _FRAMEWORK_PREFIX["tomcat"] == ("TOMCAT-",)
    assert _FRAMEWORK_PREFIX["apache-tomcat"] == ("TOMCAT-",)
    assert _FRAMEWORK_PREFIX["coyote"] == ("TOMCAT-",)


# ---------------------------------------------------------------------------
# TOMCAT-1.1 version EOL
# ---------------------------------------------------------------------------


class TestVersionEol:
    def test_tomcat_7_fails(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_1_1_version_eol as mod

        _patch_fp(monkeypatch, _fp(version="7.0.34"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"
        assert res.evidence_parsed["major"] == 7

    def test_tomcat_8_fails(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_1_1_version_eol as mod

        _patch_fp(monkeypatch, _fp(version="8.5.85"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_tomcat_9_passes(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_1_1_version_eol as mod

        _patch_fp(monkeypatch, _fp(version="9.0.91"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_tomcat_11_passes(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_1_1_version_eol as mod

        _patch_fp(monkeypatch, _fp(version="11.0.0"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_non_tomcat_is_na(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_1_1_version_eol as mod

        _patch_fp(monkeypatch, _fp(is_tomcat=False, version=""))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "N/A"

    def test_tomcat_without_version_is_error(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_1_1_version_eol as mod

        _patch_fp(monkeypatch, _fp(is_tomcat=True, version=""))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "ERROR"


# ---------------------------------------------------------------------------
# TOMCAT-1.2 AJP Ghostcat
# ---------------------------------------------------------------------------


class TestAjpGhostcat:
    def test_ajp_open_fails(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_1_2_ajp_ghostcat as mod

        _patch_fp(monkeypatch, _fp(ajp_open=True))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_ajp_closed_passes(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_1_2_ajp_ghostcat as mod

        _patch_fp(monkeypatch, _fp(ajp_open=False))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"


# ---------------------------------------------------------------------------
# TOMCAT-1.3 manager exposed
# ---------------------------------------------------------------------------


class TestManagerExposed:
    def test_manager_200_fails(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_1_3_manager_exposed as mod

        _patch_fp(monkeypatch, _fp(manager_status=200))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_manager_401_fails(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_1_3_manager_exposed as mod

        _patch_fp(monkeypatch, _fp(manager_status=401))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_manager_404_passes(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_1_3_manager_exposed as mod

        _patch_fp(monkeypatch, _fp(manager_status=404))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_manager_403_passes(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_1_3_manager_exposed as mod

        _patch_fp(monkeypatch, _fp(manager_status=403))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"


# ---------------------------------------------------------------------------
# TOMCAT-2.1 error page version leak
# ---------------------------------------------------------------------------


class TestErrorPageVersionLeak:
    def test_leak_fails(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_2_1_error_page_version_leak as mod

        _patch_fp(monkeypatch, _fp(error_page_leaks_version=True))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_no_leak_passes(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_2_1_error_page_version_leak as mod

        _patch_fp(monkeypatch, _fp(error_page_leaks_version=False))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"


# ---------------------------------------------------------------------------
# TOMCAT-2.2 server header disclosure
# ---------------------------------------------------------------------------


class TestServerHeaderDisclosure:
    def test_coyote_header_fails(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_2_2_server_header_disclosure as mod

        _patch_fp(monkeypatch, _fp(server_header="Apache-Coyote/1.1"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_tomcat_header_fails(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_2_2_server_header_disclosure as mod

        _patch_fp(monkeypatch, _fp(server_header="Apache Tomcat/9.0.91"))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_suppressed_header_passes(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_2_2_server_header_disclosure as mod

        _patch_fp(monkeypatch, _fp(server_header=""))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"


# ---------------------------------------------------------------------------
# TOMCAT-2.3 / 2.4 default webapps
# ---------------------------------------------------------------------------


class TestDefaultWebapps:
    def test_docs_deployed_fails(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_2_3_docs_accessible as mod

        _patch_fp(monkeypatch, _fp(docs_status=200))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"

    def test_docs_404_passes(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_2_3_docs_accessible as mod

        _patch_fp(monkeypatch, _fp(docs_status=404))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "PASS"

    def test_examples_deployed_fails(self, monkeypatch):
        from kryon.compliance.checks.tomcat import c_tomcat_2_4_examples_accessible as mod

        _patch_fp(monkeypatch, _fp(examples_status=200))
        res = mod.CHECK.run(_ctx())
        assert res.verdict == "FAIL"


# ---------------------------------------------------------------------------
# Example regression scenario — Tomcat 7.0.34 with everything wide open
# ---------------------------------------------------------------------------


def test_example_h11_tomcat_7_0_34_full_scenario(monkeypatch):
    """The exact case from .11: Tomcat 7.0.34, AJP probably open,
    Manager exposed with Basic auth, error page leaks version."""
    from kryon.compliance.checks.tomcat import (
        c_tomcat_1_1_version_eol,
        c_tomcat_1_2_ajp_ghostcat,
        c_tomcat_1_3_manager_exposed,
        c_tomcat_2_1_error_page_version_leak,
        c_tomcat_2_2_server_header_disclosure,
    )

    example_fp = _fp(
        version="7.0.34",
        server_header="Apache-Coyote/1.1",
        manager_status=401,
        host_manager_status=401,
        docs_status=404,
        examples_status=404,
        ajp_open=True,
        error_page_leaks_version=True,
    )
    _patch_fp(monkeypatch, example_fp)

    assert c_tomcat_1_1_version_eol.CHECK.run(_ctx()).verdict == "FAIL"
    assert c_tomcat_1_2_ajp_ghostcat.CHECK.run(_ctx()).verdict == "FAIL"
    assert c_tomcat_1_3_manager_exposed.CHECK.run(_ctx()).verdict == "FAIL"
    assert c_tomcat_2_1_error_page_version_leak.CHECK.run(_ctx()).verdict == "FAIL"
    assert c_tomcat_2_2_server_header_disclosure.CHECK.run(_ctx()).verdict == "FAIL"
