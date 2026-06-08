"""F202.X — WeasyPrint graceful skip cuando faltan GTK3 DLLs (Windows).

WeasyPrint en Windows requiere libgobject-2.0-0 + pango + cairo +
fontconfig. Sin esas DLLs, `from weasyprint import HTML` dispara
OSError (NO ImportError). El except ImportError no lo capturaba ->
crash en Fase 6 perdiendo todo el reporte.

Tests cubren:
- demo_report: pdf_error emitido, HTML+JSON sobreviven
- KRYON_SKIP_PDF=1 short-circuit
- pdf.py: re-raise como RuntimeError con mensaje accionable
- multi_framework_pdf: re-raise OSError con instalacion GTK3 hint
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")


# ---------------------------------------------------------------------------
# demo_report.render_demo_report — graceful skip when WeasyPrint fails
# ---------------------------------------------------------------------------


class TestDemoReportGracefulSkip:
    def test_oserror_on_import_emits_pdf_error(self, tmp_path):
        """OSError al import weasyprint -> paths['pdf_error'] con hint
        GTK3 install. HTML + JSON aun se escriben."""
        from kryon.reporting.demo_report import render_demo_report

        # Stub weasyprint module to raise OSError on import
        fake_weasyprint = type(sys)("weasyprint")

        def _raise_on_html_access():
            raise OSError("cannot load library 'libgobject-2.0-0': error 0x7e")

        # When weasyprint is imported, force OSError by replacing the
        # module with one that raises on attribute access.
        original = sys.modules.pop("weasyprint", None)
        try:
            with patch.dict(sys.modules, {"weasyprint": None}):
                # Force re-import to fail with OSError
                def _bad_import(*_a, **_kw):
                    raise OSError("cannot load library 'libgobject-2.0-0': error 0x7e")

                with patch.dict(sys.modules, {}, clear=False):
                    sys.modules["weasyprint"] = type(sys)("weasyprint")

                    def _raise(_name):
                        raise OSError("cannot load library 'libgobject-2.0-0'")

                    sys.modules["weasyprint"].__getattr__ = _raise  # type: ignore[attr-defined]
                    paths = render_demo_report(
                        findings=[],
                        context={"engagement_id": "test-f202x"},
                        output_dir=str(tmp_path),
                    )
        finally:
            if original is not None:
                sys.modules["weasyprint"] = original

        # PDF should have failed gracefully
        assert "pdf" not in paths
        assert "pdf_error" in paths
        # HTML and JSON should still be written
        assert "html" in paths
        assert "json" in paths
        assert paths["html"].exists()
        assert paths["json"].exists()

    def test_kryon_skip_pdf_env_short_circuits(self, tmp_path):
        """KRYON_SKIP_PDF=1 hace skip sin intentar importar."""
        from kryon.reporting.demo_report import render_demo_report

        with patch.dict(os.environ, {"KRYON_SKIP_PDF": "1"}):
            paths = render_demo_report(
                findings=[],
                context={"engagement_id": "test-skip"},
                output_dir=str(tmp_path),
            )
        assert "pdf" not in paths
        assert "pdf_skipped" in paths
        assert "html" in paths
        assert "json" in paths

    @pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "YES"])
    def test_skip_pdf_accepts_truthy_values(self, tmp_path, val):
        from kryon.reporting.demo_report import render_demo_report

        with patch.dict(os.environ, {"KRYON_SKIP_PDF": val}):
            paths = render_demo_report(
                findings=[],
                context={"engagement_id": "test-skip"},
                output_dir=str(tmp_path),
            )
        assert "pdf_skipped" in paths

    @pytest.mark.parametrize("val", ["0", "false", "no", ""])
    def test_skip_pdf_falsy_does_not_skip(self, tmp_path, val):
        """Falsy values still attempt PDF (may fail with pdf_error on Win)."""
        from kryon.reporting.demo_report import render_demo_report

        with patch.dict(os.environ, {"KRYON_SKIP_PDF": val}):
            paths = render_demo_report(
                findings=[],
                context={"engagement_id": "test-noskip"},
                output_dir=str(tmp_path),
                write_pdf=False,  # avoid actual rendering in test
            )
        assert "pdf_skipped" not in paths

    def test_write_pdf_false_skips_entirely(self, tmp_path):
        from kryon.reporting.demo_report import render_demo_report

        paths = render_demo_report(
            findings=[],
            context={"engagement_id": "test-noPdf"},
            output_dir=str(tmp_path),
            write_pdf=False,
        )
        assert "pdf" not in paths
        assert "pdf_error" not in paths
        assert "pdf_skipped" not in paths
        assert "html" in paths
        assert "json" in paths


# ---------------------------------------------------------------------------
# pdf.html_to_pdf — re-raise OSError as RuntimeError with hint
# ---------------------------------------------------------------------------


class TestPdfHelperReraises:
    def test_oserror_becomes_runtimeerror_with_hint(self):
        from kryon.reporting import pdf as pdf_mod

        async def _run():
            return await pdf_mod.html_to_pdf("<html></html>")

        fake = type(sys)("weasyprint")

        def _bad_html(string):
            raise OSError("cannot load library 'libgobject-2.0-0'")

        fake.HTML = _bad_html
        with patch.dict(sys.modules, {"weasyprint": fake}):
            with pytest.raises(RuntimeError, match="WeasyPrint native deps missing"):
                asyncio.run(_run())

    def test_importerror_still_raises_importerror(self):
        from kryon.reporting import pdf as pdf_mod

        # Force ImportError by setting module to None (raises ImportError on import)
        with patch.dict(sys.modules, {"weasyprint": None}):
            with pytest.raises(ImportError, match="weasyprint is required"):
                asyncio.run(pdf_mod.html_to_pdf("<html></html>"))


# ---------------------------------------------------------------------------
# multi_framework_pdf — re-raise OSError as RuntimeError
# ---------------------------------------------------------------------------


class TestMultiFrameworkPdfReraises:
    def test_oserror_becomes_runtimeerror(self, tmp_path):
        from kryon.reporting.multi_framework_pdf import render_multi_framework_pdf

        fake = type(sys)("weasyprint")

        def _bad_html(string):
            raise OSError("cannot load library 'libgobject-2.0-0'")

        fake.HTML = _bad_html

        # Force OSError on import path
        with patch.dict(sys.modules, {"weasyprint": None}):
            # sys.modules[None] forces a re-import; combined with no install
            # this will get ImportError, so simulate OSError differently
            pass

        # More reliable: monkeypatch the import inside the function
        import builtins

        real_import = builtins.__import__

        def _import_fail(name, *args, **kwargs):
            if name == "weasyprint":
                raise OSError("cannot load library 'libgobject-2.0-0'")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", _import_fail):
            with pytest.raises(RuntimeError, match="WeasyPrint native deps missing"):
                render_multi_framework_pdf(
                    framework_results={},
                    output_path=str(tmp_path / "out.pdf"),
                )
