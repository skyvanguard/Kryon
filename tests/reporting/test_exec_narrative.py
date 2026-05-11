"""F85.G — LLM-narrated executive summary tests.

The LLM call is mocked via monkeypatch on ``urllib.request.urlopen``
so tests don't need a live model. We verify:

  - Successful 3-paragraph output is parsed and HTML-rendered
  - Missing tags trigger fallback (empty string)
  - LLM failure (urlopen raises) triggers fallback
  - Ollama-vs-external auth-token logic picks the right token
  - render_executive_summary respects KRYON_EXEC_NARRATIVE opt-in
  - HTML escaping in narrative body
"""

from __future__ import annotations

import io
import json
from dataclasses import dataclass

import pytest

from kryon.reporting.exec_narrative import (
    _is_ollama,
    generate_executive_narrative,
    render_narrative_as_html,
)


@dataclass
class _FakeFinding:
    """engage.py Finding shape (uppercase severity, message field)."""

    cwe: str = "CWE-89"
    severity: str = "CRITICAL"
    host: str = "10.0.0.1"
    rule_id: str = "sqli_login"
    message: str = "SQL Injection on login endpoint"
    evidence: str = ""


class _MockResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


_SAMPLE_OUTPUT = """PARRAFO_1_IMPACTO: Existe exposicion directa a perdida de datos sensibles porque los servicios de administracion estan abiertos a internet sin segundo factor. Esto compromete las obligaciones PCI-DSS del banco.

PARRAFO_2_PATRON: El patron sistematico es la falta de hardening sobre los servicios expuestos: passwords debiles, headers que filtran versiones, paneles de admin sin restriccion de IP. Indica deficit de bastionado en la operacion.

PARRAFO_3_RECOMENDACION: Asignar un sprint del equipo de plataforma para cerrar los puertos de gestion expuestos y rotar credenciales en las proximas 72 horas. Despues, definir politica de hardening estandar.
"""


def test_is_ollama_recognises_endpoint():
    assert _is_ollama("http://localhost:11434/v1")
    assert _is_ollama("https://ollama.example.com/v1")
    assert not _is_ollama("https://api.deepseek.com/v1")
    assert not _is_ollama("https://api.openai.com/v1")


def test_generate_returns_text_on_success(monkeypatch):
    captured_request = {}

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        captured_request["url"] = req.full_url
        captured_request["body"] = json.loads(req.data.decode())
        return _MockResponse({"choices": [{"message": {"content": _SAMPLE_OUTPUT}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    findings = [_FakeFinding(), _FakeFinding(severity="HIGH", rule_id="xss_form")]
    out = generate_executive_narrative(
        findings,
        client_name="BritImp",
        scope="172.18.201.0/24",
    )

    assert "PARRAFO_1_IMPACTO" in out
    assert "PARRAFO_2_PATRON" in out
    assert "PARRAFO_3_RECOMENDACION" in out
    # Prompt mentions the client name and scope
    sent_prompt = captured_request["body"]["messages"][0]["content"]
    assert "BritImp" in sent_prompt
    assert "172.18.201.0/24" in sent_prompt
    # Top critical summary shows the sqli finding
    assert "SQL Injection" in sent_prompt


def test_generate_returns_empty_on_missing_tags(monkeypatch):
    """If the LLM forgets the structured tags, we fall back to template."""

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        return _MockResponse({"choices": [{"message": {"content": "Free-form prose without tags."}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    out = generate_executive_narrative([_FakeFinding()], client_name="x", scope="y")
    assert out == ""


def test_generate_returns_empty_on_urlopen_failure(monkeypatch):
    """Any urlopen exception falls back to empty string — the
    deterministic template still ships."""

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        raise ConnectionError("DeepSeek unreachable")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    out = generate_executive_narrative([_FakeFinding()], client_name="x", scope="y")
    assert out == ""


def test_ollama_uses_token_literal_ollama(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        captured["auth"] = req.headers.get("Authorization") or req.headers.get("authorization")
        return _MockResponse({"choices": [{"message": {"content": _SAMPLE_OUTPUT}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    generate_executive_narrative(
        [_FakeFinding()],
        endpoint="http://localhost:11434/v1",
    )
    assert captured["auth"] == "Bearer ollama"


def test_external_endpoint_uses_real_api_key(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        captured["auth"] = req.headers.get("Authorization") or req.headers.get("authorization")
        return _MockResponse({"choices": [{"message": {"content": _SAMPLE_OUTPUT}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-real-key")
    generate_executive_narrative(
        [_FakeFinding()],
        endpoint="https://api.deepseek.com/v1",
    )
    assert captured["auth"] == "Bearer sk-test-real-key"


def test_render_html_extracts_three_paragraphs():
    html = render_narrative_as_html(_SAMPLE_OUTPUT)
    assert "<h3>Análisis ejecutivo</h3>" in html
    assert "Impacto al negocio" in html
    assert "Patrón de exposición" in html
    assert "Recomendación prioritaria" in html
    assert "PCI-DSS" in html
    assert "hardening" in html


def test_render_html_returns_empty_for_empty_input():
    assert render_narrative_as_html("") == ""
    assert render_narrative_as_html(None or "") == ""


def test_render_html_escapes_dangerous_chars():
    """Even though the LLM output is sanitised upstream, the HTML
    render path itself must escape <, >, & in the paragraph bodies."""
    crafted = "PARRAFO_1_IMPACTO: <script>alert(1)</script>\nPARRAFO_2_PATRON: A & B\nPARRAFO_3_RECOMENDACION: end."
    html = render_narrative_as_html(crafted)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "A &amp; B" in html


# ---------------------------------------------------------------------------
# render_executive_summary integration
# ---------------------------------------------------------------------------


def test_render_executive_summary_opt_in_off_by_default(monkeypatch):
    """Without KRYON_EXEC_NARRATIVE, no LLM call is made."""
    from kryon.intelligence.models import Finding, Severity
    from kryon.reporting.sections.executive_summary import render_executive_summary

    monkeypatch.delenv("KRYON_EXEC_NARRATIVE", raising=False)
    called = {"n": 0}

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        called["n"] += 1
        return _MockResponse({"choices": [{"message": {"content": _SAMPLE_OUTPUT}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    findings = [
        Finding(
            id="f1",
            title="SQL Injection",
            description="...",
            severity=Severity.CRITICAL,
            affected_asset="10.0.0.1",
        )
    ]
    out = render_executive_summary(findings, client_name="BritImp", scope="x")
    assert called["n"] == 0  # no LLM call
    assert "Executive Summary" in out


def test_render_executive_summary_invokes_llm_when_opted_in(monkeypatch):
    from kryon.intelligence.models import Finding, Severity
    from kryon.reporting.sections.executive_summary import render_executive_summary

    monkeypatch.setenv("KRYON_EXEC_NARRATIVE", "true")

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        return _MockResponse({"choices": [{"message": {"content": _SAMPLE_OUTPUT}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    findings = [
        Finding(
            id="f1",
            title="SQL Injection",
            description="...",
            severity=Severity.CRITICAL,
            affected_asset="10.0.0.1",
        )
    ]
    out = render_executive_summary(findings, client_name="BritImp", scope="x")
    assert "Análisis ejecutivo" in out
    assert "Impacto al negocio" in out
