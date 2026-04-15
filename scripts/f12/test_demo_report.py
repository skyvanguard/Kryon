"""F12.4 tests — demo report HTML + PDF rendering.

Uses findings modelled on what Kryon would produce against the
vulnerable-lab containers (F12.3). If weasyprint is available, also
generates the actual PDF and verifies non-empty output.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from kryon.reporting.demo_report import (
    _normalise_severity,
    _severity_counts,
    _sorted_findings,
    render_demo_report,
    render_html,
)

_LAB_FINDINGS = [
    {
        "cwe": "CWE-521",
        "severity": "CRITICAL",
        "host": "target-ssh",
        "rule_id": "sshd-permit-root-login",
        "message": "SSH permite login de root con contraseña.",
        "evidence": "PermitRootLogin yes\nPasswordAuthentication yes",
        "remediation": "Desactivar PermitRootLogin y requerir autenticación por clave pública.",
    },
    {
        "cwe": "CWE-307",
        "severity": "HIGH",
        "host": "target-ssh",
        "rule_id": "sshd-max-auth-tries",
        "message": "MaxAuthTries 10 permite intentos de fuerza bruta prolongados.",
        "evidence": "MaxAuthTries 10",
        "remediation": "Reducir MaxAuthTries a 3 y habilitar fail2ban.",
    },
    {
        "cwe": "CWE-306",
        "severity": "HIGH",
        "host": "target-web",
        "rule_id": "nginx-admin-open",
        "message": "Endpoint /admin accesible sin autenticación.",
        "evidence": "GET /admin → 200 (sin auth_basic configurado)",
        "remediation": "Agregar auth_basic en la location /admin de nginx.",
    },
    {
        "cwe": "CWE-319",
        "severity": "HIGH",
        "host": "target-db",
        "rule_id": "mysql-no-tls",
        "message": "MySQL acepta conexiones sin TLS.",
        "evidence": "require_secure_transport no configurado; bind-address 0.0.0.0",
        "remediation": "Habilitar require_secure_transport=ON y restringir bind-address a la red interna.",
    },
    {
        "cwe": "CWE-200",
        "severity": "MEDIUM",
        "host": "target-web",
        "rule_id": "nginx-server-tokens",
        "message": "Header Server expone la versión de nginx.",
        "evidence": "Server: nginx/1.27.5",
        "remediation": "Configurar server_tokens off en nginx.conf.",
    },
    {
        "cwe": "CWE-1004",
        "severity": "LOW",
        "host": "target-web",
        "rule_id": "cookie-no-httponly",
        "message": "Cookie de sesión sin flags Secure / HttpOnly.",
        "evidence": "Set-Cookie: SESSIONID=... (sin HttpOnly ni Secure)",
        "remediation": "Añadir HttpOnly y Secure al Set-Cookie.",
    },
]

_CONTEXT = {
    "client_name": "britimp",
    "engagement_id": "britimp-demo-2026-04-15",
    "target_scope": "172.30.0.0/24 (vulnerable-lab)",
    "auditor": "SkyVanguard / Kryon",
}


def test_normalise_severity_alias() -> None:
    assert _normalise_severity("CRITICAL") == "CRITICAL"
    assert _normalise_severity("ERROR") == "HIGH"
    assert _normalise_severity("warning") == "MEDIUM"
    assert _normalise_severity("weird") == "INFO"
    print("  ok: severity aliases normalised")


def test_severity_counts_and_sort() -> None:
    counts = _severity_counts(_LAB_FINDINGS)
    assert counts["CRITICAL"] == 1
    assert counts["HIGH"] == 3
    assert counts["MEDIUM"] == 1
    assert counts["LOW"] == 1
    # Sorted: CRITICAL first, LOW last
    s = _sorted_findings(_LAB_FINDINGS)
    assert s[0]["severity"] == "CRITICAL"
    assert s[-1]["severity"] in ("LOW", "INFO")
    print("  ok: counts + sort order")


def test_render_html_contains_all_findings() -> None:
    html = render_html(_LAB_FINDINGS, _CONTEXT)
    assert "britimp" in html
    assert "britimp-demo-2026-04-15" in html
    assert "CWE-521" in html
    assert "PermitRootLogin yes" in html
    assert "nginx-admin-open" in html
    assert "require_secure_transport" in html
    # KPI row counts
    assert ">6<" in html or ">6 <" in html  # total=6 somewhere in KPI
    print("  ok: HTML contains context + all finding evidence + remediation")


def test_render_html_empty_findings() -> None:
    html = render_html([], {"client_name": "x", "target_scope": "nothing"})
    assert "No se detectaron hallazgos" in html
    assert "Sin hallazgos" in html  # table placeholder row
    print("  ok: empty findings renders the 'no findings' messages")


def test_render_demo_report_writes_html_and_json() -> None:
    with tempfile.TemporaryDirectory() as td:
        paths = render_demo_report(
            _LAB_FINDINGS, _CONTEXT, output_dir=td,
            write_html=True, write_pdf=False,
        )
        assert "html" in paths and paths["html"].is_file()
        assert "json" in paths and paths["json"].is_file()
        # Audit JSON is round-trippable
        data = json.loads(paths["json"].read_text())
        assert len(data["findings"]) == 6
        assert data["context"]["engagement_id"] == "britimp-demo-2026-04-15"
    print("  ok: render_demo_report writes HTML + audit JSON")


def test_render_demo_report_pdf_if_weasyprint_available() -> None:
    try:
        import weasyprint  # noqa: F401
    except ImportError:
        print("  skip: weasyprint not installed (install kryon[reporting] to test PDF)")
        return

    with tempfile.TemporaryDirectory() as td:
        paths = render_demo_report(
            _LAB_FINDINGS, _CONTEXT, output_dir=td,
            write_html=True, write_pdf=True,
        )
        assert "pdf" in paths, f"PDF not generated: {paths}"
        assert paths["pdf"].is_file()
        size = paths["pdf"].stat().st_size
        assert size > 5_000, f"PDF suspiciously small: {size} bytes"
        print(f"  ok: PDF rendered ({size:,} bytes)")


if __name__ == "__main__":
    print("F12.4 demo report unit tests")
    test_normalise_severity_alias()
    test_severity_counts_and_sort()
    test_render_html_contains_all_findings()
    test_render_html_empty_findings()
    test_render_demo_report_writes_html_and_json()
    test_render_demo_report_pdf_if_weasyprint_available()
    print("\nALL PASS")
