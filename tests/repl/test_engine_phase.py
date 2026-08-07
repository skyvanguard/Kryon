"""Contract for kryon.repl.engine_phase.

The engine phase wires the read-only deterministic detector battery into the
interactive REPL. These tests pin the pure surface (target resolution, intent
detection, URL normalization, faithful narration, ground-truth suffix) that
lets a plain "analizá <host>" turn fire the engine instead of leaving the
whole analysis to the LLM.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest


@dataclass
class _Finding:
    """Minimal stand-in for kryon.intelligence Finding (duck-typed)."""

    cwe: str = "CWE-693"
    rule_id: str = "security-headers-missing"
    severity: str = "MEDIUM"
    host: str = "10.0.0.5"
    message: str = "HSTS missing"
    evidence: str = ""


# ---------- resolve_target ----------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("analizá http://10.0.0.5/login", "http://10.0.0.5/login"),
        ("auditá 10.0.0.5", "10.0.0.5"),
        ("revisá example.com:8080", "example.com:8080"),
        ("scan localhost", "localhost"),
        ("mirá https://target.com/a/b", "https://target.com/a/b"),
    ],
)
def test_resolve_target_from_message(text: str, expected: str) -> None:
    from kryon.repl.engine_phase import resolve_target

    assert resolve_target(text) == expected


def test_resolve_target_ignores_plain_words() -> None:
    """A generic sentence with no address resolves to None (no accidental scan)."""
    from kryon.repl.engine_phase import resolve_target

    assert resolve_target("realiza un análisis de seguridad sobre esto") is None


@pytest.mark.parametrize(
    "text",
    [
        "analizá el package.json",
        "revisá config.yaml",
        "mirá el archivo main.go",
        "abrí app.py",
        "leé el README.md",
        "el dump está en data.sql",
        "cargá creds.pem",
    ],
)
def test_resolve_target_ignores_filenames(text: str) -> None:
    """A code/asset filename is NOT a network host — no scan of http://package.json."""
    from kryon.repl.engine_phase import resolve_target

    assert resolve_target(text) is None


@pytest.mark.parametrize(
    "text,expected",
    [
        ("escaneá cdn.example.io", "cdn.example.io"),
        ("auditá https://juice-shop.local/robots.txt", "https://juice-shop.local/robots.txt"),
        ("analizá example.com", "example.com"),
        # ccTLD-vs-file-ext collision: Paraguayan .com.py domains are HOSTS, not
        # Python files — the whole determinism phase was silently skipping them.
        ("audita example.com.py", "example.com.py"),
        ("auditá example.com", "example.com"),
        ("escaneá app.example.com", "app.example.com"),
        ("revisá sitio.gov.py", "sitio.gov.py"),
        ("analizá app.co.uk", "app.co.uk"),
    ],
)
def test_resolve_target_keeps_real_hosts(text: str, expected: str) -> None:
    """Real dotted hosts (even with a file in the path) still resolve."""
    from kryon.repl.engine_phase import resolve_target

    assert resolve_target(text) == expected


def test_resolve_target_falls_back_to_session_then_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from kryon.repl.engine_phase import resolve_target

    monkeypatch.delenv("KRYON_TARGET_HOST", raising=False)
    # Session target used when the message has no address.
    assert resolve_target("analizá esto", session_target="10.9.9.9") == "10.9.9.9"
    # Env used when neither message nor session provide one.
    monkeypatch.setenv("KRYON_TARGET_HOST", "192.168.1.1")
    assert resolve_target("analizá esto") == "192.168.1.1"
    # Message address still wins over session + env.
    assert resolve_target("analizá 10.0.0.5", session_target="10.9.9.9") == "10.0.0.5"


# ---------- is_analysis_request ----------


@pytest.mark.parametrize(
    "text",
    [
        "realiza un análisis de seguridad sobre esto",
        "auditá el host",
        "escaneá 10.0.0.5",
        "pentest contra el target",
        "revisá vulnerabilidades",
        "run a security scan",
        # Broadened stems (gap audit).
        "investigá 10.0.0.5",
        "checkea el host",
        "testeá la web",
        "enumerá servicios",
        "qué CVEs tiene nginx",
        "identificá debilidades",
    ],
)
def test_is_analysis_request_true(text: str) -> None:
    from kryon.repl.engine_phase import is_analysis_request

    assert is_analysis_request(text) is True


@pytest.mark.parametrize("text", ["hola, cómo estás?", "cuánto es 2+2", "", "listá los archivos"])
def test_is_analysis_request_false(text: str) -> None:
    from kryon.repl.engine_phase import is_analysis_request

    assert is_analysis_request(text) is False


# ---------- normalize_to_url ----------


@pytest.mark.parametrize(
    "target,expected",
    [
        ("10.0.0.5", "http://10.0.0.5"),
        ("example.com:8080", "http://example.com:8080"),
        ("http://x.com", "http://x.com"),
        ("https://x.com/a", "https://x.com/a"),
        ("", ""),
    ],
)
def test_normalize_to_url(target: str, expected: str) -> None:
    from kryon.repl.engine_phase import normalize_to_url

    assert normalize_to_url(target) == expected


@pytest.mark.parametrize(
    "target,expected",
    [
        # Bare host → https FIRST, then http (the example https-only fix).
        ("www.example.com", ["https://www.example.com", "http://www.example.com"]),
        ("10.0.0.5", ["https://10.0.0.5", "http://10.0.0.5"]),
        # Explicit scheme is honoured as-is (no second candidate).
        ("http://lab.local", ["http://lab.local"]),
        ("https://x.com/a", ["https://x.com/a"]),
        ("ssh://10.0.0.5", ["ssh://10.0.0.5"]),
        # B1 — bare host with a non-web service port → that service's scheme.
        ("10.0.0.5:22", ["ssh://10.0.0.5:22"]),
        ("10.0.0.5:3306", ["mysql://10.0.0.5:3306"]),
        ("10.0.0.5:5432", ["postgres://10.0.0.5:5432"]),
        # Web-ish port stays https/http.
        ("10.0.0.5:8080", ["https://10.0.0.5:8080", "http://10.0.0.5:8080"]),
        ("", []),
    ],
)
def test_candidate_urls_scheme_by_port(target: str, expected: list[str]) -> None:
    from kryon.repl.engine_phase import candidate_urls

    assert candidate_urls(target) == expected


@pytest.mark.parametrize(
    "target,expected",
    [
        ("10.0.0.0/24", True),
        ("192.168.1.0/16", True),
        ("10.0.0.5", False),
        ("example.com", False),
        ("example.com/path", False),
        ("", False),
    ],
)
def test_is_cidr(target: str, expected: bool) -> None:
    from kryon.repl.engine_phase import is_cidr

    assert is_cidr(target) is expected


def test_resolve_target_matches_cidr() -> None:
    from kryon.repl.engine_phase import resolve_target

    assert resolve_target("analizá la red 10.0.0.0/24") == "10.0.0.0/24"


def test_resolve_target_rejects_invalid_octets() -> None:
    from kryon.repl.engine_phase import resolve_target

    # 10.0.0.256 is not a valid IPv4 — the octet-validated regex must not match it
    # as an IP (falls through; no dotted-TLD hostname here either).
    assert resolve_target("mirá 10.0.0.256 por favor") is None


def test_host_sweep_gated_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    from kryon.repl.engine_phase import run_host_sweep

    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    findings, ports = run_host_sweep("10.0.0.5")
    assert findings == [] and ports == []


# ---------- build_narration_lines ----------


def test_narration_empty_is_honest() -> None:
    """A clean run says 'sin hallazgos' — it never fabricates activity."""
    from kryon.repl.engine_phase import build_narration_lines

    lines = build_narration_lines("10.0.0.5", [], 3.14)
    assert lines[0] == "⚙  motor de análisis · 10.0.0.5"
    assert any("sin hallazgos" in ln for ln in lines)
    assert any("3.1s" in ln for ln in lines)


def test_narration_groups_and_counts() -> None:
    from kryon.repl.engine_phase import build_narration_lines

    findings = [
        _Finding(cwe="CWE-693", rule_id="security-headers-missing", severity="MEDIUM"),
        _Finding(cwe="CWE-614", rule_id="cookie-insecure-flag", severity="LOW"),
        _Finding(cwe="CWE-319", rule_id="tls-weak-cipher", severity="HIGH"),
    ]
    lines = build_narration_lines("10.0.0.5", findings, 2.0)
    header_line = lines[1]
    assert "3 hallazgo(s)" in header_line
    assert "3 categoría(s)" in header_line  # headers, cookies, tls
    # Each finding rendered as an indented operator row with its CWE.
    body = "\n".join(lines[2:])
    assert "CWE-693" in body and "CWE-614" in body and "CWE-319" in body


# ---------- format_engine_ground_truth ----------


def test_ground_truth_empty_for_no_findings() -> None:
    from kryon.repl.engine_phase import format_engine_ground_truth

    assert format_engine_ground_truth([], "10.0.0.5") == ""


def test_ground_truth_marks_authoritative_and_sorts_by_severity() -> None:
    from kryon.repl.engine_phase import format_engine_ground_truth

    findings = [
        _Finding(cwe="CWE-1", severity="low", rule_id="r-low"),
        _Finding(cwe="CWE-2", severity="critical", rule_id="r-crit"),
    ]
    block = format_engine_ground_truth(findings, "10.0.0.5")
    assert "ground truth confirmado" in block.lower()
    # Critical must be rendered before low.
    assert block.index("CWE-2") < block.index("CWE-1")


def test_converge_directive_default_tells_4b_to_terminate(monkeypatch: pytest.MonkeyPatch) -> None:
    from kryon.repl.engine_phase import converge_directive

    monkeypatch.delenv("KRYON_CAPABLE_MODEL", raising=False)
    out = converge_directive(3)
    assert "CONVERGENCIA" in out
    assert "TERMINAR" in out


def test_converge_directive_capable_chains_from_foothold(monkeypatch: pytest.MonkeyPatch) -> None:
    from kryon.repl.engine_phase import converge_directive

    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    out = converge_directive(3)
    # A capable model must NOT be told to terminate at the first finding.
    assert "TERMINAR" not in out
    assert "PUNTO DE PARTIDA" in out
    assert "escalá" in out.lower() or "encadená" in out.lower()


def test_ground_truth_capable_allows_rescan(monkeypatch: pytest.MonkeyPatch) -> None:
    from kryon.repl.engine_phase import format_engine_ground_truth

    findings = [_Finding(cwe="CWE-1", severity="high", rule_id="r")]
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    block = format_engine_ground_truth(findings, "10.0.0.5")
    assert "re-escaneá" in block.lower()  # capable may re-scan
    assert "head start" in block.lower()
    assert "ni los re-escanees" not in block.lower()

    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "false")
    block = format_engine_ground_truth(findings, "10.0.0.5")
    assert "ni los re-escanees" in block.lower()  # 4B keeps the restriction


# ---------- run_engine_phase (no target → no run) ----------


def test_run_engine_phase_empty_target_does_not_run() -> None:
    from kryon.repl.engine_phase import run_engine_phase

    result = run_engine_phase("", console=None)
    assert result.ran is False
    assert result.findings == []
    assert result.ground_truth == ""


# ---------- active expert sweep (RED_TEAM gate) ----------


def test_expert_sweep_gated_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    from kryon.repl.engine_phase import run_expert_sweep

    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    assert run_expert_sweep("https://x.test") == []


def test_adapt_banking_finding_maps_fields() -> None:
    from kryon.repl.engine_phase import _adapt_banking_finding

    bf = type("BF", (), {})()  # duck-typed BankingFinding stand-in
    bf.cwe_id, bf.probe_id, bf.severity = "CWE-79", "xss_reflected", "HIGH"
    bf.url, bf.title, bf.evidence, bf.payload = "https://s.test/x?q=1", "XSS on q", "<script>", ""
    a = _adapt_banking_finding(bf, "https://s.test")
    assert a.cwe == "CWE-79" and a.rule_id == "xss_reflected" and a.severity == "HIGH"
    assert a.host == "s.test" and a.message == "XSS on q" and a.evidence == "<script>"


def test_render_findings_report_renders_without_raising() -> None:
    from io import StringIO

    from rich.console import Console

    from kryon.repl.engine_phase import render_findings_report

    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=120, color_system=None)
    findings = [
        _Finding(cwe="CWE-79", rule_id="xss_reflected", severity="HIGH", message="XSS on q"),
        _Finding(cwe="CWE-693", rule_id="hsts-missing", severity="LOW", message="HSTS weak"),
    ]
    render_findings_report(findings, console, target="site.test")
    out = buf.getvalue()
    assert "Informe" in out and "site.test" in out
    assert "xss_reflected" in out and "hsts-missing" in out
    assert "2 hallazgo(s) confirmado(s)" in out


def test_render_findings_report_empty_is_noop() -> None:
    from io import StringIO

    from rich.console import Console

    from kryon.repl.engine_phase import render_findings_report

    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=120, color_system=None)
    render_findings_report([], console)
    assert buf.getvalue() == ""


def test_converge_directive_counters_keep_searching() -> None:
    from kryon.repl.engine_phase import converge_directive

    d = converge_directive(9)
    assert "9 hallazgo(s)" in d
    assert "CONVERGENCIA" in d
    assert "TERMINAR" in d
    # It must explicitly neutralize the empty-pre_hook "keep going" push.
    assert "IGNORALO" in d and "NUNCA emitas" in d


def test_narration_shows_active_sweep_block() -> None:
    from kryon.repl.engine_phase import build_narration_lines

    passive = [_Finding(cwe="CWE-693", rule_id="hsts-missing", severity="LOW")]
    active = [_Finding(cwe="CWE-79", rule_id="xss_reflected", severity="HIGH")]
    lines = build_narration_lines("10.0.0.5", passive, 2.0, active_findings=active)
    body = "\n".join(lines)
    assert "sweep activo (experts) · 1 hallazgo(s)" in body
    assert "xss_reflected" in body and "hsts-missing" in body
