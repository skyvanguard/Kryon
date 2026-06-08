"""F203.A — Tests for `kryon investigate` entry point.

Cubre:
- Intent classification (URL detection, code path, topic hints)
- Prompt building (passive vs active mode safety language)
- Argparse subparser wiring (kryon investigate --help)

NO ejecuta el agente real — eso requeriría Ollama up. Solo verifica
el pipeline de setup (intent classification, skill matching gate).
"""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.investigate import (
    _build_investigate_prompt,
    _classify_intent,
    _is_local_path,
    _is_url,
    add_investigate_subparser,
)


class TestUrlDetection:
    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com",
            "https://eaula.ing.una.py",
            "https://target.com/path?q=1",
        ],
    )
    def test_recognizes_http_urls(self, url):
        assert _is_url(url)

    @pytest.mark.parametrize(
        "not_url",
        [
            "example.com",
            "ftp://example.com",
            "file:///etc/passwd",
            "/local/path",
            "",
        ],
    )
    def test_rejects_non_http(self, not_url):
        assert not _is_url(not_url)


class TestIntentClassification:
    def test_url_in_prompt_sets_web_audit_mode(self):
        hints = _classify_intent("audita https://eaula.ing.una.py")
        assert hints["mode"] == "web_audit"
        assert "https://eaula.ing.una.py" in hints["urls"]
        assert "webapp" in hints["keywords"]

    def test_url_with_trailing_punctuation_stripped(self):
        hints = _classify_intent("mira esto: https://example.com/login.")
        assert "https://example.com/login" in hints["urls"]

    def test_moodle_keyword_detected(self):
        hints = _classify_intent("audita el Moodle de la facultad")
        assert "moodle" in hints["keywords"]
        assert "lms" in hints["keywords"]

    def test_wordpress_keyword_detected(self):
        hints = _classify_intent("revisar WordPress wp-admin")
        assert "wordpress" in hints["keywords"]

    def test_sqli_keyword_detected(self):
        hints = _classify_intent("buscá SQL injection en el login")
        assert "sqli" in hints["keywords"]
        assert "cwe-89" in hints["keywords"]

    def test_xss_keyword_detected(self):
        hints = _classify_intent("XSS en el search field")
        assert "xss" in hints["keywords"]
        assert "cwe-79" in hints["keywords"]

    def test_auth_keyword_detected(self):
        hints = _classify_intent("revisar el login y JWT")
        assert "auth" in hints["keywords"]
        assert "cwe-287" in hints["keywords"]

    def test_cve_keyword_detected(self):
        hints = _classify_intent("qué CVE aplica a nginx 1.18")
        assert "cve" in hints["keywords"]

    def test_local_path_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            hints = _classify_intent(f"audita {tmp}")
            assert hints["mode"] == "code_sast"
            assert hints["code_path"] == tmp
            assert "sast" in hints["keywords"]

    def test_general_mode_when_no_signal(self):
        hints = _classify_intent("hola mundo")
        assert hints["mode"] == "general"
        assert hints["keywords"] == []


class TestPromptBuilder:
    def test_passive_mode_has_safety_language(self):
        hints = {"mode": "web_audit", "urls": ["https://x"], "keywords": []}
        prompt = _build_investigate_prompt("audita https://x", hints, active=False)
        assert "PASSIVE MODE" in prompt
        assert "web_fetch_smart" in prompt
        assert "NO ejecutes nmap" in prompt

    def test_active_mode_has_authorization_warning(self):
        hints = {"mode": "web_audit", "urls": [], "keywords": []}
        prompt = _build_investigate_prompt("audita target", hints, active=True)
        assert "ACTIVE MODE" in prompt
        assert "autorización" in prompt

    def test_includes_user_prompt(self):
        hints = {"mode": "general", "keywords": []}
        user_text = "específicamente buscá CSRF en /transfer"
        prompt = _build_investigate_prompt(user_text, hints, active=False)
        assert user_text in prompt

    def test_includes_react_loop_steps(self):
        hints = {"mode": "general", "keywords": []}
        prompt = _build_investigate_prompt("x", hints, active=False)
        # Should mention the 5 steps of the ReAct loop
        for marker in ("Observar", "Reflexionar", "Decidir", "Verificar", "Parar"):
            assert marker in prompt

    def test_includes_urls_when_detected(self):
        hints = {"mode": "web_audit", "urls": ["https://eaula.ing.una.py"], "keywords": []}
        prompt = _build_investigate_prompt("x", hints, active=False)
        assert "eaula.ing.una.py" in prompt

    def test_includes_code_path_when_detected(self):
        hints = {"mode": "code_sast", "code_path": "/tmp/repo", "keywords": []}
        prompt = _build_investigate_prompt("x", hints, active=False)
        assert "/tmp/repo" in prompt


class TestArgparseWiring:
    def test_subparser_registers_required_args(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        add_investigate_subparser(sub)

        args = parser.parse_args(["investigate", "audita example.com"])
        assert args.command == "investigate"
        assert args.query == "audita example.com"
        assert args.active is False
        assert args.max_turns == 30
        assert args.url == ""

    def test_subparser_accepts_url_flag(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        add_investigate_subparser(sub)

        args = parser.parse_args(
            [
                "investigate",
                "--url",
                "https://eaula.ing.una.py",
                "--active",
                "--max-turns",
                "10",
            ]
        )
        assert args.url == "https://eaula.ing.una.py"
        assert args.active is True
        assert args.max_turns == 10

    def test_subparser_accepts_out_dir(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        add_investigate_subparser(sub)

        args = parser.parse_args(["investigate", "x", "--out", "./reports"])
        assert args.out == "./reports"

    def test_reflect_every_default_is_4(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        add_investigate_subparser(sub)

        args = parser.parse_args(["investigate", "x"])
        assert args.reflect_every == 4

    def test_reflect_every_can_be_disabled(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        add_investigate_subparser(sub)

        args = parser.parse_args(["investigate", "x", "--reflect-every", "0"])
        assert args.reflect_every == 0

    def test_reflect_every_custom_value(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        add_investigate_subparser(sub)

        args = parser.parse_args(["investigate", "x", "--reflect-every", "6"])
        assert args.reflect_every == 6


class TestHybridMode:
    """F203.M — deterministic phase + LLM agent."""

    def test_no_hybrid_flag_default_false(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        add_investigate_subparser(sub)

        args = parser.parse_args(["investigate", "x"])
        assert args.no_hybrid is False

    def test_no_hybrid_flag_enabled(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        add_investigate_subparser(sub)

        args = parser.parse_args(["investigate", "x", "--no-hybrid"])
        assert args.no_hybrid is True

    def test_run_deterministic_phase_invalid_url_returns_empty(self):
        from kryon.cli.investigate import _run_deterministic_phase

        # Garbage URL → no findings, no crash
        assert _run_deterministic_phase("not-a-url") == []
        assert _run_deterministic_phase("") == []

    def test_run_deterministic_phase_unsupported_scheme(self):
        from kryon.cli.investigate import _run_deterministic_phase

        # gopher://, ftp://, file:// — none should produce findings
        assert _run_deterministic_phase("ftp://x:21/") == []
        assert _run_deterministic_phase("file:///etc/passwd") == []

    def test_format_findings_for_prompt_empty(self):
        from kryon.cli.investigate import _format_findings_for_prompt

        assert _format_findings_for_prompt([]) == ""

    def test_ssh_creds_flags_parsed(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        add_investigate_subparser(sub)

        args = parser.parse_args(
            [
                "investigate",
                "x",
                "--ssh-user",
                "admin",
                "--ssh-pass",
                "secret123",
                "--ssh-key",
                "/path/to/key",
            ]
        )
        assert args.ssh_user == "admin"
        assert args.ssh_pass == "secret123"
        assert args.ssh_key == "/path/to/key"

    def test_db_creds_flags_parsed(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        add_investigate_subparser(sub)

        args = parser.parse_args(
            [
                "investigate",
                "x",
                "--db-user",
                "app",
                "--db-pass",
                "pw",
            ]
        )
        assert args.db_user == "app"
        assert args.db_pass == "pw"

    def test_include_dns_smb_flags(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        add_investigate_subparser(sub)

        args = parser.parse_args(
            [
                "investigate",
                "x",
                "--include-dns-checks",
                "--include-smb-checks",
            ]
        )
        assert args.include_dns_checks is True
        assert args.include_smb_checks is True

    def test_creds_default_empty(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        add_investigate_subparser(sub)

        args = parser.parse_args(["investigate", "x"])
        assert args.ssh_user == ""
        assert args.db_user == ""
        assert args.include_dns_checks is False
        assert args.include_smb_checks is False

    def test_run_deterministic_phase_accepts_kwargs(self):
        from kryon.cli.investigate import _run_deterministic_phase

        # Should not raise — empty URL returns []
        assert (
            _run_deterministic_phase(
                "",
                ssh_user="admin",
                ssh_password="x",
                ssh_key="/k",
                db_user="root",
                db_password="r",
                include_dns=True,
                include_smb=True,
            )
            == []
        )

    def test_format_findings_for_prompt_includes_cwe_and_rule(self):
        from kryon.cli.investigate import _format_findings_for_prompt

        # Use a SimpleNamespace as a duck-typed Finding stub
        class FakeFinding:
            def __init__(self, cwe, rule_id, severity, host, message):
                self.cwe = cwe
                self.rule_id = rule_id
                self.severity = severity
                self.host = host
                self.message = message

        findings = [
            FakeFinding("CWE-319", "http-plaintext", "HIGH", "x:8080", "no tls"),
            FakeFinding("CWE-1004", "http-cookie-missing-httponly", "MEDIUM", "x:8080", "no flag"),
        ]
        text = _format_findings_for_prompt(findings)
        assert "CWE-319" in text
        assert "CWE-1004" in text
        assert "http-plaintext" in text
        assert "http-cookie-missing-httponly" in text
        assert "Deterministic findings" in text  # heading present
