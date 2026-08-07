"""F114.B — TDD contract for the Active SSRF Probe."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from kryon.tools.active_probes.ssrf_active import (
    SsrfActiveConfig,
    _classify_body,
    default_ssrf_payloads,
    probe_ssrf_active,
)

# =====================================================================
# Pure functions
# =====================================================================


def test_default_payloads_includes_cloud_metadata():
    payloads = default_ssrf_payloads()
    joined = "|".join(payloads)
    assert "169.254.169.254" in joined
    assert "metadata.google.internal" in joined
    assert "127.0.0.1" in joined
    assert "100.100.100.200" in joined  # alibaba
    assert "[::1]" in joined  # ipv6 loopback


@pytest.mark.parametrize(
    "body,expected",
    [
        (b"ami-id\ninstance-id\nlocal-ipv4", "aws-metadata"),
        (b"computeMetadata/v1\nprojects/12345", "gcp-metadata"),
        (b'"compute":"foo","vmId":"abc"', "azure-imds"),
        (b"root:x:0:0:root:/root:/bin/bash", "file-etc-passwd"),
        (b"<html><title>Apache/2.4.41 Server</title>", "internal-http-banner"),
        (b"dial tcp 169.254.169.254: connection refused", "error-leak"),
        (b"java.net.UnknownHostException at ...", "error-leak"),
        (b"Plain harmless content here", ""),
        (b"", ""),
    ],
)
def test_classify_body(body, expected):
    assert _classify_body(body) == expected


# =====================================================================
# Double-gate behavior
# =====================================================================


def test_dry_run_when_fire_false(monkeypatch):
    monkeypatch.setenv("KRYON_SSRF_FIRE", "true")
    cfg = SsrfActiveConfig(
        endpoint_url="https://target.com/proxy",
        parameter_name="url",
        fire=False,
    )
    result = probe_ssrf_active(cfg)
    assert result.fired is False
    assert "fire=False" in result.fire_gate_state
    assert len(result.payloads_built) > 0  # still reports them


def test_dry_run_when_env_not_set(monkeypatch):
    monkeypatch.delenv("KRYON_SSRF_FIRE", raising=False)
    cfg = SsrfActiveConfig(
        endpoint_url="https://target.com/proxy",
        parameter_name="url",
        fire=True,
    )
    result = probe_ssrf_active(cfg)
    assert result.fired is False
    assert "KRYON_SSRF_FIRE" in result.fire_gate_state


def test_canary_url_appended_to_payloads(monkeypatch):
    monkeypatch.delenv("KRYON_SSRF_FIRE", raising=False)
    cfg = SsrfActiveConfig(
        endpoint_url="https://target.com/proxy",
        parameter_name="url",
        canary_url="https://my-interactsh.example/abc123",
        fire=False,  # dry-run
    )
    result = probe_ssrf_active(cfg)
    assert "https://my-interactsh.example/abc123" in result.payloads_built
    assert result.canary_url_supplied is True


def test_invalid_endpoint_url_rejected(monkeypatch):
    monkeypatch.setenv("KRYON_SSRF_FIRE", "true")
    cfg = SsrfActiveConfig(
        endpoint_url="ftp://target.com/proxy",
        parameter_name="url",
        fire=True,
    )
    result = probe_ssrf_active(cfg)
    assert result.fired is False
    assert "scheme" in result.fire_gate_state


# =====================================================================
# Live probe against a local handler simulating SSRF behavior
# =====================================================================


class _SsrfVulnHandler(BaseHTTPRequestHandler):
    """Simulates a naive server that follows ANY URL given via ?url= and
    echoes the body back."""

    def log_message(self, format, *args):
        return

    def do_GET(self) -> None:
        if self.path.startswith("/proxy"):
            import urllib.parse

            parsed = urllib.parse.urlparse(self.path)
            qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            target = qs.get("url", "")
            # Simulate that if target contains 169.254.169.254, we echo
            # back AWS metadata.
            if "169.254.169.254" in target:
                body = b"ami-id\nami-launch-index\nhostname\ninstance-id\nlocal-ipv4"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if "metadata.google.internal" in target:
                body = b"computeMetadata/v1\nprojects/-12345\ninstance/service-accounts/"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if target.startswith("file:///"):
                body = b"root:x:0:0:root:/root:/bin/bash"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            # Otherwise: 404 (target not reachable from server's perspective)
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/safe-proxy"):
            # SAFE handler: rejects any payload pointing to internal
            import urllib.parse

            parsed = urllib.parse.urlparse(self.path)
            qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            target = qs.get("url", "")
            INTERNAL_MARKERS = (
                "169.254",
                "127.0.0",
                "metadata.google",
                "localhost",
                "10.",
                "192.168.",
                "172.",
                "file://",
            )
            if any(m in target for m in INTERNAL_MARKERS):
                body = b"forbidden - internal URL"
                self.send_response(403)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def vuln_server():
    httpd = HTTPServer(("127.0.0.1", 0), _SsrfVulnHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_live_probe_confirms_aws_metadata_ssrf(monkeypatch, vuln_server):
    monkeypatch.setenv("KRYON_SSRF_FIRE", "true")
    cfg = SsrfActiveConfig(
        endpoint_url=f"{vuln_server}/proxy",
        parameter_name="url",
        fire=True,
        rate_limit_per_second=50,
    )
    result = probe_ssrf_active(cfg)
    assert result.fired is True
    # At least one CRITICAL finding from cloud-metadata signatures
    critical = [f for f in result.findings if f.severity == "CRITICAL"]
    assert len(critical) >= 1
    # AWS payload should have detected the signature
    aws_attempt = next(
        (a for a in result.attempts if "169.254.169.254" in a.payload and a.detected_signature),
        None,
    )
    assert aws_attempt is not None
    assert aws_attempt.detected_signature == "aws-metadata"


def test_live_probe_safe_handler_no_findings(monkeypatch, vuln_server):
    monkeypatch.setenv("KRYON_SSRF_FIRE", "true")
    cfg = SsrfActiveConfig(
        endpoint_url=f"{vuln_server}/safe-proxy",
        parameter_name="url",
        fire=True,
        rate_limit_per_second=50,
    )
    result = probe_ssrf_active(cfg)
    assert result.fired is True
    assert result.findings == ()  # safe handler emits no SSRF findings


def test_live_probe_attempts_match_payloads(monkeypatch, vuln_server):
    monkeypatch.setenv("KRYON_SSRF_FIRE", "true")
    cfg = SsrfActiveConfig(
        endpoint_url=f"{vuln_server}/proxy",
        parameter_name="url",
        fire=True,
        rate_limit_per_second=50,
    )
    result = probe_ssrf_active(cfg)
    assert len(result.attempts) == len(result.payloads_built)


def test_unreachable_target_no_crash(monkeypatch):
    monkeypatch.setenv("KRYON_SSRF_FIRE", "true")
    cfg = SsrfActiveConfig(
        endpoint_url="http://127.0.0.1:1/proxy",
        parameter_name="url",
        fire=True,
        timeout_seconds=1.0,
        rate_limit_per_second=50,
    )
    result = probe_ssrf_active(cfg)
    assert result.fired is True
    # All attempts will fail to connect
    assert all(a.error or a.http_status == 0 for a in result.attempts)
    assert result.findings == ()
