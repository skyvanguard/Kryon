"""F113 — integration tests for the Replay Engine.

Strategy: spin up a local HTTP server whose response shape is
mutable mid-test. Run pipeline → collect findings. Mutate server →
run replay → assert which findings disappear."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from kryon.tools.crawler.crawler import CrawlerConfig
from kryon.tools.pipeline.pipeline import (
    PipelineConfig,
    UnifiedFinding,
    run_pipeline,
)
from kryon.tools.replay.engine import (
    ReplayConfig,
    ReplayEngine,
    ReplayedFinding,
    REPLAY_STATUS_DISAPPEARED,
    REPLAY_STATUS_INCONCLUSIVE,
    REPLAY_STATUS_STILL_PRESENT,
    run_replay,
)


# State: mutable per test
_HEADERS_ENABLED = {"value": False}
_ROOT_BODY = {"value": "<h1>hello</h1>"}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self) -> None:
        if self.path != "/":
            self.send_response(404)
            self.end_headers()
            return
        body = _ROOT_BODY["value"].encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        if _HEADERS_ENABLED["value"]:
            # Production-grade hardening
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "geolocation=()")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    _HEADERS_ENABLED["value"] = False
    _ROOT_BODY["value"] = "<h1>hello</h1>"
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        yield base
    finally:
        httpd.shutdown()
        httpd.server_close()


def _make_pipeline_cfg(base: str) -> PipelineConfig:
    return PipelineConfig(
        seeds=(base + "/",),
        crawler=CrawlerConfig(
            seeds=(base + "/",),
            max_pages=3,
            max_depth=1,
            max_concurrency=1,
            rate_limit_per_second=50.0,
            respect_robots=False,
            block_internal_ips=False,
        ),
    )


# =====================================================================
# Smoke
# =====================================================================


def test_replay_with_empty_findings_returns_empty(server):
    result = run_replay(ReplayConfig(findings=()))
    assert len(result.replayed) == 0
    assert result.still_present_count == 0


def test_replay_classifies_still_present(server):
    """Findings should reproduce when nothing changed."""
    pipeline = run_pipeline(_make_pipeline_cfg(server))
    # Original run with NO security headers → many F97 findings
    f97 = [f for f in pipeline.findings if f.source_module == "F97"]
    assert f97, "expected F97 findings from pipeline"

    cfg = ReplayConfig(findings=tuple(f97), rate_limit_per_second=100)
    result = run_replay(cfg)
    # Every finding should still be present (target unchanged)
    assert result.still_present_count == len(f97)
    assert result.disappeared_count == 0


def test_replay_classifies_disappeared_after_fix(server):
    """When the target adds the missing headers, findings should
    disappear."""
    pipeline = run_pipeline(_make_pipeline_cfg(server))
    f97 = [f for f in pipeline.findings if f.source_module == "F97"]
    assert f97, "expected F97 findings"

    # Simulate operator fixing the target: turn on all hardening headers
    _HEADERS_ENABLED["value"] = True

    cfg = ReplayConfig(findings=tuple(f97), rate_limit_per_second=100)
    result = run_replay(cfg)
    # The major headers (CSP, HSTS, X-Content-Type-Options, etc.)
    # should all disappear now that the server returns them.
    assert result.disappeared_count > 0, (
        f"expected at least some headers fixed, got "
        f"disappeared={result.disappeared_count}, "
        f"still_present={result.still_present_count}"
    )


def test_replay_inconclusive_on_unreachable_target():
    """When the target can't be reached, finding is INCONCLUSIVE."""
    finding = UnifiedFinding(
        rule_id="HSH-001",
        severity="HIGH",
        title="CSP missing",
        detail="",
        remediation="",
        source_module="F97",
        target="http://127.0.0.1:1/",  # port 1 — unreachable
    )
    cfg = ReplayConfig(
        findings=(finding,), timeout_seconds=2.0, rate_limit_per_second=100
    )
    result = run_replay(cfg)
    assert result.inconclusive_count == 1
    assert result.replayed[0].status == REPLAY_STATUS_INCONCLUSIVE


def test_replay_unknown_module_inconclusive():
    """Findings from modules with no replay implementation are
    classified as inconclusive, NOT disappeared."""
    finding = UnifiedFinding(
        rule_id="NUC:wordpress-detect",
        severity="INFO",
        title="WordPress detected",
        detail="",
        remediation="",
        source_module="F110",  # not implemented
        target="https://target.example/",
    )
    result = run_replay(ReplayConfig(findings=(finding,)))
    assert result.inconclusive_count == 1
    assert "replay not implemented for F110" in result.replayed[0].detail


def test_replay_inconclusive_when_target_not_url():
    """Findings without a valid http(s) target → inconclusive."""
    finding = UnifiedFinding(
        rule_id="HSH-001",
        severity="HIGH",
        title="x",
        detail="",
        remediation="",
        source_module="F97",
        target="not-a-url",
    )
    result = run_replay(ReplayConfig(findings=(finding,)))
    assert result.inconclusive_count == 1
    assert result.replayed[0].status == REPLAY_STATUS_INCONCLUSIVE


def test_replay_counts_match_replayed_list(server):
    pipeline = run_pipeline(_make_pipeline_cfg(server))
    findings = tuple(pipeline.findings[:5])  # cap at 5 for speed
    result = run_replay(ReplayConfig(findings=findings, rate_limit_per_second=100))
    total_classified = (
        result.still_present_count
        + result.disappeared_count
        + result.changed_count
        + result.inconclusive_count
    )
    assert total_classified == len(result.replayed)
    assert len(result.replayed) == len(findings)


def test_replay_elapsed_recorded(server):
    pipeline = run_pipeline(_make_pipeline_cfg(server))
    f97 = [f for f in pipeline.findings if f.source_module == "F97"][:2]
    result = run_replay(ReplayConfig(findings=tuple(f97), rate_limit_per_second=100))
    assert result.elapsed_seconds >= 0
    for r in result.replayed:
        assert r.elapsed_seconds >= 0


def test_replay_f102_js_libs():
    """A finding that says jquery 1.8.3 is vulnerable should still
    fire when re-analyzed (URL-pattern based)."""
    finding = UnifiedFinding(
        rule_id="VJS-001",
        severity="MEDIUM",
        title="jQuery 1.8.3 is vulnerable",
        detail="",
        remediation="",
        source_module="F102",
        target="https://target.example/jquery-1.8.3.min.js",
    )
    result = run_replay(ReplayConfig(findings=(finding,)))
    # F102 replay only inspects the URL — no network call needed
    assert result.still_present_count == 1


def test_replay_f102_js_libs_disappears_after_upgrade():
    """If the URL changes from 1.8.3 to 3.7.0, the rule disappears."""
    finding = UnifiedFinding(
        rule_id="VJS-001",
        severity="MEDIUM",
        title="jQuery 1.8.3 is vulnerable",
        detail="",
        remediation="",
        source_module="F102",
        target="https://target.example/jquery-3.7.0.min.js",  # upgraded
    )
    result = run_replay(ReplayConfig(findings=(finding,)))
    assert result.disappeared_count == 1


def test_replay_handles_exception_gracefully(server, monkeypatch):
    """If a replay function raises, the finding is inconclusive,
    not propagated as an exception."""
    finding = UnifiedFinding(
        rule_id="HSH-001",
        severity="HIGH",
        title="x",
        detail="",
        remediation="",
        source_module="F97",
        target=server + "/",
    )

    # Force the analyzer to raise
    import kryon.tools.replay.engine as engine_module

    def _boom(*a, **k):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(engine_module, "analyze_security_headers", _boom)

    result = run_replay(ReplayConfig(findings=(finding,), rate_limit_per_second=100))
    assert result.inconclusive_count == 1
    assert "synthetic failure" in result.replayed[0].detail


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    f = UnifiedFinding(
        rule_id="x",
        severity="LOW",
        title="x",
        detail="",
        remediation="",
        source_module="F97",
        target="x",
    )
    r = ReplayedFinding(original=f, status="x")
    with pytest.raises(FrozenInstanceError):
        r.status = "y"  # type: ignore[misc]


def test_replay_changed_severity_detected(server):
    """When a rule still fires but severity changes, the verdict is
    CHANGED (not still-present)."""
    # We don't have an easy way to mutate severity in the analyzer
    # mid-test, but we can verify the codepath via a synthetic
    # scenario where original.severity differs from analyzer output.
    # The analyzer never emits HSH-001 at MEDIUM (it's hardcoded
    # HIGH), so a finding tagged HSH-001/MEDIUM that re-fires from
    # the live server will come back as CHANGED.
    finding = UnifiedFinding(
        rule_id="HSH-001",
        severity="MEDIUM",  # original (intentionally wrong)
        title="CSP missing",
        detail="",
        remediation="",
        source_module="F97",
        target=server + "/",
    )
    result = run_replay(ReplayConfig(findings=(finding,), rate_limit_per_second=100))
    # The analyzer will emit HSH-001 with HIGH severity → CHANGED
    assert result.changed_count == 1
    assert result.replayed[0].new_severity == "HIGH"
