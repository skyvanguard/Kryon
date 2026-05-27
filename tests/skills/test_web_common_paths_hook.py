"""FASE 11.T — web common paths pre_hook tests.

The Bench Robots run (2026-05-27) confirmed our infra (Q+R+S) handles
the SDK / subprocess / message-list edge cases but the agent still
NEVER consulted ``/robots.txt`` — the very path the lab hides flags
behind. The model just emitted ``whatweb + curl -I`` against the
root and gave up.

FASE 11.T closes that gap with a deterministic pre_hook that probes
a curated list of well-known paths and injects the findings into the
first reflection turn. The model doesn't get to "decide" whether to
check /robots.txt; the answer is already in the conversation.

Tests pin:
1. The helper returns a structured report when /robots.txt is served.
2. ``Disallow:`` entries appear verbatim in the output (so the
   ``fact_extractor`` can pick them up via the existing
   ``_DISALLOW_PATH_RE``).
3. Empty ctx target → graceful skip, no crash.
4. All-404 target → "no interesting paths" summary, not silence.
5. Wall-clock bound: even against a server that hangs every request,
   the helper returns within ~30s (per-path timeout × small N).
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import time

import pytest

from kryon.skills.playbooks.pre_hooks.web_common_paths_hook import run


@pytest.fixture
def robots_server():
    """Mini HTTP server that mimics the Robots THM lab: serves
    ``/robots.txt`` with disallow paths, 404s for most other paths,
    plus a 200 on ``/admin`` for variety.

    FASE 11.U: also serves ``/harm/to/self/login.php`` and
    ``/harm/to/self/`` (directory listing) so the chain-enumeration
    step can find them. This mirrors what the real lab exposes
    behind the /harm/to/self disallow entry."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        # Silence the test output.
        def log_message(self, *_args, **_kwargs) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/robots.txt":
                body = (
                    "User-agent: *\n"
                    "Disallow: /post/\n"
                    "Disallow: /harm/to/self/\n"
                    "Disallow: /admin/\n"
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/admin":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>admin login</html>")
                return
            # FASE 11.U — disallow chain enumeration targets
            if self.path == "/harm/to/self/":
                body = b"<html><h1>Index of /harm/to/self/</h1><a href='login.php'>login.php</a></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/harm/to/self/login.php":
                body = b"<html><body><form>Username:<input name=u><input type=submit></form></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_run_reports_robots_txt_disallow_entries_verbatim(robots_server) -> None:
    """Critical invariant: the fact_extractor downstream relies on
    matching ``Disallow:`` lines in the reflection turn. The pre_hook
    MUST emit those lines verbatim — not summarized, not truncated
    mid-path — so the existing parser keeps working."""
    out = run({"target": f"http://127.0.0.1:{robots_server}"})
    assert "Disallow: /post/" in out
    assert "Disallow: /harm/to/self/" in out
    assert "Disallow: /admin/" in out


def test_run_lists_interesting_paths_first(robots_server) -> None:
    """``/robots.txt`` (200) + ``/admin`` (200) should appear in the
    'interesting' section above the 404 noise."""
    out = run({"target": f"http://127.0.0.1:{robots_server}"})
    # Interesting block must come before the non-existent block.
    interesting_idx = out.find("Interesting paths")
    nonexistent_idx = out.find("Non-existent")
    assert interesting_idx != -1, "missing 'Interesting paths' section"
    if nonexistent_idx != -1:
        assert interesting_idx < nonexistent_idx
    assert "/robots.txt" in out
    assert "/admin" in out


def test_run_handles_empty_target() -> None:
    """No target → short graceful skip message, not a crash."""
    out = run({})
    assert isinstance(out, str)
    assert "no target" in out.lower()


def test_run_handles_missing_ctx_target_key() -> None:
    out = run({"client_name": "bench-thm"})
    assert "no target" in out.lower()


def test_run_normalizes_target_without_scheme(robots_server) -> None:
    """Operator can pass ``127.0.0.1:port`` without ``http://`` — the
    helper must add the scheme rather than crash on urllib parse."""
    out = run({"target": f"127.0.0.1:{robots_server}"})
    assert "Disallow: /post/" in out


def test_run_target_with_trailing_slash_normalizes(robots_server) -> None:
    """``http://host/`` and ``http://host`` must produce identical
    probes — no double-slash in the URLs."""
    out_with_slash = run({"target": f"http://127.0.0.1:{robots_server}/"})
    out_no_slash = run({"target": f"http://127.0.0.1:{robots_server}"})
    # Both must have surfaced /robots.txt — exact equality of the
    # output isn't guaranteed (status codes shouldn't change but
    # ordering of concurrent results may differ slightly).
    assert "Disallow: /post/" in out_with_slash
    assert "Disallow: /post/" in out_no_slash


def test_run_completes_within_wall_clock_budget(robots_server) -> None:
    """Total wall-clock for the probe MUST stay under 25s even on a
    well-behaved server. The bench loop budget allows ~30s for the
    pre_hook; anything longer regresses the bench."""
    start = time.monotonic()
    run({"target": f"http://127.0.0.1:{robots_server}"})
    elapsed = time.monotonic() - start
    assert elapsed < 25.0, f"web_common_paths took {elapsed:.2f}s; budget regression"


def test_run_handles_unreachable_target() -> None:
    """Unroutable target → return within budget (per-path timeout
    kicks in) and emit an output saying no interesting paths."""
    # 10.255.255.1 is reserved; should refuse fast / time out fast.
    start = time.monotonic()
    out = run({"target": "http://10.255.255.1"})
    elapsed = time.monotonic() - start
    assert elapsed < 25.0, f"unreachable target hang: {elapsed:.2f}s"
    assert isinstance(out, str)
    # Either a "no interesting" summary or per-path errors — both
    # acceptable as long as we returned a string.


def test_run_emits_well_formed_markdown_header(robots_server) -> None:
    """The output starts with a markdown H1 naming the target — the
    reflection-prompt renderer relies on this for the section title."""
    out = run({"target": f"http://127.0.0.1:{robots_server}"})
    assert out.startswith("# "), f"missing markdown header: {out[:60]!r}"
    # Target URL should appear in the header (helps the model anchor
    # findings to the right host when multiple targets are probed).
    assert "127.0.0.1" in out.splitlines()[0]


def test_run_includes_robots_txt_body_inline_when_present(robots_server) -> None:
    """The /robots.txt body is the entire point of this probe —
    not just the status code. The helper must inline the body so the
    fact_extractor's _DISALLOW_PATH_RE picks it up downstream."""
    out = run({"target": f"http://127.0.0.1:{robots_server}"})
    # The body block should be present (we render robots.txt fully).
    assert "User-agent:" in out


# ---------------------------------------------------------------------------
# FASE 11.T.2 — prominent action items for disallow paths
# ---------------------------------------------------------------------------
#
# Bench Robots run #1 with FASE 11.T showed the model receiving the
# pre_hook output and DESPITE seeing the disallow paths, narrating
# "web_common_paths didn't return anything" and skipping straight to
# whatweb. The fix is to make the disallow paths IMPOSSIBLE to ignore:
# explicit imperative + action items + 🚨 markers at the top.


def test_run_surfaces_disallow_paths_as_explicit_action_items(robots_server) -> None:
    """When /robots.txt yields Disallow entries, the output must list
    them as concrete `curl <target><path>` action items near the top —
    not just inline inside the body block. The model's reasoning loop
    needs to see CONCRETE NEXT MOVES, not just data."""
    out = run({"target": f"http://127.0.0.1:{robots_server}"})
    # KEY FINDING header for disallow paths.
    assert "KEY FINDING" in out
    # Each disallow path appears as a concrete action item.
    target_url = f"http://127.0.0.1:{robots_server}"
    assert f"{target_url}/post/" in out
    assert f"{target_url}/harm/to/self/" in out
    assert f"{target_url}/admin/" in out
    # Imperative directive present.
    assert "ACCIÓN OBLIGATORIA" in out or "curl" in out


def test_run_disallow_action_items_appear_before_404_noise(robots_server) -> None:
    """The KEY FINDING block must come BEFORE the non-existent 404
    list — model reads top-down and the 404 noise was burying the
    actionable signal."""
    out = run({"target": f"http://127.0.0.1:{robots_server}"})
    key_idx = out.find("KEY FINDING")
    nonex_idx = out.find("Non-existent")
    if nonex_idx != -1:
        assert key_idx != -1
        assert key_idx < nonex_idx, "KEY FINDING block must precede 404 noise"


def test_run_no_disallow_section_when_robots_txt_missing() -> None:
    """If /robots.txt isn't served (404 / error / no disallow entries),
    we MUST NOT emit a misleading KEY FINDING header. The block is
    conditional on actual disallow content."""
    # Use an unreachable target so no probe succeeds.
    out = run({"target": "http://10.255.255.1"})
    assert "KEY FINDING" not in out, (
        "should not claim disallow finding when /robots.txt absent"
    )


# ---------------------------------------------------------------------------
# FASE 11.T.4 — ctx resolution priority (host > target)
# ---------------------------------------------------------------------------
#
# Bench Robots run #3 surfaced the worst-case false-positive of
# ``build_turn_ctx``: the user input "find user.txt and root.txt
# flags" caused ``_HOST_RE`` to match ``user.txt`` as a hostname and
# populate ``ctx['target'] = 'user.txt'``. The helper then probed
# http://user.txt/... and every path errored. The env-backed
# ``ctx['host']`` is reliable; we must prefer it.


def test_run_prefers_ctx_host_over_ctx_target(robots_server) -> None:
    """When ctx has both host (env-backed, correct) and target
    (regex-detected, wrong), the helper MUST use host."""
    out = run({
        "host": f"http://127.0.0.1:{robots_server}",  # correct
        "target": "user.txt",  # false positive from "find user.txt"
    })
    # Should hit the real server, not http://user.txt
    assert "Disallow: /post/" in out
    assert "KEY FINDING" in out


def test_run_falls_back_to_target_when_host_empty(robots_server) -> None:
    """Older call sites that only pass ``target`` (no host key) must
    still work — backward compat."""
    out = run({"target": f"http://127.0.0.1:{robots_server}"})
    assert "Disallow: /post/" in out


def test_run_handles_both_missing_gracefully() -> None:
    """Neither host nor target → graceful skip, not crash."""
    out = run({"host": "", "target": ""})
    assert "no target" in out.lower() or "[" in out


# ---------------------------------------------------------------------------
# FASE 11.U — disallow path chain enumeration
# ---------------------------------------------------------------------------
#
# Bench Robots T.4 (2026-05-27) achieved PARTIAL with 9 findings —
# model consumed the KEY FINDING block and emitted findings for each
# Disallow path. But it never CURLED those paths to discover the
# real assets (login.php / admin.php / register.php). The chain
# stopped at "disallow paths exist" instead of progressing to
# "disallow paths contain login.php".
#
# FASE 11.U closes the gap by extending web_common_paths_hook to
# auto-probe sub-paths under each Disallow entry: ``<disallow>/``,
# ``<disallow>/login.php``, ``<disallow>/admin.php``, etc. Live hits
# (200) get surfaced as new findings at the top of the output.


def test_run_enumerates_subpaths_under_disallow(robots_server) -> None:
    """The mock server hides /harm/to/self/login.php behind the
    /harm/to/self disallow entry. The chain step must discover it
    and surface the 200 in the output."""
    out = run({"host": f"http://127.0.0.1:{robots_server}"})
    # The auto-probed sub-path should appear as a LIVE finding.
    assert "/harm/to/self/login.php" in out
    # Marked as live (200).
    assert "200" in out


def test_run_enumeration_includes_directory_listing(robots_server) -> None:
    """When the disallow path itself responds 200 (directory
    listing), surface it — that's a separate finding from
    sub-files."""
    out = run({"host": f"http://127.0.0.1:{robots_server}"})
    assert "/harm/to/self/" in out


def test_run_enumeration_section_has_imperative_action(robots_server) -> None:
    """The chain-enum section must include explicit follow-up
    commands so the model knows what to do with the live hits
    (curl the form, brute-force, sqlmap, etc.)."""
    out = run({"host": f"http://127.0.0.1:{robots_server}"})
    # Output must contain the chain-enum header so model knows
    # this is a separate section from the initial probe.
    assert "DISALLOW PATH ENUMERATION" in out or "/harm/to/self/login.php" in out


def test_run_chain_enumeration_completes_within_budget(robots_server) -> None:
    """The full probe (common paths + disallow chain) must stay
    within ~60s wall-clock against a fast local server."""
    start = time.monotonic()
    run({"host": f"http://127.0.0.1:{robots_server}"})
    elapsed = time.monotonic() - start
    assert elapsed < 60.0, f"chain enum took {elapsed:.2f}s; budget regression"


def test_run_no_chain_section_when_no_disallow_paths() -> None:
    """If /robots.txt didn't yield disallow paths, the chain
    enumeration section must NOT appear (would just spam 404s)."""
    out = run({"host": "http://10.255.255.1"})  # unreachable
    assert "DISALLOW PATH ENUMERATION" not in out
