"""F191 — multi-endpoint sqlmap discovery hook tests."""

from __future__ import annotations

import pytest

from kryon.skills.playbooks.pre_hooks.endpoint_discovery_sqlmap_hook import (
    _CREDS_COLUMNS,
    _CREDS_TABLES,
    KNOWN_INJECTABLE_ENDPOINTS,
    _extract_dump_block,
    _is_responsive,
    _looks_injection_positive,
    _maybe_dump_creds,
    _red_team_enabled,
    _run_sqlmap_dump,
    _summarize_endpoint_results,
)

# ---------------------------------------------------------------------------
# Endpoint catalog
# ---------------------------------------------------------------------------


def test_known_endpoints_cover_common_apps():
    """Catalog must include the endpoint patterns we've seen vulnerable
    across the bench universe (Juice Shop, DVWA, WebGoat)."""
    paths = {e["path"] for e in KNOWN_INJECTABLE_ENDPOINTS}
    # Juice Shop's known SQLi endpoint
    assert "/rest/user/login" in paths
    # Common API auth endpoints
    assert any("/api/" in p and "login" in p for p in paths)
    # Common search GET endpoints with q= param
    assert any("search" in p for p in paths)


def test_each_endpoint_has_required_fields():
    for e in KNOWN_INJECTABLE_ENDPOINTS:
        assert "path" in e
        assert "method" in e
        assert e["method"] in {"GET", "POST"}
        if e["method"] == "POST":
            # POST needs --data
            assert "data" in e
            assert "content_type" in e


# ---------------------------------------------------------------------------
# _is_responsive — HTTP status filter
# ---------------------------------------------------------------------------


def test_responsive_accepts_2xx_3xx_4xx_5xx():
    """Anything in 200-599 means the path exists / handler ran. We
    don't filter by status because sqlmap can inject through 401/500
    handlers (proven in F187)."""
    for code in (200, 201, 301, 302, 400, 401, 403, 404, 500, 503):
        # 404 alone wouldn't be useful, but the helper returns True so
        # the caller decides — `_is_responsive` is just "did the server
        # answer at all?"
        assert _is_responsive(code) is True


def test_responsive_rejects_connection_failure():
    """0 / negative codes indicate connection failed — endpoint doesn't
    exist or server is down."""
    assert _is_responsive(0) is False
    assert _is_responsive(-1) is False
    assert _is_responsive(None) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Sqlmap output positive detection
# ---------------------------------------------------------------------------


def test_positive_detected_on_injection_point_keyword():
    sqlmap_out = """\
[INFO] testing connection
sqlmap identified the following injection point(s)
Parameter: q (GET)
    Type: boolean-based blind
"""
    assert _looks_injection_positive(sqlmap_out) is True


def test_positive_detected_on_is_vulnerable():
    out = "GET parameter 'id' is vulnerable. Do you want to keep testing?"
    assert _looks_injection_positive(out) is True


def test_negative_when_no_keywords():
    out = """\
[INFO] testing connection
[INFO] heuristic test shows parameter not injectable
[ERROR] all tested parameters do not appear to be injectable
"""
    assert _looks_injection_positive(out) is False


def test_negative_on_empty():
    assert _looks_injection_positive("") is False
    assert _looks_injection_positive(None) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Per-endpoint summary block
# ---------------------------------------------------------------------------


def test_summary_marks_positive_endpoints_explicitly():
    results = [
        {
            "endpoint": "/rest/user/login",
            "method": "POST",
            "status": 401,
            "sqlmap_summary": "Parameter: JSON email\nType: boolean-based blind",
            "injectable": True,
        },
        {
            "endpoint": "/search",
            "method": "GET",
            "status": 200,
            "sqlmap_summary": "not injectable",
            "injectable": False,
        },
    ]
    out = _summarize_endpoint_results(results)
    assert "POSITIVE" in out or "VULNERABLE" in out.upper()
    assert "/rest/user/login" in out
    assert "boolean-based blind" in out


def test_summary_empty_when_no_endpoints_probed():
    """If discovery + probing returned 0 results, the summary should
    say so explicitly so the model doesn't pretend it ran tests."""
    out = _summarize_endpoint_results([])
    assert "no endpoints" in out.lower() or "no results" in out.lower()


def test_summary_counts_positive_negative():
    results = [
        {"endpoint": "/a", "method": "GET", "status": 200, "sqlmap_summary": "vuln", "injectable": True},
        {"endpoint": "/b", "method": "GET", "status": 200, "sqlmap_summary": "ok", "injectable": False},
        {"endpoint": "/c", "method": "POST", "status": 401, "sqlmap_summary": "vuln", "injectable": True},
    ]
    out = _summarize_endpoint_results(results)
    # Count line present somewhere
    assert "2" in out and "3" in out  # 2 positive, 3 tested


def test_sqlmap_detection_uses_gentle_flags(monkeypatch):
    # Proven live vs Juice Shop: BU (boolean/union, NOT error-based) + single-thread
    # + ignore-code=500 owns the target; BEUST + threads=5 thrashed it (232s latency
    # → 0 injectable). See _SQLMAP_BASE_FLAGS rationale.
    from kryon.skills.playbooks.pre_hooks import endpoint_discovery_sqlmap_hook as hook

    captured = {}

    class _R:
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return _R()

    monkeypatch.setattr(hook.subprocess, "run", fake_run)
    hook._run_sqlmap_quick({"path": "/?id=1", "method": "GET"}, "http://t")
    cmd = captured["cmd"]
    assert "--technique=BU" in cmd
    assert "--technique=BEUST" not in cmd  # BEUST thrashed the target
    assert "--threads=1" in cmd  # single-thread — no concurrency thrash
    assert "--ignore-code=500,401" in cmd  # process the 500 body, don't skip it


# ---------------------------------------------------------------------------
# Deterministic scoped creds dump (post-confirmation pwn)
# ---------------------------------------------------------------------------


class TestRedTeamGate:
    def test_enabled_on_truthy_values(self, monkeypatch):
        for val in ("1", "true", "TRUE", "yes", "on"):
            monkeypatch.setenv("KRYON_RED_TEAM", val)
            assert _red_team_enabled() is True

    def test_disabled_when_unset_or_falsy(self, monkeypatch):
        monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
        assert _red_team_enabled() is False
        monkeypatch.setenv("KRYON_RED_TEAM", "0")
        assert _red_team_enabled() is False
        monkeypatch.setenv("KRYON_RED_TEAM", "false")
        assert _red_team_enabled() is False


class TestExtractDumpBlock:
    def test_extracts_from_table_marker(self):
        out = """\
[INFO] fetching entries
Database: main
Table: Users
[2 entries]
+----+-------------------+----------------------------------+
| id | email             | password                         |
+----+-------------------+----------------------------------+
| 1  | admin@juice-sh.op | 0192023a7bbd73250516f069df18b500 |
+----+-------------------+----------------------------------+
"""
        block = _extract_dump_block(out)
        assert "Table: Users" in block
        assert "admin@juice-sh.op" in block

    def test_empty_when_no_dump_markers(self):
        # A probe that found no data to extract → no false pwn claim.
        assert _extract_dump_block("[INFO] no columns matched, nothing to dump") == ""
        assert _extract_dump_block("") == ""
        assert _extract_dump_block(None) == ""  # type: ignore[arg-type]


class TestRunSqlmapDump:
    def test_dump_cmd_is_scoped_to_creds(self, monkeypatch):
        from kryon.skills.playbooks.pre_hooks import endpoint_discovery_sqlmap_hook as hook

        captured = {}

        class _R:
            stdout = "Table: Users\n[1 entries]"
            stderr = ""

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            captured["timeout"] = kw.get("timeout")
            return _R()

        monkeypatch.setattr(hook.subprocess, "run", fake_run)
        hook._run_sqlmap_dump({"path": "/rest/products/search?q=apple", "method": "GET"}, "http://t")
        cmd = captured["cmd"]
        assert "--dump" in cmd
        assert "-T" in cmd and _CREDS_TABLES in cmd
        assert "-C" in cmd and _CREDS_COLUMNS in cmd
        assert "--exclude-sysdbs" in cmd
        # Same gentle flags as detection — BU single-thread, no target thrash.
        assert "--technique=BU" in cmd
        assert "--threads=1" in cmd
        assert "--stop=8" in cmd  # cap rows so single-thread dump fits the budget
        # Generous budget — a single-thread boolean-blind dump is slow.
        assert captured["timeout"] and captured["timeout"] >= 300

    def test_dump_attaches_post_body(self, monkeypatch):
        from kryon.skills.playbooks.pre_hooks import endpoint_discovery_sqlmap_hook as hook

        captured = {}

        class _R:
            stdout = ""
            stderr = ""

        monkeypatch.setattr(hook.subprocess, "run", lambda cmd, **kw: (captured.update(cmd=cmd), _R())[1])
        ep = {"path": "/rest/user/login", "method": "POST", "data": '{"email":"x"}', "content_type": "application/json"}
        hook._run_sqlmap_dump(ep, "http://t")
        assert "--data" in captured["cmd"]
        assert '{"email":"x"}' in captured["cmd"]

    def test_dump_handles_missing_sqlmap(self, monkeypatch):
        from kryon.skills.playbooks.pre_hooks import endpoint_discovery_sqlmap_hook as hook

        def boom(cmd, **kw):
            raise FileNotFoundError

        monkeypatch.setattr(hook.subprocess, "run", boom)
        assert "[sqlmap not installed]" in hook._run_sqlmap_dump({"path": "/x", "method": "GET"}, "http://t")


class TestMaybeDumpCreds:
    _INJECTABLE = [
        {"endpoint": "/rest/products/search?q=apple", "method": "GET", "status": 200, "injectable": True},
    ]

    def test_no_dump_without_red_team(self, monkeypatch):
        monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
        # Even with an injectable endpoint, no dump when not red-team.
        assert _maybe_dump_creds(self._INJECTABLE, "http://t") == ""

    def test_no_dump_without_injectable(self, monkeypatch):
        monkeypatch.setenv("KRYON_RED_TEAM", "true")
        clean = [{"endpoint": "/x", "method": "GET", "status": 200, "injectable": False}]
        assert _maybe_dump_creds(clean, "http://t") == ""

    def test_dumps_first_injectable_under_red_team(self, monkeypatch):
        from kryon.skills.playbooks.pre_hooks import endpoint_discovery_sqlmap_hook as hook

        monkeypatch.setenv("KRYON_RED_TEAM", "true")
        called = {}

        def fake_dump(endpoint, target, **kw):
            called["path"] = endpoint["path"]
            return "Database: main\nTable: Users\n[1 entries]\n| admin@juice-sh.op | 0192023a |"

        monkeypatch.setattr(hook, "_run_sqlmap_dump", fake_dump)
        block = _maybe_dump_creds(self._INJECTABLE, "http://t")
        assert called["path"] == "/rest/products/search?q=apple"
        assert "CREDS DUMPED" in block
        assert "admin@juice-sh.op" in block

    def test_get_param_endpoint_preferred_over_login(self, monkeypatch):
        # A login WHERE-clause injection confirms vulnerable but often can't dump;
        # a GET query-param injection dumps cleanly. GET must be attempted first.
        from kryon.skills.playbooks.pre_hooks import endpoint_discovery_sqlmap_hook as hook

        results = [
            {"endpoint": "/rest/user/login", "method": "POST", "status": 500, "injectable": True},
            {"endpoint": "/rest/products/search?q=apple", "method": "GET", "status": 200, "injectable": True},
        ]
        order = hook._dump_candidate_paths(results)
        assert order[0] == "/rest/products/search?q=apple"  # flagged GET first
        assert order[-1] == "/rest/user/login" or "/rest/user/login" not in order[:1]

    def test_canonical_vector_tried_even_when_probe_skipped_it(self, monkeypatch):
        # Only login got flagged (search was skipped by the flaky responsive probe),
        # but SQLi IS confirmed → the canonical search vector must still be attempted.
        from kryon.skills.playbooks.pre_hooks import endpoint_discovery_sqlmap_hook as hook

        monkeypatch.setenv("KRYON_RED_TEAM", "true")
        results = [
            {"endpoint": "/rest/user/login", "method": "POST", "status": 500, "injectable": True},
        ]
        attempts = []

        def fake_dump(endpoint, target, **kw):
            attempts.append(endpoint["path"])
            # search (canonical, tried before login) yields the creds.
            if endpoint["path"] == "/rest/products/search?q=apple":
                return "Table: Users\n[2 entries]\n| admin@juice-sh.op | 0192023a |"
            return "[INFO] unable to retrieve"

        monkeypatch.setattr(hook, "_run_sqlmap_dump", fake_dump)
        block = _maybe_dump_creds(results, "http://t")
        assert "/rest/products/search?q=apple" in attempts  # canonical vector attempted
        assert "admin@juice-sh.op" in block

    def test_no_dump_when_no_sqli_confirmed_anywhere(self, monkeypatch):
        # No injectable endpoint at all → do NOT blind-dump canonical vectors on a
        # non-vulnerable target.
        from kryon.skills.playbooks.pre_hooks import endpoint_discovery_sqlmap_hook as hook

        monkeypatch.setenv("KRYON_RED_TEAM", "true")
        called = []
        monkeypatch.setattr(hook, "_run_sqlmap_dump", lambda e, t, **k: called.append(1) or "x")
        clean = [{"endpoint": "/x?id=1", "method": "GET", "status": 200, "injectable": False}]
        assert _maybe_dump_creds(clean, "http://t") == ""
        assert not called  # never invoked sqlmap

    def test_no_block_when_dump_extracts_nothing(self, monkeypatch):
        from kryon.skills.playbooks.pre_hooks import endpoint_discovery_sqlmap_hook as hook

        monkeypatch.setenv("KRYON_RED_TEAM", "true")
        # sqlmap ran but no rows came back → no false pwn claim.
        monkeypatch.setattr(hook, "_run_sqlmap_dump", lambda e, t, **k: "[INFO] nothing to dump")
        assert _maybe_dump_creds(self._INJECTABLE, "http://t") == ""
