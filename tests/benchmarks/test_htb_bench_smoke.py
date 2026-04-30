"""F81 — smoke tests for the HTB-style benchmark harness.

These tests don't spawn real targets — they exercise the pure-data
slice (parse_chain, check_flag, chain_match, aggregate) and verify
the runner's flow with `KRYON_BENCH_DRY_RUN=1` to inject a fixture
transcript instead of shelling out to docker.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


# ---------- Pure helpers ----------


class TestParseChain:
    def test_extracts_tools_from_invocation_glyph(self) -> None:
        from scripts.htb_bench.runner import parse_chain

        transcript = (
            "▸ run_command  curl -s http://target/\n"
            "  ✓ 0.1s · 200 OK\n"
            "▸ sqlmap_scan  http://target/?id=1\n"
            "  ✓ 12s · users: 5 entries\n"
        )
        assert parse_chain(transcript) == ("run_command", "sqlmap_scan")

    def test_preserves_order(self) -> None:
        from scripts.htb_bench.runner import parse_chain

        transcript = "▸ nmap  x\n▸ whatweb_scan  x\n▸ nuclei_scan  x\n"
        assert parse_chain(transcript) == ("nmap", "whatweb_scan", "nuclei_scan")

    def test_keeps_duplicates(self) -> None:
        """Some chains call run_command twice — that's information, not noise."""
        from scripts.htb_bench.runner import parse_chain

        transcript = "▸ run_command  echo 1\n▸ run_command  echo 2\n"
        assert parse_chain(transcript) == ("run_command", "run_command")

    def test_ignores_non_invocation_lines(self) -> None:
        from scripts.htb_bench.runner import parse_chain

        transcript = (
            "Some narrative text mentioning ▸ as a literal arrow\n"
            "  → also not an invocation\n"
            "▸ nmap  target\n"
        )
        # Only the line starting with whitespace+▸+tool_name counts.
        assert parse_chain(transcript) == ("nmap",)

    def test_empty_transcript_yields_empty_chain(self) -> None:
        from scripts.htb_bench.runner import parse_chain

        assert parse_chain("") == ()


class TestCheckFlag:
    def test_returns_first_matching_pattern(self) -> None:
        from scripts.htb_bench.runner import check_flag

        transcript = "users containing 5 entries\n"
        result = check_flag(transcript, [r"FAKE_PAT", r"users\s+containing"])
        assert result == r"users\s+containing"

    def test_returns_none_when_no_pattern_matches(self) -> None:
        from scripts.htb_bench.runner import check_flag

        assert check_flag("nothing relevant here", [r"FLAG\{[a-z]+\}"]) is None

    def test_case_insensitive_match(self) -> None:
        from scripts.htb_bench.runner import check_flag

        assert check_flag("USERS CONTAINING 5", [r"users\s+containing"]) is not None

    def test_empty_pattern_list_never_matches(self) -> None:
        from scripts.htb_bench.runner import check_flag

        assert check_flag("any content", []) is None


class TestChainMatch:
    def test_full_match_yields_one(self) -> None:
        from scripts.htb_bench.runner import chain_match

        actual = ("nmap", "sqlmap_scan", "run_command")
        required = ["sqlmap_scan", "run_command"]
        assert chain_match(actual, required) == 1.0

    def test_partial_match_proportional(self) -> None:
        from scripts.htb_bench.runner import chain_match

        # 1 of 2 required tools used.
        assert chain_match(("nmap",), ["sqlmap_scan", "run_command"]) == 0.0
        assert chain_match(("nmap", "sqlmap_scan"), ["sqlmap_scan", "run_command"]) == 0.5

    def test_empty_required_yields_one(self) -> None:
        """Vacuous truth — no required tools to satisfy."""
        from scripts.htb_bench.runner import chain_match

        assert chain_match(("nmap",), []) == 1.0

    def test_order_independent(self) -> None:
        from scripts.htb_bench.runner import chain_match

        assert chain_match(
            ("run_command", "sqlmap_scan", "nmap"),
            ["nmap", "sqlmap_scan"],
        ) == 1.0


# ---------- Walkthrough loader ----------


class TestLoadWalkthrough:
    def test_loads_pilot_walkthrough(self) -> None:
        from scripts.htb_bench.runner import load_walkthrough

        repo_root = Path(__file__).resolve().parents[2]
        path = repo_root / "tests" / "benchmarks" / "htb_style" / "walkthroughs" / "dvwa-sqli-low.json"
        wt = load_walkthrough(path)
        assert wt["slug"] == "dvwa-sqli-low"
        assert wt["category"] == "sqli"
        assert any(s["required"] for s in wt["expected_chain"])

    def test_rejects_walkthrough_missing_required_keys(self, tmp_path: Path) -> None:
        from scripts.htb_bench.runner import load_walkthrough

        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"slug": "x"}), encoding="utf-8")
        with pytest.raises(ValueError, match="missing keys"):
            load_walkthrough(bad)


# ---------- Aggregator ----------


class TestAggregate:
    def _result(self, slug: str, pwn: bool, score: float = 0.0, time: float | None = None,
                error: str | None = None):
        from scripts.htb_bench.runner import RunResult

        return RunResult(
            slug=slug,
            pwn=pwn,
            chain_match_score=score,
            time_to_pwn_seconds=time,
            wall_time_seconds=(time or 30.0),
            error=error,
        )

    def test_all_pwned_yields_full_pwn_rate(self) -> None:
        from scripts.htb_bench.scorer import aggregate

        results = [
            self._result("a", pwn=True, score=1.0, time=10.0),
            self._result("b", pwn=True, score=0.5, time=20.0),
        ]
        wts = {
            "a": {"category": "sqli"},
            "b": {"category": "xss"},
        }
        report = aggregate(results, wts)
        assert report.total_targets == 2
        assert report.pwned == 2
        assert report.pwn_rate == 1.0
        assert report.mean_chain_match == 0.75
        assert report.median_time_to_pwn_seconds == 15.0

    def test_partial_pwn_breakdown_by_category(self) -> None:
        from scripts.htb_bench.scorer import aggregate

        results = [
            self._result("a", pwn=True, score=1.0, time=10.0),
            self._result("b", pwn=False),
            self._result("c", pwn=True, score=1.0, time=20.0),
        ]
        wts = {
            "a": {"category": "sqli"},
            "b": {"category": "sqli"},
            "c": {"category": "xss"},
        }
        report = aggregate(results, wts)
        assert report.pwn_rate == pytest.approx(2 / 3)
        assert report.by_category["sqli"]["pwn_rate"] == 0.5
        assert report.by_category["xss"]["pwn_rate"] == 1.0

    def test_errors_counted_separately(self) -> None:
        from scripts.htb_bench.scorer import aggregate

        results = [
            self._result("a", pwn=False, error="target_not_ready"),
            self._result("b", pwn=False, error="kryon_timeout"),
            self._result("c", pwn=True, score=1.0, time=10.0),
        ]
        report = aggregate(results, {s.slug: {"category": "x"} for s in results})
        assert report.errors == 2
        assert report.error_breakdown["target_not_ready"] == 1
        assert report.error_breakdown["kryon_timeout"] == 1

    def test_empty_results_yields_zero_metrics(self) -> None:
        from scripts.htb_bench.scorer import aggregate

        report = aggregate([], {})
        assert report.total_targets == 0
        assert report.pwn_rate == 0.0
        assert report.mean_chain_match == 0.0
        assert report.median_time_to_pwn_seconds is None


# ---------- Runner end-to-end with dry-run ----------


class TestRunnerDryRun:
    def test_dry_run_flow_pwn_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """KRYON_BENCH_DRY_RUN=1 + injected fixture → full RunResult."""
        from scripts.htb_bench.runner import run_target

        # Stub a walkthrough that points at a URL (no spawn needed).
        wt_path = tmp_path / "stub.json"
        wt_path.write_text(json.dumps({
            "slug": "stub-pwn",
            "title": "Stub",
            "source": {"type": "url", "ref": "http://stub.local"},
            "expected_chain": [
                {"tool": "sqlmap_scan", "rationale": "x", "required": True},
                {"tool": "run_command", "rationale": "y", "required": True},
            ],
            "flag_pattern": [r"FLAG\{pwn\}"],
            "wall_budget_seconds": 5,
        }), encoding="utf-8")

        # Inject a fake transcript that has both required tools + the flag.
        monkeypatch.setenv("KRYON_BENCH_DRY_RUN", "1")
        monkeypatch.setenv(
            "KRYON_BENCH_FIXTURE_TRANSCRIPT",
            "▸ sqlmap_scan  http://stub.local/?id=1\n"
            "▸ run_command  echo done\n"
            "found FLAG{pwn} in response\n",
        )

        result = run_target(wt_path)

        assert result.pwn is True
        assert result.chain_match_score == 1.0
        assert result.time_to_pwn_seconds is not None
        assert "sqlmap_scan" in result.actual_chain
        assert result.flag_match_pattern == r"FLAG\{pwn\}"
        assert result.error is None

    def test_dry_run_no_flag_yields_no_pwn(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from scripts.htb_bench.runner import run_target

        wt_path = tmp_path / "stub.json"
        wt_path.write_text(json.dumps({
            "slug": "stub-fail",
            "title": "Stub",
            "source": {"type": "url", "ref": "http://stub.local"},
            "expected_chain": [
                {"tool": "sqlmap_scan", "rationale": "x", "required": True},
            ],
            "flag_pattern": [r"FLAG\{never\}"],
            "wall_budget_seconds": 5,
        }), encoding="utf-8")

        monkeypatch.setenv("KRYON_BENCH_DRY_RUN", "1")
        monkeypatch.setenv(
            "KRYON_BENCH_FIXTURE_TRANSCRIPT",
            "▸ nmap  stub.local\n  ✓ 0.1s · 80 open\n",
        )

        result = run_target(wt_path)

        assert result.pwn is False
        assert result.chain_match_score == 0.0  # no required tool used
        assert result.time_to_pwn_seconds is None
        assert result.flag_match_pattern is None


# ---------- F82 — multi-platform CLI ----------


class TestPlatformResolution:
    """The CLI must walk both htb_style/ and tryhackme/ labsets so a
    slug from either platform resolves cleanly."""

    def test_resolves_htb_slug_when_platform_unspecified(self) -> None:
        from scripts.htb_bench.cli import _resolve_walkthrough

        path, plat = _resolve_walkthrough("portswigger-sqli-where-clause", None)
        assert plat == "htb"
        assert path.exists()

    def test_resolves_tryhackme_slug_when_platform_unspecified(self) -> None:
        from scripts.htb_bench.cli import _resolve_walkthrough

        path, plat = _resolve_walkthrough("thm-bandit-ssh-foothold", None)
        assert plat == "tryhackme"
        assert path.exists()

    def test_explicit_platform_wins_over_autodetect(self) -> None:
        """When the operator says `--platform htb` for a slug that exists
        only on tryhackme, the resolver still returns the htb path
        (caller wants to fail fast, not silently cross-platform)."""
        from scripts.htb_bench.cli import _resolve_walkthrough

        path, plat = _resolve_walkthrough("thm-bandit-ssh-foothold", "htb")
        assert plat == "htb"
        # File doesn't exist in htb dir — caller will see SKIP, not silent jump.
        assert not path.exists()

    def test_pilots_present_on_both_platforms(self) -> None:
        """Pin: at least one ready walkthrough exists per platform so the
        F83 scoreboard always has a non-empty data point per column."""
        from scripts.htb_bench.cli import _load_labset_for, PLATFORMS

        for plat in PLATFORMS:
            labset = _load_labset_for(plat)
            ready = [t for t in labset["targets"] if t.get("status") == "ready"]
            assert ready, f"platform {plat!r} has no ready walkthrough"

    def test_select_targets_all_platforms_returns_tuples(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`--platform all --status ready` must yield (slug, platform)
        tuples covering both labsets."""
        import argparse

        from scripts.htb_bench.cli import _select_targets

        args = argparse.Namespace(
            target=None, all=True, platform="all", status="ready",
        )
        pairs = _select_targets(args)
        platforms_seen = {plat for _, plat in pairs}
        assert "htb" in platforms_seen
        assert "tryhackme" in platforms_seen


class TestTryHackMeWalkthroughs:
    def test_bandit_walkthrough_loads(self) -> None:
        from scripts.htb_bench.runner import load_walkthrough
        from scripts.htb_bench.cli import _resolve_walkthrough

        path, _ = _resolve_walkthrough("thm-bandit-ssh-foothold", "tryhackme")
        wt = load_walkthrough(path)
        assert wt["category"] == "auth"
        assert any(s["required"] for s in wt["expected_chain"])
        assert wt["source"]["type"] == "url"  # ToS-safe — no automation needed

    def test_shellshock_walkthrough_loads(self) -> None:
        from scripts.htb_bench.runner import load_walkthrough
        from scripts.htb_bench.cli import _resolve_walkthrough

        path, _ = _resolve_walkthrough("thm-vulhub-shellshock", "tryhackme")
        wt = load_walkthrough(path)
        assert wt["category"] == "rce"
        # CVE-2014-6271 reproducer is a docker-compose target.
        assert wt["source"]["type"] == "docker_compose"
