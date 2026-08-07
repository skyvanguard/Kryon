"""Fase 3 — patch-diff seeding (deterministic, no ChromaDB / embeddings / net).

Fake enriched-CVE-diff JSONL mirrors the real EnrichedEntry shape (cve_id,
cwe_ids, ecosystem, files[].added_calls/removed_calls).
"""

from __future__ import annotations

import json
from pathlib import Path

from kryon.intelligence.patch_seed import (
    PatchSeed,
    boost_scores,
    load_seeds_from_jsonl,
    render_seed_block,
    seeds_matching_code,
)

# One npm + one pip entry; the pip one patches `os.system`/`subprocess_call`.
_ENTRIES = [
    {
        "cve_id": "CVE-2026-1111",
        "cwe_ids": ["CWE-78"],
        "ecosystem": "pip",
        "summary": "OS command injection via unsanitized filename",
        "subject": "sanitize filename before shell call",
        "files": [
            {"path": "app/run.py", "removed_calls": ["os.system", "if"], "added_calls": ["shlex_quote"]},
        ],
    },
    {
        "cve_id": "CVE-2026-2222",
        "cwe_ids": ["CWE-89"],
        "ecosystem": "npm",
        "summary": "SQLi in query builder",
        "subject": "parameterize query",
        "files": [
            {"path": "db.js", "removed_calls": ["rawQuery"], "added_calls": ["parameterize"]},
        ],
    },
    # No usable calls → must be skipped.
    {
        "cve_id": "CVE-2026-3333",
        "cwe_ids": ["CWE-1"],
        "ecosystem": "pip",
        "files": [{"path": "x", "removed_calls": ["if"]}],
    },
]


def _write_jsonl(tmp_path: Path) -> Path:
    p = tmp_path / "corpus.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in _ENTRIES) + "\n", encoding="utf-8")
    return p


class TestLoad:
    def test_parses_entries_with_sink_calls(self, tmp_path):
        seeds = load_seeds_from_jsonl(_write_jsonl(tmp_path))
        ids = {s.cve_id for s in seeds}
        assert "CVE-2026-1111" in ids and "CVE-2026-2222" in ids
        # The entry whose only call is noise ("if") is dropped.
        assert "CVE-2026-3333" not in ids

    def test_noise_calls_filtered(self, tmp_path):
        seeds = load_seeds_from_jsonl(_write_jsonl(tmp_path))
        pip_seed = next(s for s in seeds if s.cve_id == "CVE-2026-1111")
        assert "os.system" in pip_seed.sink_calls
        assert "shlex_quote" in pip_seed.sink_calls
        assert "if" not in pip_seed.sink_calls  # noise removed

    def test_ecosystem_filter(self, tmp_path):
        seeds = load_seeds_from_jsonl(_write_jsonl(tmp_path), ecosystem="pip")
        assert all(s.ecosystem == "pip" for s in seeds)
        assert {s.cve_id for s in seeds} == {"CVE-2026-1111"}

    def test_limit_caps(self, tmp_path):
        seeds = load_seeds_from_jsonl(_write_jsonl(tmp_path), limit=1)
        assert len(seeds) == 1

    def test_missing_file_returns_empty(self, tmp_path):
        assert load_seeds_from_jsonl(tmp_path / "nope.jsonl") == []

    def test_malformed_line_skipped(self, tmp_path):
        p = tmp_path / "bad.jsonl"
        p.write_text('not json\n{"cve_id":"CVE-9","files":[{"removed_calls":["dangerous_eval"]}]}\n', encoding="utf-8")
        seeds = load_seeds_from_jsonl(p)
        assert len(seeds) == 1 and seeds[0].cve_id == "CVE-9"


class TestMatching:
    def _seed(self):
        return PatchSeed(
            cve_id="CVE-X",
            cwes=("CWE-78",),
            ecosystem="pip",
            summary="cmd inj",
            subject="fix",
            sink_calls=("os.system", "popen"),
        )

    def test_matches_returns_present_calls(self):
        code = "def f():\n    os.system(cmd)\n"
        assert self._seed().matches(code) == ("os.system",)

    def test_seeds_matching_code_filters(self):
        s = self._seed()
        assert seeds_matching_code("os.system(x)", [s]) == [s]
        assert seeds_matching_code("print(1)", [s]) == []


class TestBoost:
    def test_boosts_file_with_patched_sink(self, tmp_path):
        vuln = tmp_path / "vuln.py"
        vuln.write_text("os.system(user_input)", encoding="utf-8")
        clean = tmp_path / "clean.py"
        clean.write_text("x = 1 + 2", encoding="utf-8")

        seed = PatchSeed("CVE-X", ("CWE-78",), "pip", "s", "f", ("os.system",))
        # clean starts higher; the boost must lift vuln above it.
        scored = [(clean, 3), (vuln, 1)]
        out = boost_scores(scored, [seed], reader=lambda p: Path(p).read_text(encoding="utf-8"))
        assert out[0][0] == vuln  # boosted to the top

    def test_no_seeds_is_identity(self, tmp_path):
        scored = [(tmp_path / "a", 2)]
        assert boost_scores(scored, [], reader=lambda p: "") == scored


class TestRender:
    def test_empty_when_no_seeds(self):
        assert render_seed_block([]) == ""

    def test_renders_cve_and_sinks(self):
        seed = PatchSeed("CVE-2026-1111", ("CWE-78",), "pip", "cmd inj", "fix", ("os.system",))
        block = render_seed_block([seed])
        assert "CVE-2026-1111" in block
        assert "CWE-78" in block
        assert "os.system" in block
        assert "variant" in block.lower()

    def test_caps_seed_count(self):
        seeds = [PatchSeed(f"CVE-{i}", ("CWE-1",), "pip", "", "", ("call_x",)) for i in range(20)]
        block = render_seed_block(seeds, max_seeds=3)
        assert block.count("CVE-") == 3
