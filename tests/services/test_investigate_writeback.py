"""F203.F — Tests for investigate_writeback.

Cubre:
- outcome heuristic (success / partial / fail)
- chain extraction from RunResult.new_items
- profile building from hints
- write_back persistence path (mock add_experience)
- KRYON_NO_WRITEBACK env opt-out
- Chain < 2 skipped
- ImportError on learning module → graceful skip
- Banca-safe contract (source-level check)
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.services.investigate_writeback import (
    _build_profile_from_hints,
    _extract_chain,
    _outcome_from_summary,
    write_back_from_investigate,
)

# ---------------------------------------------------------------------------
# _outcome_from_summary
# ---------------------------------------------------------------------------


class TestOutcomeHeuristic:
    @pytest.mark.parametrize(
        "text",
        [
            "no se pudo identificar el target",
            "did not find any vulnerability",
            "could not connect to the host",
            "no encontré evidencia de XSS",
        ],
    )
    def test_fail_markers(self, text):
        assert _outcome_from_summary(text) == "fail"

    @pytest.mark.parametrize(
        "text",
        [
            "Hallazgo parcial: indicio de SQLi",
            "Sospechoso pero no concluyente",
            "Posible XSS, necesita verificación",
            "tentative finding requires manual review",
        ],
    )
    def test_partial_markers(self, text):
        assert _outcome_from_summary(text) == "partial"

    @pytest.mark.parametrize(
        "text",
        [
            "Encontré CWE-79 confirmado en /search",
            "Found 3 confirmed findings on the target",
            "Audit complete: 5 critical CWE-89 instances",
        ],
    )
    def test_success_default(self, text):
        assert _outcome_from_summary(text) == "success"

    def test_empty_text_is_fail(self):
        assert _outcome_from_summary("") == "fail"

    def test_none_is_fail(self):
        assert _outcome_from_summary(None or "") == "fail"

    @pytest.mark.parametrize(
        "text",
        [
            # T4-M9: definitive foothold evidence must win over an incidental
            # negative phrase, or the synthesizer rejects a genuinely successful run.
            "found no results for XSS but got a shell — uid=0(root)",
            "this could not have been easier, root obtained via sudo",
            "did not find SQLi; captured flag{deadbeef} through the upload",
            "no results on nuclei, but pwned via CVE-2021-41773",
        ],
    )
    def test_success_evidence_overrides_incidental_negatives(self, text):
        assert _outcome_from_summary(text) == "success"


# ---------------------------------------------------------------------------
# _extract_chain
# ---------------------------------------------------------------------------


class TestExtractChain:
    def test_empty_items_returns_empty(self):
        assert _extract_chain([]) == []

    def test_extracts_tool_call(self):
        tool_call = SimpleNamespace(
            raw_item=SimpleNamespace(
                name="web_fetch_smart",
                arguments={"url": "http://x"},
                call_id="call_1",
            )
        )
        chain = _extract_chain([tool_call])
        assert len(chain) == 1
        assert chain[0]["tool"] == "web_fetch_smart"
        assert "url" in chain[0]["args"]
        assert chain[0]["output_preview"] == ""

    def test_attaches_output_to_matching_call(self):
        call = SimpleNamespace(
            raw_item=SimpleNamespace(
                name="run_command",
                arguments={"command": "ls /tmp"},
                call_id="call_42",
            )
        )
        output = SimpleNamespace(
            raw_item=SimpleNamespace(
                output="file1.txt\nfile2.txt",
                call_id="call_42",
            )
        )
        chain = _extract_chain([call, output])
        assert len(chain) == 1
        assert "file1.txt" in chain[0]["output_preview"]

    def test_output_fallback_to_last_unattached(self):
        # Output without call_id should attach to the most recent call
        call = SimpleNamespace(raw_item=SimpleNamespace(name="curl", arguments={}))
        output = SimpleNamespace(raw_item=SimpleNamespace(output="HTTP 200 OK"))
        chain = _extract_chain([call, output])
        assert chain[0]["output_preview"] == "HTTP 200 OK"

    def test_truncates_long_args(self):
        big_args = {"data": "x" * 1000}
        call = SimpleNamespace(raw_item=SimpleNamespace(name="x", arguments=big_args))
        chain = _extract_chain([call])
        assert len(chain[0]["args"]) <= 510  # 500 + minor overhead


# ---------------------------------------------------------------------------
# chain_from_result — extract + hooks-captured fallback (F203.K parity)
# ---------------------------------------------------------------------------
class TestChainFromResult:
    def test_uses_new_items_when_present(self):
        from kryon.services.investigate_writeback import chain_from_result

        call = SimpleNamespace(raw_item=SimpleNamespace(name="curl", arguments={"url": "http://x"}))
        result = SimpleNamespace(new_items=[call])
        chain = chain_from_result(result)
        assert len(chain) == 1
        assert chain[0]["tool"] == "curl"

    def test_falls_back_to_captured_chain_when_new_items_empty(self):
        """The stuck/MaxTurns case: new_items dropped, but the RunHooks
        captured the real tool calls. The report must not claim 0 tool calls."""
        from kryon.services.investigate_writeback import chain_from_result

        captured = [
            {"tool": "web_fetch_smart", "args": "{}", "output_preview": "HTTP 200"},
            {"tool": "run_command", "args": "{}", "output_preview": "root:x:0:0"},
        ]
        result = SimpleNamespace(new_items=[], _captured_chain=captured)
        chain = chain_from_result(result)
        assert len(chain) == 2
        assert chain[0]["tool"] == "web_fetch_smart"

    def test_prefers_richer_source(self):
        """When new_items extraction yields fewer entries than the captured
        chain, prefer the captured one (it survived dropped chunks)."""
        from kryon.services.investigate_writeback import chain_from_result

        call = SimpleNamespace(raw_item=SimpleNamespace(name="curl", arguments={}))
        captured = [
            {"tool": "a", "args": "", "output_preview": ""},
            {"tool": "b", "args": "", "output_preview": ""},
            {"tool": "c", "args": "", "output_preview": ""},
        ]
        result = SimpleNamespace(new_items=[call], _captured_chain=captured)
        assert len(chain_from_result(result)) == 3

    def test_no_captured_attr_is_safe(self):
        from kryon.services.investigate_writeback import chain_from_result

        assert chain_from_result(SimpleNamespace(new_items=[])) == []


# ---------------------------------------------------------------------------
# _build_profile_from_hints
# ---------------------------------------------------------------------------


class TestProfileBuilder:
    def test_https_url_adds_port_443(self):
        hints = {"urls": ["https://eaula.ing.una.py/"], "keywords": []}
        p = _build_profile_from_hints(hints)
        assert p["host"] == "eaula.ing.una.py"
        assert 443 in p["ports"]

    def test_http_url_adds_port_80(self):
        hints = {"urls": ["http://127.0.0.1:8080/"], "keywords": []}
        p = _build_profile_from_hints(hints)
        assert "127.0.0.1" in p["host"]
        assert 80 in p["ports"]

    def test_tech_extracted_from_keywords(self):
        hints = {"urls": [], "keywords": ["webapp", "moodle", "mysql", "cwe-89"]}
        p = _build_profile_from_hints(hints)
        assert "moodle" in p["tech"]
        assert "mysql" in p["tech"]
        # "webapp" and "cwe-89" are NOT tech identifiers — excluded
        assert "webapp" not in p["tech"]

    def test_empty_hints(self):
        p = _build_profile_from_hints({})
        assert p["tech"] == []
        assert p["ports"] == []
        assert p["host"] == ""


# ---------------------------------------------------------------------------
# write_back_from_investigate — integration
# ---------------------------------------------------------------------------


def _fake_result(tool_calls=2, final_output="Found CWE-79 confirmed in /search"):
    """Build a fake RunResult shape with N tool calls."""
    items = []
    for i in range(tool_calls):
        items.append(
            SimpleNamespace(
                raw_item=SimpleNamespace(
                    name=f"tool_{i}",
                    arguments={"i": i},
                    call_id=f"call_{i}",
                )
            )
        )
        items.append(
            SimpleNamespace(
                raw_item=SimpleNamespace(
                    output=f"output_{i}",
                    call_id=f"call_{i}",
                )
            )
        )
    return SimpleNamespace(new_items=items, final_output=final_output)


class TestWriteBackIntegration:
    def test_persists_when_chain_sufficient(self):
        fake_result = _fake_result(tool_calls=3)
        captured = []

        def _fake_add(exp):
            captured.append(exp)
            return "exp_test123"

        with patch("kryon.learning.experiences.add_experience", side_effect=_fake_add):
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("KRYON_NO_WRITEBACK", None)
                exp_id = write_back_from_investigate(
                    "audita https://x.com",
                    {"mode": "web_audit", "urls": ["https://x.com"], "keywords": ["webapp"]},
                    fake_result,
                    auto_synth=False,
                )
        assert exp_id == "exp_test123"
        assert len(captured) == 1
        assert captured[0]["outcome"] == "success"
        assert len(captured[0]["chain"]) == 3
        assert captured[0]["source"] == "investigate"

    def test_skipped_when_chain_too_short(self):
        # Only 1 tool call — should skip
        fake_result = _fake_result(tool_calls=1)
        with patch("kryon.learning.experiences.add_experience") as mock_add:
            exp_id = write_back_from_investigate(
                "x",
                {"mode": "general", "keywords": []},
                fake_result,
                auto_synth=False,
            )
        assert exp_id is None
        mock_add.assert_not_called()

    def test_no_writeback_env_disables(self):
        fake_result = _fake_result(tool_calls=3)
        with patch.dict(os.environ, {"KRYON_NO_WRITEBACK": "1"}):
            with patch("kryon.learning.experiences.add_experience") as mock_add:
                exp_id = write_back_from_investigate(
                    "x",
                    {"mode": "general", "keywords": []},
                    fake_result,
                    auto_synth=False,
                )
        assert exp_id is None
        mock_add.assert_not_called()

    def test_learning_unavailable_returns_none(self):
        fake_result = _fake_result(tool_calls=3)
        # Patch the import target — when add_experience raises ImportError-like
        # we return None gracefully.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("KRYON_NO_WRITEBACK", None)
            # Simulate import failure by patching the module
            with patch("kryon.learning.experiences.add_experience", side_effect=RuntimeError("ChromaDB unavailable")):
                exp_id = write_back_from_investigate(
                    "x",
                    {"mode": "general", "keywords": []},
                    fake_result,
                    auto_synth=False,
                )
        assert exp_id is None

    def test_outcome_fail_blocks_auto_synth(self):
        # When outcome=fail, auto_synth should NOT be invoked.
        fake_result = _fake_result(
            tool_calls=3,
            final_output="no se pudo identificar nada útil",
        )
        with patch("kryon.learning.experiences.add_experience", return_value="exp_x"):
            with patch("kryon.learning.draft_writer.try_synthesize_and_persist") as mock_synth:
                with patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("KRYON_NO_WRITEBACK", None)
                    exp_id = write_back_from_investigate("x", {}, fake_result, auto_synth=True)
        assert exp_id == "exp_x"
        mock_synth.assert_not_called()


# ---------------------------------------------------------------------------
# Banca-safe source-level check
# ---------------------------------------------------------------------------


class TestBancaSafe:
    SRC = Path(__file__).resolve().parents[2] / "src" / "kryon" / "services" / "investigate_writeback.py"

    def test_no_network_calls(self):
        text = self.SRC.read_text(encoding="utf-8")
        assert "urllib.request" not in text
        assert "requests." not in text
        assert "httpx" not in text

    def test_no_subprocess(self):
        text = self.SRC.read_text(encoding="utf-8")
        assert "subprocess" not in text
        assert "os.system" not in text
