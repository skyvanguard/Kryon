"""GAP-7: las tools de validación/explotación de alto valor sobreviven el cap.

Antes carecían de marker en `_HIGH_VALUE_TOOL_MARKERS` → rank 1 → el cap las dropeaba
(incluso con RED_TEAM, donde SÍ están en el registry), dejando al modelo con recon pero
sin con qué llevar un finding a impacto. Con los markers agregados son rank 0 (sobreviven).
"""

from __future__ import annotations

from kryon.skills.tool_budget import _tool_relevance_rank


def test_exploit_validation_tools_are_high_value():
    for t in [
        "validate_rce",
        "validate_auth_bypass",
        "detect_bola",
        "exploit_file_upload",
        "exploit_java_deserialization",
        "sqlmap_dump_database",
        "shell_session_start",
    ]:
        assert _tool_relevance_rank(t) == 0, f"{t} debe sobrevivir el cap (rank 0)"


def test_generic_tools_stay_low_rank():
    for t in ["run_command", "web_fetch_smart", "execute_code", "request_skill", "tool_search"]:
        assert _tool_relevance_rank(t) == 1, f"{t} debe seguir rank 1 (generico)"
