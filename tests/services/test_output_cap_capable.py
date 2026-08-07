"""Los caps de output escalan a la ventana para un modelo capable (fix DSpark 64K).

El diseño era window-relative BINARIO (>=500K → large 50000/50000/×8, else → 4B-tight
5000/1000/×1). Con DSpark la ventana del V4 bajó de 512K a 64K (<500K) → caía en el
régimen agresivo y perdía la evidencia (p.ej. un sqlmap --dump) que el reasoner necesita
para encadenar SQLi→login-admin. Fix: `capable OR >=500K` escala el cap a `window//4`
(con piso/techo); un 4B débil (aún con ventana 128K) sigue agresivo (banca-safe) porque
la CAPACIDAD, no el tamaño de ventana, levanta el cap.
"""

from __future__ import annotations

from kryon.config.settings import resolve_context_budget
from kryon.services.micro_compact import resolve_micro_compact_budget
from kryon.services.tool_output_cap import resolve_tool_result_cap


def _capable(monkeypatch, on: bool) -> None:
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true" if on else "false")


def test_capable_64k_scales_tool_cap(monkeypatch):
    _capable(monkeypatch, True)
    assert resolve_tool_result_cap(64_000) == 16_000  # sin el fix era 5000


def test_capable_64k_scales_micro_budget_consistently(monkeypatch):
    _capable(monkeypatch, True)
    # igual al tool cap → layer-2 no re-trunca lo que layer-1 preservó
    assert resolve_micro_compact_budget(64_000) == 16_000


def test_capable_64k_lifts_context_budget(monkeypatch):
    _capable(monkeypatch, True)
    assert resolve_context_budget(500, 64_000) == 4_000


def test_capable_respects_floor_and_ceiling(monkeypatch):
    _capable(monkeypatch, True)
    assert resolve_tool_result_cap(8_000) == 5_000  # piso (4B-tight)
    assert resolve_tool_result_cap(1_000_000) == 50_000  # techo (V4-1M)


def test_non_capable_large_window_stays_aggressive(monkeypatch):
    # banca-safe: un 4B débil con ventana 128K NO obtiene caps grandes
    _capable(monkeypatch, False)
    assert resolve_tool_result_cap(128_000) == 5_000
    assert resolve_micro_compact_budget(128_000) == 1_000
    assert resolve_context_budget(500, 128_000) == 500


def test_override_wins_over_capable(monkeypatch):
    _capable(monkeypatch, True)
    assert resolve_tool_result_cap(64_000, override="9000") == 9_000
    assert resolve_micro_compact_budget(64_000, override="7000") == 7_000
