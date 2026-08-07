"""Los prompts no educan al modelo capable a ser PASIVO (narrar) en vez de EJECUTOR.

Barrido de prompts-pasivos: el codebase ya gatea el tono por is_capable_model() en
engine_stance/investigate-stop-rule/imperative-suffix/stall/premature, PERO los cuerpos
de los playbooks .md (inyectados verbatim) y las 5 preguntas de reflexión quedaron fuera.
- A1 web-pentest.md: "Report and STOP / run_web_pentest is TERMINAL" → reencuadrado a
  "chain toward impact según tu régimen" (el código _deterministic_terminal_close cierra
  el turno del 4B; el .md no debe duplicar la orden absoluta).
- A2 recon-scout.md (skill DEFAULT): STOP al confirmar la vuln → bifurcado (ofensivo
  encadena a impacto; recon/banca-safe confirma sin explotar).
- A3 reflective_runner 5-preguntas: Q5 "¿PARAR?→resumen" → capable reencuadra a "próximo
  eslabón / ¿lograste impacto?"; el 4B conserva el off-ramp.
- A4 investigate "A verificar": para capable reservada a lo NO-ejecutable, no a "no lo intenté".
"""

from __future__ import annotations

from pathlib import Path

from kryon.cli.investigate import _build_investigate_prompt
from kryon.cli.reflective_runner import _build_reflection_prompt

_PLAYBOOKS = Path(__file__).resolve().parents[2] / "src" / "kryon" / "skills" / "playbooks"


# --- A1/A2: los .md ya no ordenan STOP pasivo ---
def test_web_pentest_md_no_longer_orders_terminal_stop():
    body = (_PLAYBOOKS / "web-pentest.md").read_text(encoding="utf-8")
    assert "STOP — do not call another tool" not in body
    assert "TERMINAL action" not in body
    assert "CHAIN toward impact" in body


def test_recon_scout_md_stops_on_impact_not_confirmation():
    body = (_PLAYBOOKS / "recon-scout.md").read_text(encoding="utf-8")
    # el "confirmar el vector NO es parar" debe estar presente para el modo ofensivo
    assert "confirmar el vector NO es parar" in body
    assert "IMPACTO real" in body


# --- A3: las 5 preguntas de reflexión ---
def _reflect(monkeypatch, capable: bool) -> str:
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true" if capable else "false")
    return _build_reflection_prompt(
        turns_used=4, total_turns_cap=30, tool_history=[], last_output_summary="", stuck_record=None
    )


def test_reflection_capable_reframes_toward_impact(monkeypatch):
    p = _reflect(monkeypatch, True)
    assert "impacto real" in p and "próximo eslabón" in p
    assert "¿Debería **PARAR**" not in p  # sin el off-ramp recurrente


def test_reflection_4b_keeps_stop_offramp(monkeypatch):
    p = _reflect(monkeypatch, False)
    assert "¿Debería **PARAR**" in p


# --- A4: la sección "A verificar" de investigate ---
def _invest(monkeypatch, capable: bool) -> str:
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true" if capable else "false")
    return _build_investigate_prompt("audita https://x", {}, True)


def test_investigate_a_verificar_capable_scoped_to_non_executable(monkeypatch):
    p = _invest(monkeypatch, True)
    assert "SOLO para lo que NO PODÉS ejecutar" in p


def test_investigate_a_verificar_4b_plain(monkeypatch):
    p = _invest(monkeypatch, False)
    assert "SOLO para lo que NO PODÉS ejecutar" not in p
