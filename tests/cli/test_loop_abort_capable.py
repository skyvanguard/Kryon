"""Axis-7: los cortes por bucle no deben estrangular al modelo capable.

Tres mecanismos cortan el loop cuando el modelo repite:
- `command_dedup.check_repeat` suprime el N-ésimo comando idéntico stateless.
- El StuckDetector del SDK (ver test_harness_capable_gates) aborta el run.
- El stuck-loop abort del reflective_runner (`consecutive_stuck_count >=
  _stuck_abort_trigger`) es RESULT-INDEPENDIENTE (matchea solo tool+args_hash),
  el más agresivo. Un capable que re-emite un probe con intención mientras
  encadena no debe ser cortado con el mismo gatillo tight que el 4B.

Todos deben aflojar bajo is_capable_model() y mantener el bound tight sin él.
"""

from __future__ import annotations

import importlib

import kryon.tools.common.command_dedup as cd


def _fresh_dedup():
    # el estado es per-process global; recargar limpia el contador entre casos
    importlib.reload(cd)
    return cd


# --- command_dedup: suppress_at 3 (4B) vs 5 (capable) ---
def test_command_dedup_4b_suppresses_at_third(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "false")
    m = _fresh_dedup()
    cmd = "curl -s http://t/x?id=1"
    assert m.check_repeat(cmd) is None  # 1ª
    assert m.check_repeat(cmd) is None  # 2ª
    assert m.check_repeat(cmd) is not None  # 3ª suprimida


def test_command_dedup_capable_gets_more_grace(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    m = _fresh_dedup()
    cmd = "curl -s http://t/x?id=1"
    assert m.check_repeat(cmd) is None  # 1ª
    assert m.check_repeat(cmd) is None  # 2ª
    assert m.check_repeat(cmd) is None  # 3ª — todavía ejecuta (grace ampliado)
    assert m.check_repeat(cmd) is None  # 4ª
    assert m.check_repeat(cmd) is not None  # 5ª suprimida


# --- stuck-loop abort trigger capable-aware ---
def test_stuck_abort_trigger_widens_for_capable(monkeypatch):
    from kryon.util.env import is_capable_model

    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    assert is_capable_model() is True
    # el runner computa _stuck_abort_trigger = _DEFAULT_STUCK_ABORT_TRIGGER + 2 para capable.
    from kryon.cli.reflective_runner import _DEFAULT_STUCK_ABORT_TRIGGER

    capable_trigger = _DEFAULT_STUCK_ABORT_TRIGGER + 2
    assert capable_trigger > _DEFAULT_STUCK_ABORT_TRIGGER
    assert capable_trigger >= 5  # da margen para re-emitir con intención al encadenar


def test_stuck_abort_trigger_tight_for_4b(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "false")
    from kryon.cli.reflective_runner import _DEFAULT_STUCK_ABORT_TRIGGER

    # el 4B conserva el gatillo tight (loopea una URL ~48×)
    assert _DEFAULT_STUCK_ABORT_TRIGGER == 3
