"""Ejes 11-14: budgets de selección + stance de engage/playbooks capable-aware.

- Eje 11: skill-loader token budget (6000) recortaba playbooks ofensivos al régimen
  4B; capable lo eleva (gemelo de _effective_max_tools).
- Eje 13: los preambles de `kryon engage` (_phase_preamble) no tenían branch capable —
  fallback pasivo para exploitation/post_exploit + contrato "emit array → []". Ahora
  capable recibe el stance ofensivo y no se le empuja a cerrar con [].
- Eje 12/14 (playbooks .md): la stop-rule "4 turns → operator-input" (15 skills) y el
  "settle a los 5 turns" de vuln-hunter se reencuadraron como off-ramp del 4B, no techo.
"""

from __future__ import annotations

from pathlib import Path

from kryon.cli.engage import _phase_preamble
from kryon.skills.loader import _effective_skill_budget

_PLAYBOOKS = Path(__file__).resolve().parents[2] / "src" / "kryon" / "skills" / "playbooks"


# --- Eje 11: skill budget ---
def test_skill_budget_capable_lifted(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    monkeypatch.delenv("KRYON_SKILL_BUDGET_TOKENS", raising=False)
    assert _effective_skill_budget(6000) == 20000


def test_skill_budget_4b_tight(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "false")
    monkeypatch.delenv("KRYON_SKILL_BUDGET_TOKENS", raising=False)
    assert _effective_skill_budget(6000) == 6000


def test_skill_budget_override_wins(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    monkeypatch.setenv("KRYON_SKILL_BUDGET_TOKENS", "9000")
    assert _effective_skill_budget(6000) == 9000


def test_skill_budget_capable_never_lowers(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    monkeypatch.delenv("KRYON_SKILL_BUDGET_TOKENS", raising=False)
    # si el default ya es > 20000, no lo baja
    assert _effective_skill_budget(30000) == 30000


# --- Eje 13: engage _phase_preamble ---
def _preamble(monkeypatch, capable: bool, phase: str = "exploitation") -> str:
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true" if capable else "false")
    return _phase_preamble(phase, target="http://t:3000", scope="t", families=[], findings=[])


def test_engage_exploitation_capable_offensive_stance(monkeypatch):
    p = _preamble(monkeypatch, True, "exploitation")  # cae al fallback (sin key propia)
    assert "kill-chain para CONDUCIR" in p
    assert "encadená" in p
    # el contrato capable NO empuja a cerrar con []
    assert "NO cierres el turno con []" in p
    assert "Emit [] if there are" not in p


def test_engage_exploitation_4b_passive_fallback(monkeypatch):
    p = _preamble(monkeypatch, False, "exploitation")
    assert "Investigate and emit structured JSON" in p
    assert "Emit [] if there are" in p  # contrato clásico F150
    assert "kill-chain para CONDUCIR" not in p


def test_engage_known_phase_capable_contract(monkeypatch):
    # una fase con key propia (recon): el body es el mismo, pero el CONTRATO cambia por régimen
    p = _preamble(monkeypatch, True, "recon")
    assert "NO cierres el turno con []" in p
    # la citación F152 se conserva para ambos
    assert "F152" in p


def test_engage_known_phase_4b_contract(monkeypatch):
    p = _preamble(monkeypatch, False, "recon")
    assert "Emit [] if there are" in p
    assert "F152" in p


# --- Eje 12/14: playbooks reencuadrados ---
def test_active_playbooks_no_longer_hard_stop_at_4_turns():
    hits = [
        f.name
        for f in _PLAYBOOKS.glob("*.md")
        if "operator-input request en lugar de resumen prematuro" in f.read_text(encoding="utf-8")
    ]
    assert hits == []  # ningún playbook conserva el corte tight


def test_active_playbooks_reframed_as_offramp():
    reframed = [
        f.name
        for f in _PLAYBOOKS.glob("*.md")
        if "off-ramp del modelo local chico" in f.read_text(encoding="utf-8")
    ]
    # 14 web-pentest-*-active + post-foothold-active
    assert len(reframed) >= 15


def test_vuln_hunter_settle_reframed():
    body = (_PLAYBOOKS / "vuln-hunter.md").read_text(encoding="utf-8")
    assert "0 findings tras 5 turns de loop" not in body
    assert "NO reemplaza perseguir el P1" in body
