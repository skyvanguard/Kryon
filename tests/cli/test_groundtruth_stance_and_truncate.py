"""Ejes 9 y 10: dos puntos que aplicaban el régimen 4B al capable.

Eje 9 — ground-truth STANCE en `kryon investigate`: `_format_findings_for_prompt`
hard-codeaba el stance 4B ("NO los repitas / reconocelos / validá si dudás"),
mientras su hermano `format_engine_ground_truth` (REPL/engage) ya es capable-aware.
`investigate` era el path que quedaba en el techo tight. Fix: branch capable con
el head-start ("explotá cada uno / re-escaneá / extendé hacia impacto").

Eje 10 — `truncate_output` (SDK executor): cap fijo 10K sobre el tool-result que
el modelo ve en la historia, re-cortando lo que el output-cap de services ya
preservó para el capable (50K). Fix: 40K capable / 10K 4B, head/tail proporcional.
"""

from __future__ import annotations

from types import SimpleNamespace

from kryon.cli.investigate import _format_findings_for_prompt
from kryon.sdk.agents._run_impl import truncate_output


def _finding(**kw):
    base = dict(cwe="CWE-89", rule_id="error_based_probe", severity="high", host="t:3000", message="SQLi", evidence="500")
    base.update(kw)
    return SimpleNamespace(**base)


# --- Eje 9: stance ---
def test_groundtruth_capable_head_start_stance(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    out = _format_findings_for_prompt([_finding()])
    assert "HEAD START" in out
    assert "explotá cada uno" in out
    assert "re-escaneá" in out
    # sin la task-list restrictiva del 4B
    assert "Validar/contextualizar cada uno con un curl adicional si dudás" not in out
    assert "NO los repitas en tu resumen final" not in out


def test_groundtruth_4b_keeps_tight_stance(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "false")
    out = _format_findings_for_prompt([_finding()])
    assert "NO los repitas en tu resumen final" in out
    assert "Validar/contextualizar cada uno con un curl adicional si dudás" in out
    assert "HEAD START" not in out


def test_groundtruth_empty_is_blank():
    assert _format_findings_for_prompt([]) == ""


# --- Eje 10: truncate_output ---
def test_truncate_capable_larger_window(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    big = "X" * 30000  # entre 10K (4B) y 40K (capable)
    out = truncate_output(big)
    assert "TRUNCATED" not in out  # 30K <= 40K capable → intacto
    assert out == big


def test_truncate_4b_tight_window(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "false")
    big = "X" * 30000
    out = truncate_output(big)
    assert "TRUNCATED" in out  # 30K > 10K 4B → cortado
    # head+tail proporcional a 10K → ~5000+5000
    assert out.count("X") == 10000


def test_truncate_explicit_max_length_wins(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    big = "B" * 5000
    out = truncate_output(big, max_length=1000)  # override explícito gana sobre capable
    assert "TRUNCATED" in out
    assert out.count("B") == 1000


def test_truncate_capable_still_caps_huge(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    huge = "Z" * 100000  # > 40K capable
    out = truncate_output(huge)
    assert "TRUNCATED" in out
    assert out.count("Z") == 40000  # 20K head + 20K tail
