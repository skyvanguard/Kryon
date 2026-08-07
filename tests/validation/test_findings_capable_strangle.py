"""Findings gates no estrangulan el trabajo del modelo capable (A1 grounding, A2 dedup).

Barrido de findings-gates:
- A1: `apply_grounding` capeaba a 0.3 TODO finding del LLM sin cita literal
  (call_id/step-N/"según output de X"), auto-on para reasoning-class, SIN exención
  capable — el "over-filter" que el propio docstring de is_capable_model reconoce.
  Fix: capable salta el cap (el finding conserva needs_verification del default LLM,
  así que no promueve nada sin verificar; solo evita el castigo de 0.3).
- A2: findings del LLM DISTINTOS con rule_id default 'agent-finding' en el mismo host
  colapsaban en dedup (clave sin discriminador). Fix: discriminar por message.
"""

from __future__ import annotations

import pytest

from kryon.services.finding_dedup import dedup_key
from kryon.validation.grounding import apply_grounding


class _F:
    def __init__(self, msg, host="h1", rid="agent-finding", url="", conf=0.8):
        self.message = msg
        self.host = host
        self.rule_id = rid
        self.url = url
        self.confidence = conf
        self.needs_verification = False


def test_grounding_penalises_4b_ungrounded(monkeypatch):
    monkeypatch.setenv("KRYON_REQUIRE_GROUNDING", "true")
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "false")
    f = _F("RCE confirmado via jndi, el listener recibio callback")  # sin keyword de cita
    assert apply_grounding([f]) == 1
    assert f.confidence == pytest.approx(0.3)


def test_grounding_exempts_capable(monkeypatch):
    monkeypatch.setenv("KRYON_REQUIRE_GROUNDING", "true")
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    f = _F("RCE confirmado via jndi, el listener recibio callback")
    assert apply_grounding([f]) == 0  # capable no es sobre-filtrado
    assert f.confidence == pytest.approx(0.8)


def test_dedup_distinct_agent_findings_survive():
    a = _F("IDOR en /api/orders")
    b = _F("Stored XSS en /profile/bio")
    assert dedup_key(a) != dedup_key(b)  # antes colapsaban en uno


def test_dedup_identical_agent_findings_merge():
    a = _F("IDOR en /api/orders")
    c = _F("IDOR en /api/orders")
    assert dedup_key(a) == dedup_key(c)


def test_dedup_specific_rule_id_still_dedups():
    d = _F("instancia 1", rid="probe_xss_reflected")
    e = _F("instancia 2", rid="probe_xss_reflected")
    assert dedup_key(d) == dedup_key(e)  # un rule_id real sigue deduplicando por id
