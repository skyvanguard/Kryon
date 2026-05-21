"""F203.D — `request_skill` tool: in-turn skill discovery + lightweight draft.

Cuando el agent no sabe cómo proceder ("no tengo metodología para X"), puede
invocar esta tool en vez de quedarse atascado. El comportamiento:

1. **Match contra skills existentes** (SkillLoader): si una skill matchea el
   topic con suficiente signal (keyword whole-word + priority bump), retorna
   el body de la skill (truncado a 4000 chars) → el agent usa esa metodología.

2. **Si no match**: retorna un mini-playbook genérico con heurísticas básicas
   (grep/find/curl/duckduckgo_search/query_knowledge_base) + lista de las 3
   skills más cercanas (semánticamente) para que el agent considere si
   adaptarlas.

3. **Telemetría**: cada call queda en `selection_telemetry` con `request=topic`
   → permite analizar post-engagement qué gaps de skills aparecieron y
   priorizar synthesis manual.

Banca-safe:
- NO sintetiza ni promueve skills automáticamente a disco. Solo retorna
  texto al agent. La promoción real se hace via `/skill auto` (F1 pipeline
  existente).
- NO toca network ni filesystem fuera del read del SkillLoader.
- read-only by design.
"""

from __future__ import annotations

import logging
from typing import Any

from kryon.sdk.agents import function_tool

logger = logging.getLogger(__name__)


# Cap on the body slice returned to the agent (LLM context budget).
_BODY_MAX_CHARS = 4000

# Lightweight fallback playbook when no skill matches.
_GENERIC_FALLBACK = """\
## Generic methodology (no specific skill matched)

No existe una skill específica para tu topic. Heurísticas a aplicar:

1. **Recon inicial**:
   - `web_fetch_smart(url)` si hay HTTP target → títulos, meta tags, links.
   - `run_command "grep -rn KEYWORD ./path"` si auditás código local.
   - `query_knowledge_base("topic")` → busca en el RAG si hay info previa.

2. **Búsqueda externa**:
   - `duckduckgo_search("topic vulnerability CVE")` → lleva al menos top 5
     resultados y revisar exploit-db.com / nist.gov entries.
   - `search_vulnerabilities(technology=X, version=Y)` si tenés un stack
     fingerprinted.

3. **Análisis**:
   - Identificá el `sink pattern` típico de esta familia (ej: ejecución de
     comandos shell = CWE-78, deserialize untrusted = CWE-502, etc).
   - Cross-validar con al menos 2 fuentes antes de emitir finding.

4. **Si seguís sin progreso** después de 3-4 turns más:
   - Emití el resumen final con lo que SÍ sabés.
   - Documentá el gap: este topic no tiene playbook → operator debería
     crear uno post-engagement con `kryon learn auto-promote`.

NO repitas la misma tool 2+ veces con args idénticos. Si una tool no devuelve
signal, cambiá de approach (otra tool, otros args, o emití findings parciales).
"""


def _format_skill_body(skill: Any) -> str:
    """Return a slice of the skill body suitable for the agent context."""
    body = getattr(skill, "body", "") or getattr(skill, "content", "") or ""
    body = body.strip()
    if len(body) > _BODY_MAX_CHARS:
        body = body[:_BODY_MAX_CHARS] + "\n\n... (truncated)"
    name = getattr(skill, "name", "unknown")
    desc = getattr(skill, "description", "") or ""
    return (
        f"## Skill: `{name}`\n"
        f"{desc}\n\n"
        f"---\n\n{body}\n"
    )


def _log_telemetry(topic: str, matched: bool, returned_skill: str | None) -> None:
    """Best-effort telemetry. Failures here NEVER kill the tool."""
    try:
        from kryon.learning.selection_telemetry import log_selection

        log_selection(
            user_msg=f"[request_skill] {topic}",
            ranking_mode="request_skill",
            candidates=[],
            selected=[returned_skill] if returned_skill else [],
        )
    except Exception:  # noqa: BLE001 — telemetry must never raise
        logger.debug("telemetry skipped for request_skill('%s')", topic)


@function_tool
def request_skill(topic: str) -> str:
    """F203.D — Ask for a methodology playbook on-demand.

    Use when you don't know how to proceed with the current investigation
    topic. Returns either an existing matching skill body, or a generic
    fallback playbook with heuristics.

    DO NOT use as a substitute for actually running tools — this returns
    guidance, you still need to execute the methodology.

    Args:
        topic: Free-text description of what you need a skill for.
               Examples: "audit a Moodle instance", "find SSRF in nodejs",
               "analyze a docker registry", "PCI-DSS req 8 password policy".

    Returns:
        Markdown text: either an existing skill body, or generic fallback +
        list of closest existing skills.
    """
    topic = (topic or "").strip()
    if not topic:
        return "ERROR: empty topic. Provide a description of what skill you need."

    try:
        from kryon.skills.loader import SkillLoader
    except ImportError as e:
        logger.warning("SkillLoader unavailable: %s", e)
        _log_telemetry(topic, matched=False, returned_skill=None)
        return _GENERIC_FALLBACK

    loader = SkillLoader()
    matched = loader.match(profile={}, user_msg=topic)

    if matched:
        # Take the highest-priority match (loader already sorted).
        top = matched[0]
        _log_telemetry(topic, matched=True, returned_skill=getattr(top, "name", None))

        # Also list other near-matches so the agent knows what else is available.
        other_names = [
            getattr(s, "name", "?")
            for s in matched[1:6]
        ]
        other_block = (
            f"\n\n**Other related skills available**: {', '.join(other_names)}\n"
            if other_names
            else ""
        )
        return _format_skill_body(top) + other_block

    # No match — return generic + 3 closest by name similarity.
    _log_telemetry(topic, matched=False, returned_skill=None)
    all_skills = loader.scan()
    topic_lower = topic.lower()
    # Cheap "closest" heuristic: skills whose name shares a token with topic.
    tokens = {t for t in topic_lower.split() if len(t) > 3}
    scored: list[tuple[int, str]] = []
    for s in all_skills:
        name = getattr(s, "name", "").lower()
        name_tokens = set(name.replace("-", " ").split())
        overlap = len(tokens & name_tokens)
        if overlap > 0:
            scored.append((overlap, getattr(s, "name", "")))
    scored.sort(key=lambda x: -x[0])
    near_misses = [n for _, n in scored[:3]]

    suggestion = (
        f"\n\n**Closest existing skills (by name similarity)**: "
        f"{', '.join(near_misses) if near_misses else '(none with name overlap)'}\n"
        f"Consider whether one of these is adaptable to your topic, or "
        f"continue with the generic methodology above.\n"
    )
    return _GENERIC_FALLBACK + suggestion


__all__ = ["request_skill"]
