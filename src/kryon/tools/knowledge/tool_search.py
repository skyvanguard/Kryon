"""F203.E — `tool_search` autonomous discovery.

Equivalente al `ToolSearch` que yo (Claude) uso: cuando el agent no sabe
qué tool aplicar a un sub-problema, invoca `tool_search(query)` y obtiene
una lista ranked de tools relevantes del inventario.

A diferencia de `request_skill` (que retorna metodología textual),
`tool_search` retorna **tool names + signatures** que el agent puede
invocar directamente en el siguiente turn.

Diseño:
- Inventario fijo: importamos los toolsets conocidos (CORE + RAG_FULL +
  AI + MEMORY + algunos OSINT + web) lazy para evitar imports circulares.
- Ranking semántico simple sin embeddings:
    * whole-word match en `name` → peso 3
    * whole-word match en `description` → peso 2
    * substring match en `description` → peso 1
- Retorna top 8 con name + description (200 chars) + params schema preview.

Banca-safe: read-only por design. Solo introspecta metadatos de tools,
no las invoca ni toca network/filesystem.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from kryon.sdk.agents import function_tool

logger = logging.getLogger(__name__)


_MAX_RESULTS = 8
_DESC_PREVIEW_CHARS = 200


def _whole_word(needle: str, haystack: str) -> bool:
    """Whole-word match (same semantic as SkillLoader._keyword_matches)."""
    if not needle:
        return False
    pattern = r"\b" + re.escape(needle.lower()) + r"\b"
    return re.search(pattern, haystack.lower()) is not None


def _gather_inventory() -> list[Any]:
    """Lazy import of all known toolsets. Returns deduped flat list of
    FunctionTool objects. Failures on any single toolset are non-fatal
    (we keep going with whatever loaded)."""
    inventory: list[Any] = []
    seen_names: set[str] = set()

    def _add(tools_iter: Any) -> None:
        for t in tools_iter or ():
            name = getattr(t, "name", None)
            if not name or name in seen_names:
                continue
            inventory.append(t)
            seen_names.add(name)

    # Core toolsets — RAG/MEMORY/AI are common to every agent.
    try:
        from kryon.agents.toolsets import (
            AI_TOOLS,
            CORE_TOOLS,
            RAG_TOOLS_FULL,
        )

        _add(CORE_TOOLS)
        _add(RAG_TOOLS_FULL)
        _add(AI_TOOLS)
    except Exception as e:  # noqa: BLE001
        logger.debug("toolsets core import failed: %s", e)

    # Web tools (F203.B + duckduckgo + others)
    try:
        from kryon.tools.web.duckduckgo_search import duckduckgo_search
        from kryon.tools.web.web_fetch_smart import web_fetch_smart

        _add([web_fetch_smart, duckduckgo_search])
    except Exception as e:  # noqa: BLE001
        logger.debug("web tools import failed: %s", e)

    # OSINT (some require API keys; we still surface them so agent knows
    # they exist — invocation will return graceful error if unconfigured).
    try:
        from kryon.tools.osint.shodan_cli import shodan_host
        from kryon.tools.osint.theharvester import theharvester_search
        from kryon.tools.osint.threat_intel import (
            censys_search,
            virustotal_search,
        )

        _add([theharvester_search, shodan_host, virustotal_search, censys_search])
    except Exception as e:  # noqa: BLE001
        logger.debug("osint tools import failed: %s", e)

    # Common active-recon tools (nmap, nuclei, sqlmap wrappers)
    try:
        from kryon.tools.reconnaissance.nmap import nmap_scan

        _add([nmap_scan])
    except Exception as e:  # noqa: BLE001
        logger.debug("nmap tool import failed: %s", e)

    try:
        from kryon.tools.web.nuclei import nuclei_scan

        _add([nuclei_scan])
    except Exception as e:  # noqa: BLE001
        logger.debug("nuclei tool import failed: %s", e)

    return inventory


def _score_tool(tool: Any, query_lower: str, query_tokens: set[str]) -> int:
    """Return a relevance score (higher = more relevant). Zero = no match."""
    name_raw = (getattr(tool, "name", "") or "").lower()
    # Snake/kebab-case tool names (`nmap_scan`, `web-fetch-smart`) don't
    # whole-word match on `\b` because `_` is `\w`. Normalize separators
    # to spaces so tokenization works for tool names too.
    name = name_raw.replace("_", " ").replace("-", " ")
    desc = (getattr(tool, "description", "") or "").lower()

    score = 0
    # Whole-word in name = strong signal (peso 3)
    for tok in query_tokens:
        if len(tok) >= 3 and _whole_word(tok, name):
            score += 3
    # Whole-word in description = moderate (peso 2)
    for tok in query_tokens:
        if len(tok) >= 3 and _whole_word(tok, desc):
            score += 2
    # Substring in description = weak (peso 1)
    if score == 0 and query_lower in desc:
        score += 1
    return score


def _format_tool_entry(tool: Any) -> str:
    """Render one tool as markdown bullet."""
    name = getattr(tool, "name", "unknown")
    desc = (getattr(tool, "description", "") or "").strip()
    desc_preview = desc[:_DESC_PREVIEW_CHARS]
    if len(desc) > _DESC_PREVIEW_CHARS:
        desc_preview += "..."

    # Param preview from JSON schema.
    schema = getattr(tool, "params_json_schema", None) or {}
    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    if props:
        param_names = list(props.keys())[:6]
        param_block = f"  args: ({', '.join(param_names)})"
    else:
        param_block = "  args: ()"

    return f"- `{name}`\n  {desc_preview}\n{param_block}"


@function_tool
def tool_search(query: str) -> str:
    """F203.E — Discover relevant tools from Kryon's inventory.

    Use when you don't know which tool to invoke for a sub-problem.
    Returns the top relevant tools (by name + description match) with
    their signatures so you can invoke them in the next turn.

    Args:
        query: What you want to accomplish, in free-text. Examples:
               "fetch a webpage and extract links", "search for CVE
               information", "scan a host's open ports", "find similar
               past engagements".

    Returns:
        Markdown listing the top matching tools with names, descriptions,
        and parameter previews. If no good match, suggests next steps
        (request_skill, query_knowledge_base).
    """
    query = (query or "").strip()
    if not query:
        return "ERROR: empty query. Describe what you want to accomplish."

    inventory = _gather_inventory()
    if not inventory:
        return (
            "ERROR: tool inventory empty (import failure). "
            "Fallback: try `request_skill(topic=...)` or "
            "`query_knowledge_base('...')` directly."
        )

    query_lower = query.lower()
    # Tokenize: split on whitespace, keep tokens >=3 chars to avoid noise.
    query_tokens = {t for t in re.split(r"\s+", query_lower) if len(t) >= 3}

    scored: list[tuple[int, Any]] = []
    for t in inventory:
        s = _score_tool(t, query_lower, query_tokens)
        if s > 0:
            scored.append((s, t))

    scored.sort(key=lambda x: -x[0])
    top = scored[:_MAX_RESULTS]

    if not top:
        # No semantic match — list a small default subset so agent has
        # *something* to consider, instead of total silence.
        default_names = ["web_fetch_smart", "duckduckgo_search", "run_command", "query_knowledge_base", "request_skill"]
        defaults = [t for t in inventory if getattr(t, "name", "") in default_names]
        if not defaults:
            return (
                f"No tools matched query '{query}'. "
                "Try a different query, or invoke `request_skill(topic='...')` "
                "for methodology guidance instead."
            )
        suggestions = "\n".join(_format_tool_entry(t) for t in defaults)
        return (
            f"No specific match for query '{query}'. "
            f"Default tools you might consider:\n\n{suggestions}\n\n"
            f"Or invoke `request_skill(topic='{query}')` for methodology."
        )

    entries = "\n".join(_format_tool_entry(t) for s, t in top)
    return (
        f"## Top {len(top)} tools matching '{query}'\n\n"
        f"{entries}\n\n"
        f"_Invoke any tool above directly in your next turn._"
    )


__all__ = ["tool_search"]
