"""
Tool budget manager — select which tools to register on the unified agent
based on active skills. Caps at max_tools to keep schema tokens under control.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# These tools are ALWAYS included regardless of skill selection
ALWAYS_INCLUDE = {
    "run_command",
    "execute_code",
    "nmap",
    "recall_similar_experiences",
    "query_knowledge_base",
    "search_vulnerabilities",
    "add_to_memory_semantic",
    "query_memory",
}


def build_tool_registry() -> dict[str, Any]:
    """Import ALL tools from toolsets and index them by name.
    Returns dict[tool_name, Tool object].
    """
    registry: dict[str, Any] = {}

    # Import all toolsets
    from kryon.agents.toolsets import (
        AI_TOOLS,
        CORE_TOOLS,
        MEMORY_TOOLS,
        RAG_TOOLS_FULL,
    )

    for tool in [*CORE_TOOLS, *RAG_TOOLS_FULL, *AI_TOOLS, *MEMORY_TOOLS]:
        if hasattr(tool, "name"):
            registry[tool.name] = tool

    # Import domain-specific tools with graceful fallback
    _optional_imports = [
        ("kryon.agents.toolsets", "APPSEC_TOOLS"),
        ("kryon.agents.toolsets", "VALIDATION_TOOLS"),
        ("kryon.agents.toolsets", "CREDENTIAL_TOOLS"),
        ("kryon.agents.toolsets", "LLM_SECURITY_TOOLS"),
        ("kryon.agents.toolsets", "DISCOVERY_TOOLS"),
    ]
    for module_path, attr in _optional_imports:
        try:
            import importlib

            mod = importlib.import_module(module_path)
            tools = getattr(mod, attr, [])
            for tool in tools:
                if hasattr(tool, "name"):
                    registry[tool.name] = tool
        except Exception:
            pass

    # Import individual tools that aren't in shared toolsets
    _extra_tools = [
        "kryon.tools.reconnaissance.nmap",
        "kryon.tools.reconnaissance.whatweb",
        "kryon.tools.web.nuclei",
        "kryon.tools.web.duckduckgo_search",
        # F203.B — smart HTTP GET with HTML→markdown extraction
        "kryon.tools.web.web_fetch_smart",
        # F197 — IoT / DVR fingerprinting (Hikvision / Dahua / ONVIF)
        "kryon.tools.iot.dvr_recon",
        "kryon.tools.iot.onvif_probe",
        # F198 — Asterisk / VoIP / SIP recon
        "kryon.tools.voice.asterisk_discover",
        # F200.A — Apache Tomcat recon (version + endpoints + AJP probe)
        "kryon.tools.web.tomcat_recon",
        # Source-code tools — F1 of ZERO_DAY_ROADMAP
        "kryon.tools.code.git_tools",
        "kryon.tools.code.reader",
        "kryon.tools.code.priority",
        "kryon.tools.code.sandbox",
        # Supervisor tools — F3.1 (planner-hunter coordination)
        "kryon.skills.supervisor_tools",
        # CVE corpus RAG — F4.2 (recall_similar_code_pattern)
        "kryon.knowledge.cve_corpus",
        # Semgrep — F5.2.b (industry-standard pattern scanner)
        "kryon.tools.code.semgrep_tool",
        # Structured finding submission — F5.1.d (replaces text-block parsing)
        "kryon.skills.submit_tools",
        # F203.R — DFIR detection/exploit validation tools.
        # Banca-safe: validate_detection es analítico (no fire), exploit_validator
        # respeta el doble gate KRYON_EXPLOIT_FIRE+fire=True; bas_scenarios y
        # attack_simulator solo emiten plans/scenarios, no ejecutan. coverage_scorer
        # mapea findings vs MITRE ATT&CK (analítico). detection_generator emite
        # Sigma/YARA rules (read-only).
        "kryon.tools.validation.detection_validator",
        "kryon.tools.validation.detection_generator",
        "kryon.tools.validation.coverage_scorer",
        "kryon.tools.validation.attack_simulator",
        "kryon.tools.validation.bas_scenarios",
        "kryon.tools.validation.exploit_validator",
    ]
    for mod_path in _extra_tools:
        try:
            import importlib

            mod = importlib.import_module(mod_path)
            for attr_name in dir(mod):
                obj = getattr(mod, attr_name)
                if hasattr(obj, "name") and hasattr(obj, "params_json_schema"):
                    if obj.name not in registry:
                        registry[obj.name] = obj
        except Exception:
            pass

    logger.debug("Tool registry: %d tools indexed", len(registry))
    return registry


def select_tools(
    registry: dict[str, Any],
    skill_tool_names: set[str],
    max_tools: int = 30,
    forbidden_tool_names: set[str] | None = None,
) -> list[Any]:
    """Select tool objects from the registry based on skill requirements.

    Always includes ALWAYS_INCLUDE tools, then adds skill-specific tools.
    If forbidden_tool_names is given, those names are REMOVED from the
    final set even if they're in ALWAYS_INCLUDE — lets individual skills
    veto ambient tools (used by the zero-day-hunter to block
    run_command/execute_code side-channels around run_sandboxed).
    """
    selected_names = set(ALWAYS_INCLUDE)
    selected_names.update(skill_tool_names)
    if forbidden_tool_names:
        selected_names -= set(forbidden_tool_names)

    # Resolve names to tool objects
    tools: list[Any] = []
    missing: list[str] = []
    for name in sorted(selected_names):
        if name in registry:
            tools.append(registry[name])
        else:
            missing.append(name)

    if missing:
        logger.debug("Tools not found in registry: %s", missing)

    # Cap
    if len(tools) > max_tools:
        # Keep ALWAYS_INCLUDE first, then fill from skills
        always = [t for t in tools if t.name in ALWAYS_INCLUDE]
        rest = [t for t in tools if t.name not in ALWAYS_INCLUDE]
        tools = always + rest[: max_tools - len(always)]

    return tools


def select_tools_itr(
    registry: dict[str, Any],
    user_query: str,
    *,
    max_tools: int = 30,
    forbidden_tool_names: set[str] | None = None,
    embedder: Any = None,
    index: Any = None,
) -> list[Any] | None:
    """F84.7 — Per-turn ITR tool selection. Embeds the user query,
    scores every tool in the persisted index by cosine similarity,
    keeps the high-confidence hits (CAR adaptive K) plus the
    ALWAYS_INCLUDE set, caps at max_tools.

    Returns None on any of:
      - empty query
      - index not built / missing
      - embedder failure (network, model down)
      - too few hits clear the confidence threshold (ambiguous query)

    The caller is REQUIRED to handle None by falling back to
    `select_tools` so an ITR misfire never produces an empty tool
    list on a live banking engagement.

    `embedder` and `index` are dependency-injected so tests can mock
    them. Production callers pass None and we wire the Ollama
    embedder + on-disk index automatically."""
    if not user_query or not user_query.strip():
        return None
    if not registry:
        return None

    # Lazy import to avoid pulling the embedder module on the static
    # path (banca-safe default).
    from kryon.skills.itr_retriever import select_with_itr

    if embedder is None:
        from kryon.skills.itr_tool_index import OllamaEmbedder

        embedder = OllamaEmbedder()
    if index is None:
        from kryon.skills.itr_tool_index import load_index

        index = load_index()

    selected_names = select_with_itr(
        user_query,
        embedder,
        index,
        max_tools=max_tools,
        always_include=ALWAYS_INCLUDE,
    )
    if selected_names is None:
        return None

    if forbidden_tool_names:
        selected_names = [n for n in selected_names if n not in forbidden_tool_names]

    tools = [registry[n] for n in selected_names if n in registry]
    return tools or None
