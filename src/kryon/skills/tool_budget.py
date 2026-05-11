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
