"""Centralised RunConfig factory for Claude Code CLI integration.

Importable from anywhere without circular dependencies (unlike cli._original).
"""

from __future__ import annotations

import os


def get_run_config():
    """Return a RunConfig wired to ClaudeCodeProvider when KRYON_CLAUDE_CODE is set.

    Returns ``None`` when Claude Code mode is not active, letting the SDK
    fall back to the default OpenAI-compatible provider.
    """
    if os.getenv("KRYON_CLAUDE_CODE", "").lower() != "true":
        return None

    from kryon.sdk.agents import RunConfig
    from kryon.sdk.agents.models.claude_code_provider import ClaudeCodeModel, ClaudeCodeProvider

    model_name = os.getenv("KRYON_CLAUDE_MODEL", "opus")
    provider = ClaudeCodeProvider(default_model=model_name, timeout=300)
    model_instance = ClaudeCodeModel(model=model_name, timeout=300)
    return RunConfig(model=model_instance, model_provider=provider)
