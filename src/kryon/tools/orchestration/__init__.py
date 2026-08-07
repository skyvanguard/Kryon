"""Agentic wrappers over Kryon's high-level deterministic orchestrators.

These expose engage-grade pipelines (network audit, etc.) as function_tools so
the agent can invoke them mid-conversation instead of depending on the REPL's
pre-agent router or a CLI subcommand.
"""

from .audit import audit_target

__all__ = ["audit_target"]
