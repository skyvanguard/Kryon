"""
This package provides a CLI interface for testing and
interacting with KRYON agents.

All public symbols are re-exported from _original for backwards compatibility.
"""

# Re-export everything from the original monolithic module.
# This ensures 100% backwards compatibility:
#   from kryon.cli import main           -> works
#   from kryon.cli import START_TIME     -> works
#   from kryon.cli import ctf_global     -> works
#   from kryon.cli import run_kryon_cli  -> works
from kryon.cli._original import *  # noqa: F401,F403

# Explicit re-exports for the most critical symbols that external code depends on.
# Using `X as X` pattern for PEP 484 explicit re-export compatibility.
from kryon.cli._original import (  # noqa: F811
    START_TIME as START_TIME,  # noqa: F811
    ctf_global as ctf_global,  # noqa: F811
    get_run_config as get_run_config,  # noqa: F811
    main as main,  # noqa: F811
    run_kryon_cli as run_kryon_cli,  # noqa: F811
    update_agent_models_recursively as update_agent_models_recursively,
)
