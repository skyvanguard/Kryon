"""
Basic utilities for executing tools
inside or outside of virtual containers.

This package provides command execution, shell session management,
and workspace utilities for KRYON's security tools.

All public symbols are re-exported here for backwards compatibility.
"""

# Re-export everything from submodules for 100% backwards compatibility
# Any code doing `from kryon.tools.common import X` will continue to work.

from kryon.tools.common._agent_context import (
    _get_agent_token_info,
)
from kryon.tools.common._dispatchers import (
    run_command,
    run_command_async,
)
from kryon.tools.common._executors import (
    _run_ctf,
    _run_docker_async,
    _run_local,
    _run_local_async,
    _run_ssh,
)
from kryon.tools.common._lazy_imports import (
    _GenericLinuxCommandProxy,
    _get_generic_linux_command,
    generic_linux_command,
)
from kryon.tools.common._sessions import (
    ACTIVE_SESSIONS,
    FRIENDLY_SESSION_MAP,
    REVERSE_SESSION_MAP,
    SESSION_COUNTER,
    SESSION_OUTPUT_COUNTER,
    ShellSession,
    _resolve_session_id,
    create_shell_session,
    get_session_output,
    list_shell_sessions,
    send_to_session,
    terminate_session,
)
from kryon.tools.common._workspace import (
    _get_container_workspace_path,
    _get_workspace_dir,
)

# Lazy import for START_TIME from cli module (avoid circular imports)
try:
    from kryon.cli import START_TIME
except ImportError:
    START_TIME = None

__all__ = [
    # Lazy imports
    "_GenericLinuxCommandProxy",
    "_get_generic_linux_command",
    "generic_linux_command",
    # Workspace
    "_get_container_workspace_path",
    "_get_workspace_dir",
    # Agent context
    "_get_agent_token_info",
    # Sessions
    "ACTIVE_SESSIONS",
    "FRIENDLY_SESSION_MAP",
    "REVERSE_SESSION_MAP",
    "SESSION_COUNTER",
    "SESSION_OUTPUT_COUNTER",
    "ShellSession",
    "create_shell_session",
    "list_shell_sessions",
    "_resolve_session_id",
    "send_to_session",
    "get_session_output",
    "terminate_session",
    # Executors
    "_run_ctf",
    "_run_ssh",
    "_run_local_async",
    "_run_docker_async",
    "_run_local",
    # Dispatchers
    "run_command",
    "run_command_async",
    # From cli (lazy)
    "START_TIME",
]
