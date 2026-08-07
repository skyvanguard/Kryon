"""Command execution functions for different environments (local, CTF, SSH, Docker)."""

import logging
import os
import signal as _signal
import subprocess  # nosec B404
import time
import uuid

from wasabi import color

from kryon.tools.common._agent_context import _get_agent_token_info
from kryon.tools.common._workspace import _get_container_workspace_path, _get_workspace_dir
from kryon.util import (
    start_active_timer,
    start_idle_timer,
    stop_active_timer,
    stop_idle_timer,
)

logger = logging.getLogger(__name__)


def _kill_process_group(process) -> None:
    """FASE 11.R — kill the spawned process AND every descendant.

    ``process.kill()`` only signals the immediate child (the shell).
    On Bench Robots (2026-05-27) the shell got the SIGKILL but its
    perl grandchild (``nikto.pl``) was reparented to init and kept
    the stdout pipe open — leaking memory, holding the agent's
    readline loop hostage, and racking up wall-clock.

    Requires the process to have been spawned with
    ``start_new_session=True`` so its pid equals its process-group id.
    Falls back to plain ``process.kill()`` on platforms without
    ``killpg`` (Windows). Swallows ``ProcessLookupError`` because the
    common case during timeout cleanup is "process already exited
    between wait_for and the kill call."
    """
    pid = getattr(process, "pid", None)
    if pid is None:
        return
    try:
        if hasattr(os, "killpg"):
            os.killpg(pid, _signal.SIGKILL)
        else:
            process.kill()
    except (ProcessLookupError, PermissionError) as exc:
        logger.debug("kill_process_group: process %s already gone or denied: %s", pid, exc)
        try:
            process.kill()
        except Exception:  # noqa: BLE001 — last-resort, never bubble
            pass


async def _drain_and_kill(process, timeout: float = 5.0) -> None:
    """Kill the process group then wait briefly for reap.

    Used by the timeout paths in ``_run_local_async`` so the
    ``subprocess.TimeoutExpired`` is raised AFTER the kernel actually
    reaped the descendants — otherwise the next bench turn races a
    zombie and the agent prompt waits on a child that "exists but is
    dead."
    """
    import asyncio as _asyncio

    _kill_process_group(process)
    try:
        await _asyncio.wait_for(process.wait(), timeout=timeout)
    except _asyncio.TimeoutError:
        # Reaper didn't catch it — escalate. Most likely a defunct
        # state we can't help. Log and move on; the caller already
        # decided to raise TimeoutExpired anyway.
        logger.debug("process %s did not reap within %.1fs after killpg", process.pid, timeout)


def _run_ctf(ctf, command, stdout=False, timeout=300, workspace_dir=None, stream=False):
    """Runs command in CTF env, changing to workspace_dir first."""
    target_dir = workspace_dir or _get_workspace_dir()
    full_command = f"{command}"
    original_cmd_for_msg = command  # For logging
    context_msg = f"(ctf:{target_dir})"
    try:
        output = ctf.get_shell(full_command, timeout=timeout)
        # In streaming mode, don't print to stdout to avoid duplication
        # The streaming system will handle the display
        if stdout and not stream:
            print(f"\033[32m{context_msg} $ {original_cmd_for_msg}\n{output}\033[0m")  # noqa E501
        return output
    except Exception as e:  # pylint: disable=broad-except
        error_msg = f"Error executing CTF command '{original_cmd_for_msg}' in '{target_dir}': {e}"  # noqa E501
        print(color(error_msg, fg="red"))
        return error_msg


def _run_ssh(command, stdout=False, timeout=300, workspace_dir=None, stream=False):
    """Runs command via SSH. Assumes SSH agent or passwordless setup unless sshpass is used externally."""  # noqa E501
    ssh_user = os.environ.get("SSH_USER")
    ssh_host = os.environ.get("SSH_HOST")
    ssh_pass = os.environ.get("SSH_PASS")
    remote_command = command
    original_cmd_for_msg = command
    context_msg = f"({ssh_user}@{ssh_host})"

    # Construct base SSH command list
    if ssh_pass:
        ssh_cmd_list = ["sshpass", "-p", ssh_pass, "ssh", f"{ssh_user}@{ssh_host}"]  # noqa E501
    else:
        ssh_cmd_list = ["ssh", f"{ssh_user}@{ssh_host}"]
    ssh_cmd_list.append(remote_command)

    try:
        # Use subprocess.run with list of args for better security than shell=True
        result = subprocess.run(
            ssh_cmd_list,  # nosemgrep: dangerous-subprocess-use-tainted-env-args
            capture_output=True,
            text=True,
            check=False,  # Don't raise exception on non-zero exit code
            timeout=timeout,
        )
        output = result.stdout if result.stdout else result.stderr
        # In streaming mode, don't print to stdout to avoid duplication
        # The streaming system will handle the display
        if stdout and not stream:
            print(f"\033[32m{context_msg} $ {original_cmd_for_msg}\n{output}\033[0m")  # noqa E501
        # Return combined output, potentially including errors
        return output.strip()
    except subprocess.TimeoutExpired as e:
        error_output = e.stdout if e.stdout else str(e)
        timeout_msg = f"Timeout executing SSH command: {error_output}"
        if stdout and not stream:
            print(f"\033[33m{context_msg} $ {original_cmd_for_msg}\nTIMEOUT\n{error_output}\033[0m")  # noqa E501
        return timeout_msg
    except FileNotFoundError:
        # Handle case where ssh or sshpass isn't installed
        error_msg = f"'sshpass' or 'ssh' command not found. Ensure they are installed and in PATH."  # noqa E501
        print(color(error_msg, fg="red"))
        return error_msg
    except Exception as e:  # pylint: disable=broad-except
        error_msg = f"Error executing SSH command '{original_cmd_for_msg}' on {ssh_host}: {e}"  # noqa E501
        print(color(error_msg, fg="red"))
        return error_msg


# Common curl exit codes → human hint. ``curl -s`` (silent) suppresses curl's own
# stderr diagnostic, leaving only the exit code — the model then can't tell "DNS
# didn't resolve" from "timeout" and retries blind (observed live vs
# www.example.com: ``curl -s http://www.host/`` → exit 6, the model read it
# as "red lenta" and looped until the StuckDetector cut it). Glossing the code when
# there's no stderr restores the signal.
_CURL_EXIT_HINTS: dict[int, str] = {
    6: "curl no pudo resolver el host (DNS) — verificá el nombre (¿sobra o falta 'www'?)",
    7: "curl no pudo conectar al host (puerto cerrado / host caído / filtrado)",
    22: "curl: el servidor devolvió un error HTTP >= 400 (con -f/--fail)",
    28: "curl: timeout de la operación",
    35: "curl: error en el handshake SSL/TLS",
    52: "curl: el servidor no devolvió respuesta (empty reply)",
    56: "curl: fallo recibiendo datos de red",
    60: "curl: problema con el certificado SSL del servidor",
}


def _compose_command_output(stdout: str, stderr: str, returncode: int | None, command: str = "") -> str:
    """Compose a command result that always carries a usable signal for the model.

    The non-streaming path used to do ``output = stdout or stderr`` and never report
    the exit code: a failing command with partial stdout dropped its stderr, and a
    command that printed nothing returned ``""``. The model then received an empty
    block (wrapped in the EXTERNAL SERVER RESPONSE fence) with no error and retried
    blind — observed live. Surface stdout, THEN stderr (even when stdout is present),
    THEN a non-zero exit marker; never return an empty string.

    When the command is ``curl`` and it suppressed its own stderr (``-s``), the exit
    marker is glossed with a human hint (see ``_CURL_EXIT_HINTS``) so the model can
    diagnose (e.g. DNS) instead of misreading a bare ``[exit code 6]`` as a timeout.
    """
    parts: list[str] = []
    out, err = (stdout or "").strip(), (stderr or "").strip()
    if out:
        parts.append(out)
    if err:
        parts.append(f"[stderr]\n{err}")
    if returncode not in (0, None):
        marker = f"[exit code {returncode}]"
        if not err and "curl" in (command or "").lower():
            hint = _CURL_EXIT_HINTS.get(returncode)
            if hint:
                marker = f"[exit code {returncode} — {hint}]"
        parts.append(marker)
    result = "\n".join(parts)
    if not result:
        rc = returncode if returncode is not None else "?"
        result = f"[command produced no stdout/stderr; exit code {rc}]"
    return result


async def _run_local_async(
    command,
    stdout=False,
    timeout=300,
    stream=False,
    call_id=None,
    tool_name=None,
    workspace_dir=None,
    custom_args=None,
):
    """Async version of _run_local that uses asyncio subprocess for non-blocking execution."""
    import asyncio

    # Make sure we're in active time mode for tool execution
    stop_idle_timer()
    start_active_timer()

    process_start_time = time.time()  # Initialize with current time
    try:
        target_dir = workspace_dir or _get_workspace_dir()

        # If streaming is enabled and we have a call_id
        if stream:
            # Import the streaming utilities from util
            from kryon.util import (
                finish_tool_streaming,
                start_tool_streaming,
                update_tool_streaming,
            )

            # Parse command into parts for display
            parts = command.strip().split(" ", 1)
            cmd_var = parts[0] if parts else ""
            args_param_val = parts[1] if len(parts) > 1 else ""

            # For generic Linux commands, standardize the tool_name format
            if not tool_name:
                tool_name = f"{cmd_var}_command" if cmd_var else "command"

            # Create args dictionary with non-empty values only
            tool_args = {}
            if cmd_var:
                tool_args["command"] = cmd_var
            if args_param_val and args_param_val.strip():
                tool_args["args"] = args_param_val

            # Add more context for the command
            tool_args["workspace"] = os.path.basename(target_dir)
            tool_args["full_command"] = command

            # If custom args were provided, merge them with the default args
            if custom_args is not None:
                if isinstance(custom_args, dict):
                    # Merge the dictionaries, with custom args taking precedence
                    for key, value in custom_args.items():
                        tool_args[key] = value

            # For generic commands, ensure we have a unique call_id
            if not call_id:
                call_id = f"cmd_{cmd_var}_{str(uuid.uuid4())[:8]}"

            # Get token info for agent display
            token_info = _get_agent_token_info()

            # Initialize/use the call_id for this streaming session
            call_id = start_tool_streaming(tool_name, tool_args, call_id, token_info)

            # Start the async process — FASE 11.R: own process group so
            # the timeout path can kill descendants atomically. Windows
            # doesn't support start_new_session; fall back to legacy.
            # stdin=DEVNULL: a non-interactive `ssh`/`mysql`/`python` (a mistake
            # the local model makes) would otherwise inherit the TTY and block
            # for the full timeout waiting on input — DEVNULL gives it EOF now.
            _subprocess_kwargs = {"stdin": asyncio.subprocess.DEVNULL}
            if hasattr(os, "setsid"):
                _subprocess_kwargs["start_new_session"] = True
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=target_dir,
                **_subprocess_kwargs,
            )

            # Begin collecting output
            output_buffer = []
            buffer_size = 0
            # T4 — hard byte ceiling on accumulated stdout. Without it a target
            # streaming an endless/huge body (slow-drip endpoint, `cat` of a big
            # file, nmap over a huge range) grows RAM until EOF/timeout. At the
            # cap we kill the process and truncate — the downstream token cap
            # (micro_compact) runs only AFTER this full string is built.
            output_bytes = 0
            _MAX_OUTPUT_BYTES = 8 * 1024 * 1024  # 8 MB
            update_interval = 10  # lines - default for most tools

            # Use a smaller interval for known long-running tools
            if tool_name in ("run_command", "nmap_command", "nmap_scan"):
                update_interval = 1
            elif tool_name in ("hashcat_command", "gobuster_command", "ffuf_command"):
                update_interval = 3

            # Set up progress parser
            from kryon.repl.ui.progress import ProgressState, get_parser_for_command

            progress_parser = get_parser_for_command(command)
            progress_state = ProgressState(tool_name=tool_name)

            # FASE 11.R — wall-clock guard on the stdout loop. The
            # original ``async for line in process.stdout`` had NO
            # timeout: a child that holds the pipe but writes nothing
            # (Bench Robots nikto/perl orphan case) blocked the loop
            # forever. We poll readline with the REMAINING wall budget
            # so a silent child still raises TimeoutExpired inside
            # ``timeout`` seconds total.
            deadline = asyncio.get_event_loop().time() + timeout
            while True:
                now = asyncio.get_event_loop().time()
                remaining = deadline - now
                if remaining <= 0:
                    await _drain_and_kill(process)
                    # T3-A8: hand the partial output to the timeout so the model sees
                    # what the tool found before it was killed, not just "timed out".
                    raise subprocess.TimeoutExpired(command, timeout, output="".join(output_buffer))
                try:
                    line = await asyncio.wait_for(process.stdout.readline(), timeout=remaining)
                except asyncio.TimeoutError as e:
                    await _drain_and_kill(process)
                    raise subprocess.TimeoutExpired(command, timeout, output="".join(output_buffer)) from e

                if not line:
                    # EOF — process either finished or closed its stdout.
                    # The wait_for below will pick up the actual return code.
                    break

                line_str = line.decode("utf-8", errors="replace")

                # Add to output collection
                output_buffer.append(line_str)
                buffer_size += 1
                output_bytes += len(line)
                if output_bytes >= _MAX_OUTPUT_BYTES:  # T4 — cap RAM, kill + truncate
                    await _drain_and_kill(process)
                    output_buffer.append(
                        f"\n[... output truncated at {_MAX_OUTPUT_BYTES // (1024 * 1024)} MB — process killed ...]\n"
                    )
                    break

                # Update progress state
                progress_state = progress_parser.parse_line(line_str, progress_state)

                # Only update periodically to reduce UI refreshes
                if buffer_size >= update_interval:
                    current_output = "".join(output_buffer)
                    update_tool_streaming(
                        tool_name,
                        tool_args,
                        current_output,
                        call_id,
                        token_info,
                        progress_state=progress_state,
                    )
                    buffer_size = 0

            # Wait for process to complete with timeout — at this point
            # stdout EOF has fired, so wait() should return promptly.
            # The remaining-budget guard still applies for the edge
            # case where the child closed stdout but kept its zombie
            # state alive (rare but observable on docker exec exits).
            now = asyncio.get_event_loop().time()
            remaining = max(deadline - now, 0.0)
            try:
                return_code = await asyncio.wait_for(process.wait(), timeout=remaining or 1.0)
            except asyncio.TimeoutError as e:
                await _drain_and_kill(process)
                raise subprocess.TimeoutExpired(command, timeout, output="".join(output_buffer)) from e

            process_execution_time = time.time() - process_start_time

            # Get any stderr output
            stderr_data = await process.stderr.read()
            if stderr_data:
                stderr_str = stderr_data.decode("utf-8", errors="replace")
                output_buffer.append("\nERROR OUTPUT:\n" + stderr_str)

            # Final output update
            final_output = "".join(output_buffer)
            if return_code != 0:
                final_output += f"\nCommand exited with code {return_code}"

            # Calculate execution info with environment details
            execution_info = {
                "status": "completed" if return_code == 0 else "error",
                "return_code": return_code,
                "environment": "Local",
                "host": os.path.basename(target_dir),
                "tool_time": process_execution_time,
            }

            # Complete the streaming session with final output
            finish_tool_streaming(tool_name, tool_args, final_output, call_id, execution_info, token_info)

            return final_output
        else:
            # Standard non-streaming async execution — FASE 11.R:
            # same process-group treatment as the streaming branch,
            # so a timeout in parallel mode also kills descendants.
            # stdin=DEVNULL: don't inherit the TTY — a non-interactive shell
            # binary (ssh/mysql/python) would block on input for the full timeout.
            _subprocess_kwargs = {"stdin": asyncio.subprocess.DEVNULL}
            if hasattr(os, "setsid"):
                _subprocess_kwargs["start_new_session"] = True
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=target_dir,
                **_subprocess_kwargs,
            )

            try:
                stdout_data, stderr_data = await asyncio.wait_for(process.communicate(), timeout=timeout)
            except asyncio.TimeoutError as e:
                await _drain_and_kill(process)
                raise subprocess.TimeoutExpired(command, timeout) from e

            # Decode output — surface stdout AND stderr AND the exit code (see
            # _compose_command_output) so a failing command gives the model a real
            # signal instead of an empty block it retries blind.
            _out = stdout_data.decode("utf-8", errors="replace") if stdout_data else ""
            _err = stderr_data.decode("utf-8", errors="replace") if stderr_data else ""
            output = _compose_command_output(_out, _err, process.returncode, command)

            # Parse command for display
            parts = command.strip().split(" ", 1)

            # In non-streaming mode (typically parallel execution), display completed panel
            # Get token info for agent display
            token_info = _get_agent_token_info()

            # Check if we're in parallel mode by checking agent ID
            is_parallel = False
            if token_info and token_info.get("agent_id"):
                agent_id = token_info.get("agent_id")
                if agent_id and agent_id.startswith("P") and agent_id[1:].isdigit():
                    # Check KRYON_PARALLEL to confirm
                    if int(os.getenv("KRYON_PARALLEL", "1")) > 1:
                        is_parallel = True

            # NEVER display panels in non-streaming mode
            # The SDK will handle ALL display when KRYON_STREAM=false
            streaming_enabled = os.getenv("KRYON_STREAM", "false").lower() == "true"

            # Only display panels if we're in streaming mode or parallel mode
            # In streaming mode, the Live panels are handled by the streaming system
            if streaming_enabled and is_parallel:
                # Display the completed tool output
                from kryon.util import cli_print_tool_output

                # Calculate execution time
                execution_time = time.time() - process_start_time

                # Generate a unique call_id if not provided
                if not call_id:
                    cmd_name = parts[0] if parts else "cmd"
                    call_id = f"{cmd_name}_{str(uuid.uuid4())[:8]}"

                execution_info = {
                    "status": "completed" if process.returncode == 0 else "error",
                    "return_code": process.returncode,
                    "environment": "Local",
                    "host": os.path.basename(target_dir),
                    "tool_time": execution_time,
                }

                # Display the tool output panel
                cli_print_tool_output(
                    tool_name=tool_name or "run_command",
                    args={
                        "command": parts[0] if parts else command,
                        "args": parts[1] if len(parts) > 1 else "",
                        "full_command": command,
                        "workspace": os.path.basename(target_dir),
                    },
                    output=output.strip(),
                    call_id=call_id,
                    execution_info=execution_info,
                    token_info=token_info,
                    streaming=False,  # This is non-streaming display
                )

            return output.strip()

    except subprocess.TimeoutExpired as e:
        error_output = e.stdout if hasattr(e, "stdout") and e.stdout else str(e)
        error_msg = f"Command timed out after {timeout} seconds\n{error_output}"

        # If we're streaming, show the timeout in the tool output panel
        if stream and call_id:
            from kryon.util import finish_tool_streaming

            # Parse the command the same way we did for streaming
            parts = command.strip().split(" ", 1)
            cmd_var = parts[0] if parts else ""
            args_var = parts[1] if len(parts) > 1 else ""

            # Ensure tool_args has complete information
            tool_args = {
                "command": cmd_var,
                "args": args_var if args_var.strip() else "",
                "full_command": command,
                "environment": "Local",
                "workspace": os.path.basename(target_dir),
            }
            execution_info = {
                "status": "timeout",
                "error": str(e),
                "environment": "Local",
                "host": os.path.basename(target_dir),
            }

            # Get token info for agent display
            token_info = _get_agent_token_info()
            finish_tool_streaming(
                tool_name or f"{cmd_var}_command",
                tool_args,
                error_msg,
                call_id,
                execution_info,
                token_info,
            )

        if stdout:
            print("\033[32m" + error_msg + "\033[0m")

        return error_msg
    except Exception as e:  # pylint: disable=broad-except
        error_msg = f"Error executing local command: {e}"

        # If we're streaming, show the error in the tool output panel
        if stream and call_id:
            from kryon.util import finish_tool_streaming

            # Parse the command the same way we did for streaming
            parts = command.strip().split(" ", 1)
            cmd_var = parts[0] if parts else ""
            args_var = parts[1] if len(parts) > 1 else ""

            # Ensure tool_args has complete information
            tool_args = {
                "command": cmd_var,
                "args": args_var if args_var.strip() else "",
                "full_command": command,
                "environment": "Local",
                "workspace": os.path.basename(target_dir),
            }
            execution_info = {
                "status": "error",
                "error": str(e),
                "environment": "Local",
                "host": os.path.basename(target_dir),
            }

            # Get token info for agent display
            token_info = _get_agent_token_info()
            finish_tool_streaming(
                tool_name or f"{cmd_var}_command",
                tool_args,
                error_msg,
                call_id,
                execution_info,
                token_info,
            )

        print(color(error_msg, fg="red"))
        return error_msg
    finally:
        # Always switch back to idle mode when function completes
        stop_active_timer()
        start_idle_timer()


async def _run_docker_async(
    command,
    container_id,
    stdout=False,
    timeout=300,
    stream=False,
    call_id=None,
    tool_name=None,
    args=None,
):
    """Async version of Docker command execution using asyncio subprocess."""
    import asyncio

    # Make sure we're in active time mode for tool execution
    stop_idle_timer()
    start_active_timer()

    try:
        container_workspace = _get_container_workspace_path()

        # Parse command for display
        parts = command.strip().split(" ", 1)
        cmd_name = parts[0] if parts else ""
        cmd_args = parts[1] if len(parts) > 1 else ""

        if not tool_name:
            tool_name = f"{cmd_name}_command" if cmd_name else "command"

        # Build docker exec command
        docker_cmd_list = [
            "docker",
            "exec",
            "-w",
            container_workspace,
            container_id,
            "sh",
            "-c",
            command,
        ]

        if stream:
            from kryon.util import (
                finish_tool_streaming,
                start_tool_streaming,
                update_tool_streaming,
            )

            # If args were provided (e.g., from execute_code), use them as base
            # Otherwise create tool args for display
            if args and isinstance(args, dict):
                tool_args = args.copy()
                # Add container-specific info
                tool_args["container"] = container_id[:12]
                tool_args["environment"] = "Container"
                tool_args["workspace"] = container_workspace
                tool_args["full_command"] = command
            else:
                tool_args = {
                    "command": cmd_name,
                    "args": cmd_args if cmd_args.strip() else "",
                    "full_command": command,
                    "container": container_id[:12],
                    "environment": "Container",
                    "workspace": container_workspace,
                }

            if not call_id:
                call_id = f"cmd_{cmd_name}_{str(uuid.uuid4())[:8]}"

            token_info = _get_agent_token_info()
            call_id = start_tool_streaming(tool_name, tool_args, call_id, token_info)

            # Create async subprocess
            process = await asyncio.create_subprocess_exec(
                *docker_cmd_list, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            # Stream output
            output_buffer = []
            buffer_size = 0
            update_interval = 1 if tool_name in ("run_command", "nmap_command", "nmap_scan") else 10

            start_time = time.time()

            # Set up progress parser
            from kryon.repl.ui.progress import ProgressState, get_parser_for_command

            progress_parser = get_parser_for_command(command)
            progress_state = ProgressState(tool_name=tool_name)

            # Read stdout line by line
            async for line in process.stdout:
                line_str = line.decode("utf-8", errors="replace")
                output_buffer.append(line_str)
                buffer_size += 1

                # Update progress state
                progress_state = progress_parser.parse_line(line_str, progress_state)

                # Only update periodically to reduce UI refreshes
                if buffer_size >= update_interval:
                    # Show actual output as it's being collected
                    current_output = "".join(output_buffer)
                    update_tool_streaming(
                        tool_name,
                        tool_args,
                        current_output,
                        call_id,
                        token_info,
                        progress_state=progress_state,
                    )
                    buffer_size = 0

            # Wait for process completion
            try:
                return_code = await asyncio.wait_for(process.wait(), timeout=timeout)
            except asyncio.TimeoutError as e:
                process.kill()
                await process.wait()
                raise subprocess.TimeoutExpired(command, timeout) from e

            execution_time = time.time() - start_time

            # Get stderr if any
            stderr_data = await process.stderr.read()
            if stderr_data:
                stderr_str = stderr_data.decode("utf-8", errors="replace")
                output_buffer.append("\nERROR OUTPUT:\n" + stderr_str)

            final_output = "".join(output_buffer)
            if return_code != 0:
                final_output += f"\nCommand exited with code {return_code}"

            execution_info = {
                "status": "completed" if return_code == 0 else "error",
                "return_code": return_code,
                "environment": "Container",
                "host": container_id[:12],
                "tool_time": execution_time,
            }

            finish_tool_streaming(tool_name, tool_args, final_output, call_id, execution_info, token_info)
            return final_output

        else:
            # Non-streaming async execution
            start_time = time.time()
            process = await asyncio.create_subprocess_exec(
                *docker_cmd_list, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout_data, stderr_data = await asyncio.wait_for(process.communicate(), timeout=timeout)
            except asyncio.TimeoutError as e:
                process.kill()
                await process.wait()
                raise subprocess.TimeoutExpired(command, timeout) from e

            output = stdout_data.decode("utf-8", errors="replace") if stdout_data else ""
            if not output and stderr_data:
                output = stderr_data.decode("utf-8", errors="replace")

            if stdout:
                context_msg = f"(docker:{container_id[:12]}:{container_workspace})"
                print(f"\033[32m{context_msg} $ {command}\n{output}\033[0m")

            # Get token info for display
            token_info = _get_agent_token_info()

            # Check if we're in parallel mode
            is_parallel = False
            if token_info and token_info.get("agent_id"):
                agent_id = token_info.get("agent_id")
                if agent_id and agent_id.startswith("P") and agent_id[1:].isdigit():
                    if int(os.getenv("KRYON_PARALLEL", "1")) > 1:
                        is_parallel = True

            # NEVER display panels in non-streaming mode
            # The SDK will handle ALL display when KRYON_STREAM=false
            streaming_enabled = os.getenv("KRYON_STREAM", "false").lower() == "true"

            # Only display if we're in streaming mode AND parallel mode
            if streaming_enabled and is_parallel:
                from kryon.util import cli_print_tool_output

                # Calculate execution time
                execution_time = time.time() - start_time

                # Parse command for display
                parts = command.strip().split(" ", 1)

                # Generate a unique call_id if not provided
                if not call_id:
                    cmd_name = parts[0] if parts else "cmd"
                    call_id = f"container_{cmd_name}_{str(uuid.uuid4())[:8]}"

                execution_info = {
                    "status": "completed" if process.returncode == 0 else "error",
                    "return_code": process.returncode,
                    "environment": "Container",
                    "host": container_id[:12],
                    "tool_time": execution_time,
                }

                # Display the tool output panel
                display_args = (
                    args
                    if args is not None
                    else {
                        "command": parts[0] if parts else command,
                        "args": parts[1] if len(parts) > 1 else "",
                        "full_command": command,
                        "container": container_id[:12],
                        "workspace": container_workspace,
                    }
                )

                cli_print_tool_output(
                    tool_name=tool_name or "run_command",
                    args=display_args,
                    output=output.strip(),
                    call_id=call_id,
                    execution_info=execution_info,
                    token_info=token_info,
                    streaming=False,
                )

            return output.strip()

    except Exception as e:
        error_msg = f"Error executing command in container: {str(e)}"
        print(color(error_msg, fg="red"))
        return error_msg
    finally:
        stop_active_timer()
        start_idle_timer()


def _run_local(
    command,
    stdout=False,
    timeout=300,
    stream=False,
    call_id=None,
    tool_name=None,
    workspace_dir=None,
    custom_args=None,
):
    """Runs command locally in the specified workspace_dir."""
    # Make sure we're in active time mode for tool execution
    stop_idle_timer()
    start_active_timer()

    process_start_time = time.time()  # Initialize with current time
    try:
        target_dir = workspace_dir or _get_workspace_dir()

        # If streaming is enabled and we have a call_id
        if stream:
            # Import the streaming utilities from util
            from kryon.util import (
                finish_tool_streaming,
                start_tool_streaming,
                update_tool_streaming,
            )

            # Parse command into parts for display
            parts = command.strip().split(" ", 1)
            cmd_var = parts[0] if parts else ""
            args_param_val = parts[1] if len(parts) > 1 else ""  # Renamed to avoid conflict with tool_args dict key

            # For generic Linux commands, standardize the tool_name format
            if not tool_name:
                tool_name = f"{cmd_var}_command" if cmd_var else "command"

            # Create args dictionary with non-empty values only
            tool_args = {}
            if cmd_var:
                tool_args["command"] = cmd_var
            if args_param_val and args_param_val.strip():
                tool_args["args"] = args_param_val

            # Add more context for the command
            tool_args["workspace"] = os.path.basename(target_dir)
            tool_args["full_command"] = command

            # If custom args were provided, merge them with the default args
            if custom_args is not None:
                if isinstance(custom_args, dict):
                    # Merge the dictionaries, with custom args taking precedence
                    for key, value in custom_args.items():
                        tool_args[key] = value

            # For generic commands, ensure we have a unique call_id
            if not call_id:
                call_id = f"cmd_{cmd_var}_{str(uuid.uuid4())[:8]}"

            # Get token info for agent display
            token_info = _get_agent_token_info()

            # Initialize/use the call_id for this streaming session
            call_id = start_tool_streaming(tool_name, tool_args, call_id, token_info)

            # Start the process
            process = subprocess.Popen(
                command,
                shell=True,  # nosec B602  # nosemgrep: subprocess-shell-true
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                cwd=target_dir,
            )

            # Begin collecting output
            output_buffer = []
            buffer_size = 0
            # T4 — hard byte ceiling on accumulated stdout. Without it a target
            # streaming an endless/huge body (slow-drip endpoint, `cat` of a big
            # file, nmap over a huge range) grows RAM until EOF/timeout. At the
            # cap we kill the process and truncate — the downstream token cap
            # (micro_compact) runs only AFTER this full string is built.
            output_bytes = 0
            _MAX_OUTPUT_BYTES = 8 * 1024 * 1024  # 8 MB
            update_interval = 10  # lines - default for most tools

            # Use a smaller interval for known long-running tools
            if tool_name in ("run_command", "nmap_command", "nmap_scan"):
                update_interval = 1
            elif tool_name in ("hashcat_command", "gobuster_command", "ffuf_command"):
                update_interval = 3

            # Set up progress parser
            from kryon.repl.ui.progress import ProgressState, get_parser_for_command

            progress_parser = get_parser_for_command(command)
            progress_state = ProgressState(tool_name=tool_name)

            # Stream stdout in real-time
            for line in iter(process.stdout.readline, ""):
                if not line:
                    break

                # Add to output collection
                output_buffer.append(line)
                buffer_size += 1
                output_bytes += len(line)
                if output_bytes >= _MAX_OUTPUT_BYTES:  # T4 — cap RAM, kill + truncate
                    try:
                        process.kill()
                    except Exception:
                        pass
                    output_buffer.append(
                        f"\n[... output truncated at {_MAX_OUTPUT_BYTES // (1024 * 1024)} MB — process killed ...]\n"
                    )
                    break

                # Update progress state
                progress_state = progress_parser.parse_line(line, progress_state)

                # Only update periodically to reduce UI refreshes
                if buffer_size >= update_interval:
                    current_output = "".join(output_buffer)
                    update_tool_streaming(
                        tool_name,
                        tool_args,
                        current_output,
                        call_id,
                        token_info,
                        progress_state=progress_state,
                    )
                    buffer_size = 0

            # Finish process
            process.stdout.close()
            return_code = process.wait(timeout=timeout)
            process_execution_time = time.time() - process_start_time

            # Get any stderr output
            stderr_data = process.stderr.read()
            if stderr_data:
                output_buffer.append("\nERROR OUTPUT:\n" + stderr_data)

            # Final output update
            final_output = "".join(output_buffer)
            if return_code != 0:
                final_output += f"\nCommand exited with code {return_code}"

            # Calculate execution info with environment details
            execution_info = {
                "status": "completed" if return_code == 0 else "error",
                "return_code": return_code,
                "environment": "Local",
                "host": os.path.basename(target_dir),
                "tool_time": process_execution_time,
            }

            # Complete the streaming session with final output
            finish_tool_streaming(tool_name, tool_args, final_output, call_id, execution_info, token_info)

            return final_output
        else:
            # Standard non-streaming execution
            result = subprocess.run(
                command,
                shell=True,  # nosec B602  # nosemgrep: subprocess-shell-true
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
                cwd=target_dir,
            )
            # Surface stdout AND stderr AND the exit code (see _compose_command_output)
            # so a failing command gives the model a real signal, not an empty block.
            output = _compose_command_output(result.stdout, result.stderr, result.returncode, command)

            # Parse command for display
            parts = command.strip().split(" ", 1)

            # In non-streaming mode (typically parallel execution), we should display
            # the tool output as a completed panel immediately
            # Get token info for agent display
            token_info = _get_agent_token_info()

            # Check if we're in parallel mode by checking agent ID
            is_parallel = False
            if token_info and token_info.get("agent_id"):
                agent_id = token_info.get("agent_id")
                if agent_id and agent_id.startswith("P") and agent_id[1:].isdigit():
                    # Check KRYON_PARALLEL to confirm
                    if int(os.getenv("KRYON_PARALLEL", "1")) > 1:
                        is_parallel = True

            # NEVER display panels in non-streaming mode
            # The SDK will handle ALL display when KRYON_STREAM=false
            streaming_enabled = os.getenv("KRYON_STREAM", "false").lower() == "true"

            # Only display if we're in streaming mode AND parallel mode
            if streaming_enabled and is_parallel:
                # Display the completed tool output
                from kryon.util import cli_print_tool_output

                # Calculate execution time
                execution_time = time.time() - process_start_time

                # Generate a unique call_id if not provided
                if not call_id:
                    cmd_name = parts[0] if parts else "cmd"
                    call_id = f"{cmd_name}_{str(uuid.uuid4())[:8]}"

                execution_info = {
                    "status": "completed" if result.returncode == 0 else "error",
                    "return_code": result.returncode,
                    "environment": "Local",
                    "host": os.path.basename(target_dir),
                    "tool_time": execution_time,
                }

                # Display the tool output panel
                # Use provided custom_args if available, otherwise create default args
                display_args = (
                    custom_args
                    if custom_args is not None
                    else {
                        "command": parts[0] if parts else command,
                        "args": parts[1] if len(parts) > 1 else "",
                        "full_command": command,
                        "workspace": os.path.basename(target_dir),
                    }
                )

                cli_print_tool_output(
                    tool_name=tool_name or "run_command",
                    args=display_args,
                    output=output.strip(),
                    call_id=call_id,
                    execution_info=execution_info,
                    token_info=token_info,
                    streaming=False,  # This is non-streaming display
                )

            return output.strip()
    except subprocess.TimeoutExpired as e:
        error_output = e.stdout if hasattr(e, "stdout") and e.stdout else str(e)
        error_msg = f"Command timed out after {timeout} seconds\n{error_output}"

        # If we're streaming, show the timeout in the tool output panel
        if stream and call_id:
            from kryon.util import finish_tool_streaming

            # Parse the command the same way we did for streaming
            parts = command.strip().split(" ", 1)
            cmd_var = parts[0] if parts else ""
            args_var = parts[1] if len(parts) > 1 else ""

            # Ensure tool_args has complete information
            tool_args = {
                "command": cmd_var,
                "args": args_var if args_var.strip() else "",
                "full_command": command,
                "environment": "Local",
                "workspace": os.path.basename(target_dir),
            }
            execution_info = {
                "status": "timeout",
                "error": str(e),
                "environment": "Local",
                "host": os.path.basename(target_dir),
            }

            # Get token info for agent display
            token_info = _get_agent_token_info()
            finish_tool_streaming(
                tool_name or f"{cmd_var}_command",
                tool_args,
                error_msg,
                call_id,
                execution_info,
                token_info,
            )

        if stdout:
            print("\033[32m" + error_msg + "\033[0m")
            return error_msg

        return error_msg
    except Exception as e:  # pylint: disable=broad-except
        error_msg = f"Error executing local command: {e}"

        # If we're streaming, show the error in the tool output panel
        if stream and call_id:
            from kryon.util import finish_tool_streaming

            # Parse the command the same way we did for streaming
            parts = command.strip().split(" ", 1)
            cmd_var = parts[0] if parts else ""
            args_var = parts[1] if len(parts) > 1 else ""

            # Ensure tool_args has complete information
            tool_args = {
                "command": cmd_var,
                "args": args_var if args_var.strip() else "",
                "full_command": command,
                "environment": "Local",
                "workspace": os.path.basename(target_dir),
            }
            execution_info = {
                "status": "error",
                "error": str(e),
                "environment": "Local",
                "host": os.path.basename(target_dir),
            }

            # Get token info for agent display
            token_info = _get_agent_token_info()
            finish_tool_streaming(
                tool_name or f"{cmd_var}_command",
                tool_args,
                error_msg,
                call_id,
                execution_info,
                token_info,
            )

        print(color(error_msg, fg="red"))
        return error_msg
    finally:
        # Always switch back to idle mode when function completes
        stop_active_timer()
        start_idle_timer()
