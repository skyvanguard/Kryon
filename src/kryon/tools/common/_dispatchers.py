"""Main command dispatchers that route execution to the appropriate environment."""

import os
import shlex
import subprocess  # nosec B404
import time
import uuid

from wasabi import color

from kryon.tools.common._agent_context import _get_agent_token_info
from kryon.tools.common._executors import _run_ctf, _run_docker_async, _run_local, _run_local_async, _run_ssh
from kryon.tools.common._sessions import (
    ACTIVE_SESSIONS,
    SESSION_OUTPUT_COUNTER,
    _resolve_session_id,
    create_shell_session,
)
from kryon.tools.common._workspace import _get_container_workspace_path, _get_workspace_dir
from kryon.util import (
    start_active_timer,
    start_idle_timer,
    stop_active_timer,
    stop_idle_timer,
)


async def run_command_async(
    command,
    ctf=None,
    stdout=False,  # pylint: disable=too-many-arguments # noqa: E501
    async_mode=False,
    session_id=None,
    timeout=300,
    stream=False,
    call_id=None,
    tool_name=None,
    args=None,
):
    """
    Async version of run_command that properly supports parallel execution.

    Run command in the appropriate environment (Docker, CTF, SSH, Local)
    and workspace.

    Args:
        command: The command to execute
        ctf: CTF environment object (if running in CTF)
        stdout: Whether to print output to stdout
        async_mode: Whether to run the command asynchronously
        session_id: ID of an existing session to send the command to
        timeout: Command timeout in seconds
        stream: Whether to stream output in real-time
        call_id: Unique ID for the command execution (for streaming)
        tool_name: Name of the tool being executed (for display in streaming output).
                  If None, the tool name will be derived from the command.
        args: Additional arguments for the tool (for display and context).

    Returns:
        str: Command output, status message, or session ID.
    """
    # For now, we'll use a hybrid approach - delegate most of the logic to sync version
    # but use async subprocess for local execution

    if ctf and not hasattr(ctf, "get_shell"):
        ctf = None

    # Parse command into standard parts to ensure consistent naming
    parts = command.strip().split(" ", 1)
    cmd_name = parts[0] if parts else ""
    parts[1] if len(parts) > 1 else ""

    # Generate a call_id if we're streaming and one wasn't provided
    if not call_id and stream:
        call_id = f"cmd_{cmd_name}_{str(uuid.uuid4())[:8]}"

    # If no tool_name is provided, derive it from the command in a consistent way
    if not tool_name:
        tool_name = f"{cmd_name}_command" if cmd_name else "command"

    # Determine execution environment
    from kryon.cli import ctf_global

    ctf = ctf_global

    # Check for session execution
    if session_id:
        # Sessions need synchronous handling, delegate to sync version
        import asyncio
        import functools

        loop = asyncio.get_event_loop()
        func = functools.partial(
            run_command,
            command,
            ctf,
            stdout,
            async_mode,
            session_id,
            timeout,
            stream,
            call_id,
            tool_name,
            args,
        )
        return await loop.run_in_executor(None, func)

    # Check execution environment priority
    active_container = os.getenv("KRYON_ACTIVE_CONTAINER", "")
    is_ssh_env = all(os.getenv(var) for var in ["SSH_USER", "SSH_HOST"])

    # For container execution, use async subprocess
    if active_container and not is_ssh_env:
        return await _run_docker_async(
            command,
            container_id=active_container,
            stdout=stdout,
            timeout=timeout,
            stream=stream,
            call_id=call_id,
            tool_name=tool_name,
            args=args,
        )

    # For CTF execution, still need to use sync version in executor
    # because ctf.get_shell() is synchronous
    if ctf and os.getenv("CTF_INSIDE", "True").lower() == "true":
        import asyncio
        import functools

        loop = asyncio.get_event_loop()
        func = functools.partial(_run_ctf, ctf, command, stdout, timeout, _get_workspace_dir(), stream)
        return await loop.run_in_executor(None, func)

    # For SSH, delegate to sync version for now
    if is_ssh_env:
        import asyncio
        import functools

        loop = asyncio.get_event_loop()
        func = functools.partial(_run_ssh, command, stdout, timeout, _get_workspace_dir(), stream)
        return await loop.run_in_executor(None, func)

    # For local execution, use the async version
    return await _run_local_async(
        command,
        stdout=stdout,
        timeout=timeout,
        stream=stream,
        call_id=call_id,
        tool_name=tool_name,
        workspace_dir=_get_workspace_dir(),
        custom_args=args,
    )


def run_command(
    command,
    ctf=None,
    stdout=False,  # pylint: disable=too-many-arguments # noqa: E501
    async_mode=False,
    session_id=None,
    timeout=300,
    stream=False,
    call_id=None,
    tool_name=None,
    args=None,
):
    """
    Run command in the appropriate environment (Docker, CTF, SSH, Local)
    and workspace.

    Args:
        command: The command to execute
        ctf: CTF environment object (if running in CTF)
        stdout: Whether to print output to stdout
        async_mode: Whether to run the command asynchronously
        session_id: ID of an existing session to send the command to
        timeout: Command timeout in seconds
        stream: Whether to stream output in real-time
        call_id: Unique ID for the command execution (for streaming)
        tool_name: Name of the tool being executed (for display in streaming output).
                  If None, the tool name will be derived from the command.
        args: Additional arguments for the tool (for display and context).

    Returns:
        str: Command output, status message, or session ID.
    """
    if ctf and not hasattr(ctf, "get_shell"):
        ctf = None
    # Use the active timer during tool execution
    stop_idle_timer()
    start_active_timer()

    from kryon.cli import ctf_global

    ctf = ctf_global

    # Parse command into standard parts to ensure consistent naming
    parts = command.strip().split(" ", 1)
    cmd_name = parts[0] if parts else ""
    cmd_args = parts[1] if len(parts) > 1 else ""

    # Generate a call_id if we're streaming and one wasn't provided
    # Use a more specific format that includes the command name for easier tracking
    if not call_id and stream:
        call_id = f"cmd_{cmd_name}_{str(uuid.uuid4())[:8]}"

    # If no tool_name is provided, derive it from the command in a consistent way
    if not tool_name:
        tool_name = f"{cmd_name}_command" if cmd_name else "command"

    try:
        # If session_id is provided, send command to that session
        if session_id:
            resolved_session_id = _resolve_session_id(session_id)
            if not resolved_session_id or resolved_session_id not in ACTIVE_SESSIONS:
                # Switch back to idle mode before returning error
                stop_active_timer()
                start_idle_timer()
                return f"Session {session_id} not found"
            session = ACTIVE_SESSIONS[resolved_session_id]
            result = session.send_input(command)  # Send the raw command string

            # Wait for the command to execute and capture output
            # This provides automatic output display for async sessions
            wait_time = 3.0  # Wait 3 seconds for command to execute

            # Mark the current position in the output buffer before sending input
            session.get_new_output(mark_position=True)  # Reset position marker

            # Smart waiting: check for new output every 0.5 seconds, up to max wait time
            max_wait = wait_time
            check_interval = 0.5
            elapsed = 0.0
            new_output_detected = False

            while elapsed < max_wait:
                time.sleep(check_interval)
                elapsed += check_interval

                # Check if new output is available
                current_new_output = session.get_new_output(mark_position=False)

                # If we detect new output, wait a bit more for it to complete, then break
                if current_new_output.strip():
                    if not new_output_detected:
                        new_output_detected = True
                        # Give it a bit more time to complete the output
                        time.sleep(0.5)
                    else:
                        # We already detected new output and waited, now break
                        break

            # Always show the session output after sending input using the counter mechanism
            # Generate unique counter for this session input command
            counter_key = f"session_input_{resolved_session_id}"
            if counter_key not in SESSION_OUTPUT_COUNTER:
                SESSION_OUTPUT_COUNTER[counter_key] = 0
            SESSION_OUTPUT_COUNTER[counter_key] += 1

            # Create args for display
            label = getattr(session, "friendly_id", None) or resolved_session_id
            session_args = {
                "command": command,
                "args": "",
                "session_id": label,
                "call_counter": SESSION_OUTPUT_COUNTER[counter_key],  # This ensures uniqueness
                "input_to_session": True,  # Flag to identify this as session input
            }

            # Only add auto_output if not already present (prevents duplication)
            if args and isinstance(args, dict):
                # If args were passed and contain auto_output, use that value
                if "auto_output" in args:
                    session_args["auto_output"] = args["auto_output"]
                else:
                    # Otherwise, force it to True for session commands
                    session_args["auto_output"] = True
            else:
                # No args provided, force auto_output
                session_args["auto_output"] = True

            # Determine environment info for display
            env_type = "Local"
            if session.container_id:
                env_type = f"Container({session.container_id[:12]})"
            elif session.ctf:
                env_type = "CTF"

            # Get only the NEW output to display (not the entire buffer)
            output = session.get_new_output(mark_position=True)

            # Create execution info
            execution_info = {
                "status": "completed",
                "environment": env_type,
                "host": session.workspace_dir,
                "session_id": label,
                "wait_time": elapsed,
                "new_output_detected": new_output_detected,
            }

            # Display the session input and its result using cli_print_tool_output
            from kryon.util import cli_print_tool_output

            cli_print_tool_output(
                tool_name="run_command",
                args=session_args,
                output=output,
                execution_info=execution_info,
                token_info=_get_agent_token_info(),
                streaming=False,
            )

            # For async sessions, we don't switch back to idle mode here
            # since the session continues to run in the background
            if not async_mode:
                # Switch back to idle mode after synchronous command completes
                stop_active_timer()
                start_idle_timer()

            # Return the actual output from the session
            # The output has already been displayed via cli_print_tool_output
            if output and output.strip():
                return output
            else:
                return f"Command sent to session {label}. No output captured."

        # 2. Determine Execution Environment (Container > CTF > SSH > Local)
        active_container = os.getenv("KRYON_ACTIVE_CONTAINER", "")
        is_ssh_env = all(os.getenv(var) for var in ["SSH_USER", "SSH_HOST"])

        # --- Docker Container Execution ---
        if active_container and not is_ssh_env:
            container_id = active_container
            container_workspace = _get_container_workspace_path()
            context_msg = f"(docker:{container_id[:12]}:{container_workspace})"

            # Handle Async Session Creation in Container
            # Only create new session if no session_id is provided
            if async_mode and not session_id:
                # Create a session specifically for the container environment
                new_session_id = create_shell_session(command, container_id=container_id)  # noqa E501
                if "Failed" in new_session_id:  # Check if session creation failed
                    # Switch back to idle mode before returning error
                    stop_active_timer()
                    start_idle_timer()
                    return new_session_id

                # Display the command that creates the async session
                from kryon.util import cli_print_tool_output

                # Create args for display
                label = getattr(ACTIVE_SESSIONS.get(new_session_id), "friendly_id", None) or new_session_id
                session_creation_args = {
                    "command": command,
                    "args": "",
                    "session_id": label,
                    "async_mode": True,
                }

                # Create execution info
                execution_info = {
                    "status": "session_created",
                    "environment": f"Container({container_id[:12]})",
                    "host": container_workspace,
                    "session_id": label,
                }

                # Get initial output if any
                session = ACTIVE_SESSIONS.get(new_session_id)
                initial_output = ""
                if session:
                    time.sleep(0.2)  # Wait a moment for initial output
                    initial_output = session.get_new_output(mark_position=True)

                # Format the output message
                output_msg = f"Started async session {label} in container {container_id[:12]}. Use this ID to interact."
                if initial_output:
                    output_msg += f"\n\n{initial_output}"

                # Get agent token info
                token_info = _get_agent_token_info()
                # Display the session creation command and initial output
                cli_print_tool_output(
                    tool_name="run_command",
                    args=session_creation_args,
                    output=output_msg,
                    execution_info=execution_info,
                    token_info=token_info,
                    streaming=False,
                )

                # For async sessions, switch back to idle mode after session creation
                stop_active_timer()
                start_idle_timer()
                return f"Started async session {label} in container {container_id[:12]}. Use this ID to interact."  # noqa E501

            # Handle Streaming Container Execution
            if stream:
                # Import the streaming utilities from util
                from kryon.util import (
                    finish_tool_streaming,
                    start_tool_streaming,
                    update_tool_streaming,
                )

                # If args were provided (e.g., from execute_code), use them
                # Otherwise create args dictionary with standardized format
                if args is not None:
                    tool_args = args.copy() if isinstance(args, dict) else {"args": str(args)}
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

                # Add refresh rate info for run_command
                if tool_name == "run_command":
                    tool_args["refresh_rate"] = 2

                # Get token info for agent display
                token_info = _get_agent_token_info()

                # Initialize the streaming session with a consistent call_id format
                call_id = start_tool_streaming(tool_name, tool_args, call_id, token_info)

                # Start with a message indicating execution is starting
                update_tool_streaming(
                    tool_name,
                    tool_args,
                    f"Executing: {command}",  # Show the command being executed
                    call_id,
                    token_info,
                )

                # Ensure workspace directory exists inside the container first
                mkdir_cmd = ["docker", "exec", container_id, "mkdir", "-p", container_workspace]
                subprocess.run(
                    # nosemgrep: dangerous-subprocess-use-tainted-env-args
                    mkdir_cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )  # nosemgrep: dangerous-subprocess-use-tainted-env-args

                # Don't update with output during execution - let the streaming handle it

                # Build docker exec command as a single shell string for streaming
                docker_exec_cmd = (
                    "docker exec -w "
                    f"{shlex.quote(container_workspace)} "
                    f"{shlex.quote(container_id)} sh -c "
                    f"{shlex.quote(command)}"
                )

                try:
                    start_time = time.time()
                    # Start the process
                    process = subprocess.Popen(
                        docker_exec_cmd,
                        shell=True,  # nosec B602  # nosemgrep: subprocess-shell-true
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                        cwd=_get_workspace_dir(),
                    )

                    # Begin collecting output
                    output_buffer = []
                    buffer_size = 0
                    update_interval = 10  # lines

                    # Stream stdout in real-time
                    for line in iter(process.stdout.readline, ""):
                        if not line:
                            break

                        # Add to output collection
                        output_buffer.append(line)
                        buffer_size += 1

                        # Only update periodically to reduce UI refreshes
                        if buffer_size >= update_interval:
                            # Show actual output as it's being collected
                            current_output = "".join(output_buffer)
                            # Get token info for agent display
                            token_info = _get_agent_token_info()
                            update_tool_streaming(tool_name, tool_args, current_output, call_id, token_info)
                            buffer_size = 0

                    # Finish process
                    process.stdout.close()
                    return_code = process.wait(timeout=timeout)
                    execution_time = time.time() - start_time

                    # Get any stderr output
                    stderr_data = process.stderr.read()
                    if stderr_data:
                        output_buffer.append("\nERROR OUTPUT:\n" + stderr_data)

                    # Final output update
                    final_output = "".join(output_buffer)
                    if return_code != 0:
                        final_output += f"\nCommand exited with code {return_code}"

                    # Calculate execution info
                    execution_info = {
                        "status": "completed" if return_code == 0 else "error",
                        "return_code": return_code,
                        "environment": "Container",
                        "host": container_id[:12],
                        "tool_time": execution_time,
                    }

                    # Complete the streaming session with final output
                    finish_tool_streaming(tool_name, tool_args, final_output, call_id, execution_info, token_info)

                    # Switch back to idle mode after streaming command completes
                    stop_active_timer()
                    start_idle_timer()
                    return final_output

                except subprocess.TimeoutExpired as e:
                    # Handle timeout
                    error_output = e.stdout if hasattr(e, "stdout") and e.stdout else str(e)
                    error_msg = f"Command timed out after {timeout} seconds\n{error_output}"

                    execution_info = {
                        "status": "timeout",
                        "environment": "Container",
                        "host": container_id[:12],
                        "error": str(e),
                    }

                    # Complete with timeout error
                    finish_tool_streaming(tool_name, tool_args, error_msg, call_id, execution_info, token_info)

                    # Switch back to idle mode after timeout
                    stop_active_timer()
                    start_idle_timer()
                    # Fallback to local execution on timeout
                    print(
                        color(
                            "Container execution timed out. Attempting execution on host instead.",
                            fg="yellow",
                        )
                    )
                    return _run_local(command, stdout, timeout, False, None, tool_name, _get_workspace_dir(), args)

                except Exception as e:
                    # Handle other errors
                    error_msg = f"Error executing command in container: {str(e)}"

                    execution_info = {
                        "status": "error",
                        "environment": "Container",
                        "host": container_id[:12],
                        "error": str(e),
                    }

                    # Complete with error
                    finish_tool_streaming(tool_name, tool_args, error_msg, call_id, execution_info, token_info)

                    # Switch back to idle mode after error
                    stop_active_timer()
                    start_idle_timer()
                    # Fallback to local execution on error
                    print(
                        color(
                            "Container execution failed. Attempting execution on host instead.",
                            fg="yellow",
                        )
                    )
                    return _run_local(command, stdout, timeout, False, None, tool_name, _get_workspace_dir(), args)

            # Handle Synchronous Execution in Container
            process_start_time = time.time()  # Track execution time
            try:
                # Ensure container workspace exists (best effort)
                # Consider moving this to workspace set/container activation
                mkdir_cmd = ["docker", "exec", container_id, "mkdir", "-p", container_workspace]  # noqa E501
                subprocess.run(mkdir_cmd, capture_output=True, text=True, check=False, timeout=10)  # noqa E501  # nosemgrep: dangerous-subprocess-use-tainted-env-args

                # Construct the docker exec command with workspace context
                cmd_list = [
                    "docker",
                    "exec",
                    "-w",
                    container_workspace,  # Set working directory
                    container_id,
                    "sh",
                    "-c",
                    command,  # Execute command via shell
                ]
                result = subprocess.run(
                    cmd_list,  # nosemgrep: dangerous-subprocess-use-tainted-env-args
                    capture_output=True,
                    text=True,
                    check=False,  # Don't raise exception on non-zero exit
                    timeout=timeout,
                )

                output = result.stdout if result.stdout else result.stderr
                output = output.strip()  # Clean trailing newline

                # In streaming mode, don't print to stdout to avoid duplication
                # The streaming system will handle the display
                if stdout and not stream:
                    print(f"\033[32m{context_msg} $ {command}\n{output}\033[0m")  # noqa E501

                # Check if command failed specifically because container isn't running
                if result.returncode != 0 and "is not running" in result.stderr:
                    print(
                        color(
                            f"{context_msg} Container is not running. Attempting execution on host instead.",
                            fg="yellow",
                        )
                    )  # noqa E501
                    # Switch back to idle mode before fallback execution
                    stop_active_timer()
                    start_idle_timer()
                    # Fallback to local execution, preserving workspace context
                    return _run_local(
                        command,
                        stdout,
                        timeout,
                        stream,
                        call_id,
                        tool_name,
                        _get_workspace_dir(),
                        args,
                    )  # noqa E501

                # Only display panel if NOT streaming
                # When streaming=True, the panel is already shown by the streaming system
                if not stream:
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
                        execution_time = time.time() - process_start_time if "process_start_time" in locals() else 0

                        # Parse command for display
                        parts = command.strip().split(" ", 1)

                        # Generate a unique call_id if not provided
                        if not call_id:
                            cmd_name = parts[0] if parts else "cmd"
                            call_id = f"container_{cmd_name}_{str(uuid.uuid4())[:8]}"

                        execution_info = {
                            "status": "completed" if result.returncode == 0 else "error",
                            "return_code": result.returncode,
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
                            output=output,
                            call_id=call_id,
                            execution_info=execution_info,
                            token_info=token_info,
                            streaming=False,
                        )

                # Switch back to idle mode after command completes
                stop_active_timer()
                start_idle_timer()
                return output  # Return combined stdout/stderr

            except subprocess.TimeoutExpired:
                timeout_msg = "Timeout executing command in container."
                if stdout:
                    print(f"\033[33m{context_msg} $ {command}\nTIMEOUT\033[0m")  # noqa E501
                    print(color("Attempting execution on host instead.", fg="yellow"))
                # Switch back to idle mode before fallback execution
                stop_active_timer()
                start_idle_timer()
                # Fallback to local execution on timeout
                return _run_local(command, stdout, timeout, stream, call_id, tool_name, _get_workspace_dir(), args)  # noqa E501
            except Exception as e:  # pylint: disable=broad-except
                error_msg = f"Error executing command in container: {str(e)}"
                print(color(f"{context_msg} {error_msg}", fg="red"))
                print(color("Attempting execution on host instead.", fg="yellow"))
                # Switch back to idle mode before fallback execution
                stop_active_timer()
                start_idle_timer()
                # Fallback to local execution on other errors
                return _run_local(command, stdout, timeout, stream, call_id, tool_name, _get_workspace_dir(), args)  # noqa E501

        # --- CTF Execution ---

        if ctf and os.getenv("CTF_INSIDE", "True").lower() == "true":
            # If streaming is enabled and we have a call_id, show streaming UI for CTF too
            if stream:
                # Import the streaming utilities from util
                from kryon.util import (
                    finish_tool_streaming,
                    start_tool_streaming,
                    update_tool_streaming,
                )

                # If args were provided (e.g., from execute_code), use them
                # Otherwise create args dictionary with standardized format
                if args is not None:
                    tool_args = args.copy() if isinstance(args, dict) else {"args": str(args)}
                    # Add CTF-specific info
                    tool_args["environment"] = "CTF"
                    tool_args["workspace"] = os.path.basename(_get_workspace_dir())
                    tool_args["full_command"] = command
                else:
                    tool_args = {
                        "command": cmd_name,
                        "args": cmd_args if cmd_args.strip() else "",
                        "full_command": command,
                        "environment": "CTF",
                        "workspace": os.path.basename(_get_workspace_dir()),
                    }

                # Add refresh rate info for run_command
                if tool_name == "run_command":
                    tool_args["refresh_rate"] = 2

                # Get token info for agent display
                token_info = _get_agent_token_info()

                # Initialize the streaming session with a consistent call_id format
                call_id = start_tool_streaming(tool_name, tool_args, call_id, token_info)

                target_dir = _get_workspace_dir()
                # full_command = f"cd '{target_dir}' && {command}"
                full_command = command
                # Update with "executing" status
                update_tool_streaming(
                    tool_name,
                    tool_args,
                    f"Executing in CTF environment: {full_command}\n\nWaiting for response...",
                    call_id,
                    token_info,
                )

                try:
                    # Execute the command and get the output
                    start_time = time.time()
                    output = ctf.get_shell(full_command, timeout=timeout)
                    execution_time = time.time() - start_time

                    # Calculate execution info
                    execution_info = {
                        "status": "completed",
                        "environment": "CTF",
                        "tool_time": execution_time,
                    }

                    # Complete the streaming with final output
                    finish_tool_streaming(tool_name, tool_args, output, call_id, execution_info, token_info)

                    # Switch back to idle mode after CTF command completes
                    stop_active_timer()
                    start_idle_timer()
                    return output

                except Exception as e:
                    # Handle errors in CTF execution
                    error_msg = f"Error executing CTF command: {str(e)}"
                    execution_info = {"status": "error", "environment": "CTF", "error": str(e)}

                    # Complete the streaming with error output
                    finish_tool_streaming(tool_name, tool_args, error_msg, call_id, execution_info, token_info)

                    # Switch back to idle mode after error
                    stop_active_timer()
                    start_idle_timer()
                    return error_msg
            else:
                # Standard non-streaming CTF execution
                result = _run_ctf(ctf, command, stdout, timeout, _get_workspace_dir(), stream)

                # Switch back to idle mode after CTF command completes
                stop_active_timer()
                start_idle_timer()
                return result

        # --- SSH Execution ---
        if is_ssh_env:
            # If streaming is enabled, show streaming UI for SSH too
            if stream:
                # Import the streaming utilities from util
                from kryon.util import (
                    finish_tool_streaming,
                    start_tool_streaming,
                    update_tool_streaming,
                )

                # Add SSH connection info for display
                ssh_user = os.environ.get("SSH_USER", "user")
                ssh_host = os.environ.get("SSH_HOST", "host")
                ssh_connection = f"{ssh_user}@{ssh_host}"

                # If args were provided (e.g., from execute_code), use them
                # Otherwise create args dictionary with standardized format
                if args is not None:
                    tool_args = args.copy() if isinstance(args, dict) else {"args": str(args)}
                    # Add SSH-specific info
                    tool_args["ssh_host"] = ssh_connection
                    tool_args["environment"] = "SSH"
                    tool_args["full_command"] = command
                else:
                    tool_args = {
                        "command": cmd_name,
                        "args": cmd_args if cmd_args.strip() else "",
                        "full_command": command,
                        "ssh_host": ssh_connection,
                        "environment": "SSH",
                    }

                # Add refresh rate info for run_command
                if tool_name == "run_command":
                    tool_args["refresh_rate"] = 2

                # Get token info for agent display
                token_info = _get_agent_token_info()

                # Initialize streaming session with a consistent call_id format
                call_id = start_tool_streaming(tool_name, tool_args, call_id, token_info)

                # Update with "executing" status
                update_tool_streaming(
                    tool_name,
                    tool_args,
                    f"Executing on {ssh_connection}: {command}\n\nWaiting for response...",
                    call_id,
                    token_info,
                )

                try:
                    # Construct SSH command for execution
                    ssh_pass = os.environ.get("SSH_PASS")
                    if ssh_pass:
                        ssh_cmd_list = ["sshpass", "-p", ssh_pass, "ssh", ssh_connection]
                    else:
                        ssh_cmd_list = ["ssh", ssh_connection]
                    ssh_cmd_list.append(command)

                    # Execute the command and get the output
                    start_time = time.time()
                    result = subprocess.run(
                        # nosemgrep: dangerous-subprocess-use-tainted-env-args
                        ssh_cmd_list,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=timeout,
                    )  # nosemgrep: dangerous-subprocess-use-tainted-env-args
                    execution_time = time.time() - start_time

                    # Get command output
                    output = result.stdout if result.stdout else result.stderr

                    # Add SSH connection info to the output for clarity
                    result_with_info = f"Command executed on {ssh_connection}:\n\n{output}"

                    # Determine status based on return code
                    status = "completed" if result.returncode == 0 else "error"

                    # Calculate execution info
                    execution_info = {
                        "status": status,
                        "environment": "SSH",
                        "host": ssh_connection,
                        "return_code": result.returncode,
                        "tool_time": execution_time,
                    }

                    # Get agent token info
                    token_info = _get_agent_token_info()

                    # Complete the streaming with final output
                    finish_tool_streaming(tool_name, tool_args, result_with_info, call_id, execution_info, token_info)

                    # Switch back to idle mode after SSH command completes
                    stop_active_timer()
                    start_idle_timer()
                    return output.strip()

                except subprocess.TimeoutExpired as e:
                    # Handle timeout errors
                    error_output = e.stdout if e.stdout else str(e)
                    error_msg = f"Command timed out after {timeout} seconds\n{error_output}"

                    execution_info = {
                        "status": "timeout",
                        "environment": "SSH",
                        "host": ssh_connection,
                        "error": str(e),
                    }

                    # Get agent token info
                    token_info = _get_agent_token_info()

                    # Complete the streaming with timeout error
                    finish_tool_streaming(tool_name, tool_args, error_msg, call_id, execution_info, token_info)

                    # Switch back to idle mode after timeout
                    stop_active_timer()
                    start_idle_timer()
                    return error_msg

                except Exception as e:
                    # Handle other errors
                    error_msg = f"Error executing SSH command: {str(e)}"

                    execution_info = {
                        "status": "error",
                        "environment": "SSH",
                        "host": ssh_connection,
                        "error": str(e),
                    }

                    # Get agent token info
                    token_info = _get_agent_token_info()

                    # Complete the streaming with error
                    finish_tool_streaming(tool_name, tool_args, error_msg, call_id, execution_info, token_info)

                    # Switch back to idle mode after error
                    stop_active_timer()
                    start_idle_timer()
                    return error_msg
            else:
                # Standard non-streaming SSH execution
                result = _run_ssh(command, stdout, timeout, _get_workspace_dir(), stream)

                # Switch back to idle mode after SSH command completes
                stop_active_timer()
                start_idle_timer()
                return result

        # --- Local Execution (Default Fallback) ---
        # Let _run_local handle determining the host workspace
        # Handle Async Session Creation Locally
        # Only create new session if no session_id is provided
        if async_mode and not session_id:
            # create_shell_session uses _get_workspace_dir() when container_id is None
            new_session_id = create_shell_session(command)
            if isinstance(new_session_id, str) and "Failed" in new_session_id:  # Check failure
                # Switch back to idle mode before returning error
                stop_active_timer()
                start_idle_timer()
                return new_session_id

            # Display the command that creates the async session
            from kryon.util import cli_print_tool_output

            # Retrieve the actual workspace dir the session is using
            session = ACTIVE_SESSIONS.get(new_session_id)
            actual_workspace = session.workspace_dir if session else "unknown"

            # Create args for display
            label = getattr(session, "friendly_id", None) or new_session_id
            session_creation_args = {
                "command": command,
                "args": "",
                "session_id": label,
                "async_mode": True,
            }

            # Create execution info
            execution_info = {
                "status": "session_created",
                "environment": "Local",
                "host": os.path.basename(actual_workspace),
                "session_id": label,
            }

            # Get initial output if any
            initial_output = ""
            if session:
                time.sleep(0.2)  # Allow session buffer to populate
                initial_output = session.get_new_output(mark_position=True)

            # Format the output message
            output_msg = f"Started async session {label} locally. Use this ID to interact."
            if initial_output:
                output_msg += f"\n\n{initial_output}"

            # Display the session creation command and initial output
            cli_print_tool_output(
                tool_name="run_command",
                args=session_creation_args,
                output=output_msg,
                execution_info=execution_info,
                token_info=_get_agent_token_info(),
                streaming=False,
            )

            # For async, switch back to idle mode after session creation
            stop_active_timer()
            start_idle_timer()
            return f"Started async session {label} locally. Use this ID to interact."

        # Handle Synchronous Execution Locally
        # Pass stream parameter as provided (not always True)
        # In parallel mode, stream will be False since Runner.run() is non-streaming
        result = _run_local(
            command,
            stdout,
            timeout,
            stream=stream,  # Use the stream parameter passed to run_command
            call_id=call_id,
            tool_name=tool_name,
            workspace_dir=_get_workspace_dir(),
            custom_args=args,
        )

        stop_active_timer()
        start_idle_timer()
        return result
    except Exception:
        stop_active_timer()
        start_idle_timer()
        raise
