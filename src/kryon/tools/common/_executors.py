"""Command execution functions for different environments (local, CTF, SSH, Docker)."""

import os
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


def _run_ctf(ctf, command, stdout=False, timeout=100, workspace_dir=None, stream=False):
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


def _run_ssh(command, stdout=False, timeout=100, workspace_dir=None, stream=False):
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


async def _run_local_async(
    command,
    stdout=False,
    timeout=100,
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

            # Start the async process
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=target_dir,
            )

            # Begin collecting output
            output_buffer = []
            buffer_size = 0
            update_interval = 10  # lines - default for most tools

            # Use a smaller interval for run_command for better responsiveness
            if tool_name == "run_command":
                update_interval = 3  # Update more frequently for terminal commands

                # Don't add refresh_rate to tool_args as it affects command deduplication
                # The refresh behavior is already handled by the streaming update logic

            # Stream stdout in real-time
            async for line in process.stdout:
                line_str = line.decode("utf-8", errors="replace")

                # Add to output collection
                output_buffer.append(line_str)
                buffer_size += 1

                # Only update periodically to reduce UI refreshes
                if buffer_size >= update_interval:
                    current_output = "".join(output_buffer)
                    update_tool_streaming(tool_name, tool_args, current_output, call_id, token_info)
                    buffer_size = 0

            # Wait for process to complete with timeout
            try:
                return_code = await asyncio.wait_for(process.wait(), timeout=timeout)
            except asyncio.TimeoutError as e:
                process.kill()
                await process.wait()
                raise subprocess.TimeoutExpired(command, timeout) from e

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
            # Standard non-streaming async execution
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=target_dir,
            )

            try:
                stdout_data, stderr_data = await asyncio.wait_for(process.communicate(), timeout=timeout)
            except asyncio.TimeoutError as e:
                process.kill()
                await process.wait()
                raise subprocess.TimeoutExpired(command, timeout) from e

            # Decode output
            output = stdout_data.decode("utf-8", errors="replace") if stdout_data else ""
            if not output and stderr_data:
                output = stderr_data.decode("utf-8", errors="replace")

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
    timeout=100,
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
            update_interval = 3 if tool_name == "run_command" else 10

            start_time = time.time()

            # Read stdout line by line
            async for line in process.stdout:
                line_str = line.decode("utf-8", errors="replace")
                output_buffer.append(line_str)
                buffer_size += 1

                # Only update periodically to reduce UI refreshes
                if buffer_size >= update_interval:
                    # Show actual output as it's being collected
                    current_output = "".join(output_buffer)
                    update_tool_streaming(tool_name, tool_args, current_output, call_id, token_info)
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
    timeout=100,
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
            update_interval = 10  # lines - default for most tools

            # Use a smaller interval for run_command for better responsiveness
            if tool_name == "run_command":
                update_interval = 3  # Update more frequently for terminal commands

                # Don't add refresh_rate to tool_args as it affects command deduplication
                # The refresh behavior is already handled by the streaming update logic

            # Stream stdout in real-time
            for line in iter(process.stdout.readline, ""):
                if not line:
                    break

                # Add to output collection
                output_buffer.append(line)
                buffer_size += 1

                # Only update periodically to reduce UI refreshes
                if buffer_size >= update_interval:
                    current_output = "".join(output_buffer)
                    update_tool_streaming(tool_name, tool_args, current_output, call_id, token_info)
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
            output = result.stdout if result.stdout else result.stderr

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
