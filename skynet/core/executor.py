"""
Command execution module for Skynet framework.
Handles safe command execution with sandboxing and validation.
"""
import subprocess
import shlex
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from pathlib import Path
import re
from .config import get_config
from .logging import get_logger


@dataclass
class ExecutionResult:
    """Result of a command execution."""
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    command: str
    execution_time: float


class CommandExecutor:
    """Safe command executor with sandboxing capabilities."""

    def __init__(self):
        self.config = get_config()
        self.logger = get_logger()

    def is_command_allowed(self, command: str) -> bool:
        """Check if a command is allowed based on configuration."""
        if not self.config.sandbox_mode:
            return True

        # Extract the base command
        parts = shlex.split(command)
        if not parts:
            return False

        base_command = Path(parts[0]).name

        # Check against whitelist
        return base_command in self.config.allowed_commands

    def validate_command(self, command: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a command for security issues.
        Returns (is_valid, error_message).
        """
        if not command or not command.strip():
            return False, "Empty command"

        # Check for dangerous patterns
        dangerous_patterns = [
            r'rm\s+-rf\s+/',          # Dangerous rm
            r':\(\)\{\s*:\|:&\s*\};:', # Fork bomb
            r'>\s*/dev/sda',           # Overwrite disk
            r'dd\s+if=.*of=/dev/',     # DD to disk
            r'mkfs\.',                  # Format filesystem
            r'wget.*\|\s*sh',          # Download and execute
            r'curl.*\|\s*sh',          # Download and execute
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return False, f"Dangerous pattern detected: {pattern}"

        # Check if command is in whitelist (if sandbox mode is on)
        if not self.is_command_allowed(command):
            parts = shlex.split(command)
            base_cmd = Path(parts[0]).name if parts else "unknown"
            return False, f"Command '{base_cmd}' not in allowed list. Sandbox mode is enabled."

        return True, None

    def execute(
        self,
        command: str,
        timeout: Optional[int] = 300,
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        shell: bool = False
    ) -> ExecutionResult:
        """
        Execute a command safely.

        Args:
            command: Command to execute
            timeout: Timeout in seconds (default: 300)
            cwd: Working directory
            env: Environment variables
            shell: Whether to use shell execution (not recommended)

        Returns:
            ExecutionResult with execution details
        """
        import time

        start_time = time.time()

        # Validate command
        is_valid, error_msg = self.validate_command(command)
        if not is_valid:
            self.logger.error(f"Command validation failed: {error_msg}")
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=f"Command validation failed: {error_msg}",
                exit_code=-1,
                command=command,
                execution_time=0
            )

        self.logger.info(f"Executing command: {command}")

        try:
            # Execute command
            result = subprocess.run(
                command if shell else shlex.split(command),
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
                shell=shell
            )

            execution_time = time.time() - start_time
            success = result.returncode == 0

            if success:
                self.logger.info(f"Command completed successfully in {execution_time:.2f}s")
            else:
                self.logger.warning(f"Command failed with exit code {result.returncode}")

            return ExecutionResult(
                success=success,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                command=command,
                execution_time=execution_time
            )

        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            self.logger.error(f"Command timed out after {timeout}s")
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                exit_code=-1,
                command=command,
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Command execution failed: {e}")
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                command=command,
                execution_time=execution_time
            )

    def execute_script(
        self,
        script_path: Path,
        args: Optional[List[str]] = None,
        timeout: Optional[int] = 300
    ) -> ExecutionResult:
        """Execute a script file."""
        if not script_path.exists():
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=f"Script not found: {script_path}",
                exit_code=-1,
                command=str(script_path),
                execution_time=0
            )

        # Build command
        command_parts = [str(script_path)]
        if args:
            command_parts.extend(args)
        command = " ".join(shlex.quote(part) for part in command_parts)

        return self.execute(command, timeout=timeout)

    def execute_python(
        self,
        code: str,
        timeout: Optional[int] = 300
    ) -> ExecutionResult:
        """Execute Python code safely."""
        command = f"python3 -c {shlex.quote(code)}"
        return self.execute(command, timeout=timeout)

    def test_tool_availability(self, tool_name: str) -> bool:
        """Test if a tool is available in the system."""
        result = self.execute(f"which {tool_name}", timeout=5)
        return result.success

    def get_available_tools(self) -> List[str]:
        """Get list of available security tools."""
        available = []
        for tool in self.config.allowed_commands:
            if self.test_tool_availability(tool):
                available.append(tool)
        return available
