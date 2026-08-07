"""Shell session management for interactive command execution."""

import os
import platform
import signal
import subprocess  # nosec B404
import threading
import time
import uuid
from collections import deque

# Platform-specific imports
if platform.system() != "Windows":
    import pty

    PTY_AVAILABLE = True
else:
    PTY_AVAILABLE = False

from wasabi import color

from kryon.tools.common._workspace import _get_container_workspace_path, _get_workspace_dir

# Global dictionary to store active sessions
ACTIVE_SESSIONS = {}
_sessions_lock = threading.Lock()

# Friendly IDs for sessions to simplify LLM control
# Maps like S1 -> <real_id> and reverse
FRIENDLY_SESSION_MAP = {}
REVERSE_SESSION_MAP = {}
SESSION_COUNTER = 0

_MAX_SESSIONS = 50

# Global counter for session output commands to ensure they always display
SESSION_OUTPUT_COUNTER = {}


class ShellSession:  # pylint: disable=too-many-instance-attributes
    """Class to manage interactive shell sessions"""

    def __init__(self, command, session_id=None, ctf=None, workspace_dir=None, container_id=None):  # noqa E501
        self.session_id = session_id or str(uuid.uuid4())[:8]
        self.command = command
        self.ctf = ctf
        self.container_id = container_id
        # Determine workspace based on context (container, ctf or local host)
        if self.container_id:
            self.workspace_dir = _get_container_workspace_path()
        elif self.ctf:
            self.workspace_dir = workspace_dir or _get_workspace_dir()
        else:
            self.workspace_dir = _get_workspace_dir()
        self.friendly_id = None  # human-friendly alias like S1
        self.created_at = time.time()
        self.process = None
        self.master = None
        self.slave = None
        self.output_buffer = deque(maxlen=10_000)
        self._buffer_lock = threading.Lock()
        self.is_running = False
        self.last_activity = time.time()

    def start(self):
        """Start the shell session in the appropriate environment.
        Exactly one environment must be chosen to avoid duplicated processes.
        """
        start_message_cmd = self.command

        # --- Start in Container ---
        if self.container_id:
            try:
                if PTY_AVAILABLE:
                    self.master, self.slave = pty.openpty()
                else:
                    # Windows fallback - use PIPE instead of PTY
                    self.master, self.slave = None, subprocess.PIPE
                docker_cmd_list = [
                    "docker",
                    "exec",
                    "-i",
                    "-t",  # allocate a TTY inside the container
                    "-w",
                    self.workspace_dir,
                    self.container_id,
                    "sh",
                    "-c",
                    self.command,
                ]
                popen_kwargs = {
                    "stdin": self.slave,
                    "stdout": self.slave,
                    "stderr": self.slave,
                    "universal_newlines": True,
                }
                # preexec_fn is Unix-only
                if PTY_AVAILABLE:
                    popen_kwargs["preexec_fn"] = os.setsid

                self.process = subprocess.Popen(docker_cmd_list, **popen_kwargs)
                self.is_running = True
                self.output_buffer.append(
                    f"[Session {self.session_id}] Started in container {self.container_id[:12]}: "
                    f"{start_message_cmd} in {self.workspace_dir}"
                )
                threading.Thread(target=self._read_output, daemon=True).start()
                return None
            except Exception as e:
                self.output_buffer.append(f"Error starting container session: {str(e)}")
                self.is_running = False
                return str(e)

        # --- Start in CTF ---
        if self.ctf:
            try:
                self.is_running = True
                self.output_buffer.append(f"[Session {self.session_id}] Started CTF command: {self.command}")
                output = self.ctf.get_shell(self.command)
                if output:
                    self.output_buffer.append(output)
                # CTF "sessions" are request/response; mark as finished
                self.is_running = False
                return None
            except Exception as e:  # pylint: disable=broad-except
                self.output_buffer.append(f"Error executing CTF command: {str(e)}")
                self.is_running = False
                return str(e)

        # --- Start Locally (Host) ---
        try:
            if PTY_AVAILABLE:
                self.master, self.slave = pty.openpty()
            else:
                # Windows fallback - use PIPE instead of PTY
                self.master, self.slave = None, subprocess.PIPE
            popen_kwargs = {
                "shell": True,  # nosec B602
                "stdin": self.slave,
                "stdout": self.slave,
                "stderr": self.slave,
                "cwd": self.workspace_dir,
                "universal_newlines": True,
            }
            # preexec_fn is Unix-only
            if PTY_AVAILABLE:
                popen_kwargs["preexec_fn"] = os.setsid

            self.process = subprocess.Popen(  # pylint: disable=subprocess-popen-preexec-fn
                self.command, **popen_kwargs
            )
            self.is_running = True
            self.output_buffer.append(f"[Session {self.session_id}] Started: {self.command}")
            # Start a thread to read output
            threading.Thread(target=self._read_output, daemon=True).start()
        except Exception as e:  # pylint: disable=broad-except
            self.output_buffer.append(f"Error starting local session: {str(e)}")
            self.is_running = False
            return str(e)

    def _read_output(self):
        """Read output from the process"""
        try:
            while self.is_running and self.master is not None:
                try:
                    # Check if process has exited before reading
                    if self.process and self.process.poll() is not None:
                        self.is_running = False
                        break

                    # Read raw output chunk from PTY (don't require newlines)
                    output = os.read(self.master, 4096).decode("utf-8", errors="replace")

                    if output is not None and output != "":
                        # Append raw chunk so interactive tools (nc, tail -f) show partial states
                        with self._buffer_lock:
                            self.output_buffer.append(output)
                        self.last_activity = time.time()
                    else:
                        # os.read() returned empty. This does NOT necessarily mean
                        # the process itself has exited if self.process.poll() is None.
                        # It might be idle and waiting for input.
                        if self.process and self.process.poll() is None:
                            # Process is alive but PTY read was empty (e.g., idle).
                            pass
                        else:
                            # Process is confirmed dead or no process to check,
                            # and read returned empty. Session is over.
                            self.is_running = False
                            break
                except UnicodeDecodeError:
                    # Handle unicode decode errors gracefully
                    self.output_buffer.append(f"[Session {self.session_id}] Unicode decode error in output\n")
                    continue
                except Exception as read_err:
                    self.output_buffer.append(f"Error reading output buffer: {str(read_err)}\n")
                    self.is_running = False
                    break

                # Add a small sleep to prevent busy-waiting if no output
                if self.is_process_running():
                    time.sleep(0.05)

        except Exception as e:
            self.output_buffer.append(f"Error in read_output loop: {str(e)}")
            self.is_running = False
            return str(e)

    def is_process_running(self):
        """Check if the process is still running"""
        # For CTF or container
        if self.container_id or self.ctf:
            return self.is_running
        # For local host
        if not self.process:
            return False
        return self.process.poll() is None

    def send_input(self, input_data):
        """Send input to the process (local or container)"""
        if not self.is_running:  # For CTF or container
            if self.process and self.process.poll() is None:
                self.is_running = True
            else:  # For local host
                return "Session is not running"

        try:
            # --- Send to CTF ---
            if self.ctf:
                output = self.ctf.get_shell(input_data)
                self.output_buffer.append(output)
                return "Input sent to CTF session"

            # --- Send to Local or Container PTY ---
            if self.master is not None:
                # T4-A2: remember the command so its PTY echo can be stripped from the
                # output the model reads (a PTY echoes stdin back, so without this the
                # model sees its own command line as "output" and misreads results).
                self._last_input = input_data.rstrip()
                input_data_bytes = (input_data.rstrip() + "\n").encode()
                bytes_written = os.write(self.master, input_data_bytes)
                if bytes_written != len(input_data_bytes):
                    self.output_buffer.append(f"[Session {self.session_id}] Warning: Partial input write.")
                self.last_activity = time.time()
                return "Input sent to session"
            else:
                return "Session PTY not available for input"
        except Exception as e:  # pylint: disable=broad-except
            self.output_buffer.append(f"Error sending input: {str(e)}")
            return f"Error sending input: {str(e)}"

    def get_output(self, clear=True):
        """Get and optionally clear the output buffer"""
        with self._buffer_lock:
            output = "\n".join(self.output_buffer)
            if clear:
                self.output_buffer.clear()
        return output

    def get_new_output(self, mark_position=True):
        """Get only new output since last marked position"""
        if not hasattr(self, "_last_output_position"):
            self._last_output_position = 0

        with self._buffer_lock:
            # Get new output since last position
            buf_list = list(self.output_buffer)
            new_output_lines = buf_list[self._last_output_position :]
            new_output = "\n".join(new_output_lines)

            # Update position marker if requested
            if mark_position:
                self._last_output_position = len(buf_list)

        return self._strip_echo(new_output)

    def _strip_echo(self, text: str) -> str:
        """T4-A2: drop the PTY echo of the last-sent command (the first line that
        exactly matches it) so the model doesn't read its own command as output.
        Only the first match is removed — real output that happens to repeat the
        command text is preserved."""
        echo = getattr(self, "_last_input", "")
        if not echo or not text:
            return text
        lines = text.split("\n")
        for i, line in enumerate(lines):
            if line.strip() == echo.strip():
                del lines[i]
                return "\n".join(lines)
        return text

    def terminate(self):
        """Terminate the session"""
        session_id_short = self.session_id[:8]
        termination_message = f"Session {session_id_short} terminated"

        if not self.is_running:
            if self.process and self.process.poll() is None:
                pass  # Process is running, proceed with termination
            else:
                return f"Session {session_id_short} already terminated or finished."

        try:
            self.is_running = False

            if self.process:
                # Try to terminate the process group
                try:
                    pgid = os.getpgid(self.process.pid)
                    os.killpg(pgid, signal.SIGTERM)
                except ProcessLookupError:
                    pass  # Process already gone
                except subprocess.TimeoutExpired:
                    print(
                        color(
                            f"Session {session_id_short} did not terminate gracefully, sending SIGKILL...",
                            fg="yellow",
                        )
                    )  # noqa E501
                    try:
                        if pgid:
                            os.killpg(pgid, signal.SIGKILL)  # Force kill
                        else:
                            self.process.kill()
                    except ProcessLookupError:
                        pass  # Already gone
                    except Exception as kill_err:
                        termination_message = f" (Error during SIGKILL: {kill_err})"
                except Exception as term_err:  # Catch other errors during SIGTERM
                    termination_message = f" (Error during SIGTERM: {term_err})"
                    try:
                        self.process.kill()
                    except Exception:
                        pass  # Ignore nested errors

                # Final check
                if self.process.poll() is None:
                    print(
                        color(
                            f"Session {session_id_short} process {self.process.pid} may still be running after termination attempts.",
                            fg="red",
                        )
                    )  # noqa E501
                    termination_message += " (Warning: Process may still be running)"

            # Clean up PTY resources if they exist
            if self.master:
                try:
                    os.close(self.master)
                except OSError:
                    pass
                self.master = None
            if self.slave:
                try:
                    os.close(self.slave)
                except OSError:
                    pass
                self.slave = None

            return termination_message
        except Exception as e:  # pylint: disable=broad-except
            return f"Error terminating session {session_id_short}: {str(e)}"


def create_shell_session(command, ctf=None, container_id=None, **kwargs):
    """Create a new shell session in the correct workspace/environment."""
    if container_id:
        session = ShellSession(command, ctf=ctf, container_id=container_id)
    else:
        workspace_dir = _get_workspace_dir()
        session = ShellSession(command, ctf=ctf, workspace_dir=workspace_dir)

    session.start()
    if session.is_running or (ctf and not session.is_running):
        # Register session and assign friendly ID
        global SESSION_COUNTER
        with _sessions_lock:
            SESSION_COUNTER += 1
            friendly = f"S{SESSION_COUNTER}"
            session.friendly_id = friendly
            # Evict oldest sessions if at capacity
            while len(ACTIVE_SESSIONS) >= _MAX_SESSIONS:
                oldest_id = next(iter(ACTIVE_SESSIONS))
                oldest = ACTIVE_SESSIONS.pop(oldest_id)
                oldest.terminate()
                old_friendly = REVERSE_SESSION_MAP.pop(oldest_id, None)
                if old_friendly:
                    FRIENDLY_SESSION_MAP.pop(old_friendly, None)
            ACTIVE_SESSIONS[session.session_id] = session
            FRIENDLY_SESSION_MAP[friendly] = session.session_id
            REVERSE_SESSION_MAP[session.session_id] = friendly
        return session.session_id
    else:
        error_msg = session.get_output(clear=True)
        print(color(f"Failed to start session: {error_msg}", fg="red"))
        return f"Failed to start session: {error_msg}"


def list_shell_sessions():
    """List all active shell sessions"""
    result = []
    with _sessions_lock:
        for session_id, session in list(ACTIVE_SESSIONS.items()):
            # Clean up terminated sessions
            if not session.is_running:
                del ACTIVE_SESSIONS[session_id]
                continue

            result.append(
                {
                    "friendly_id": getattr(session, "friendly_id", None),
                    "session_id": session_id,
                    "command": session.command,
                    "running": session.is_running,
                    "last_activity": time.strftime("%H:%M:%S", time.localtime(session.last_activity)),
                }
            )
    return result


def _resolve_session_id(session_identifier):
    """Resolve a session identifier which may be a real ID, a friendly alias (S1/#1/1), or 'last'."""
    if not session_identifier:
        return None
    sid = str(session_identifier).strip()
    # Accept patterns: S1, s1, #1, 1
    key = sid
    if sid.lower() == "last":
        # Return the most recently created active session
        if not ACTIVE_SESSIONS:
            return None
        # Pick by created_at
        latest = None
        latest_t = -1
        for _sid, sess in ACTIVE_SESSIONS.items():
            if hasattr(sess, "created_at") and sess.created_at > latest_t and sess.is_running:
                latest = _sid
                latest_t = sess.created_at
        return latest or next(iter(ACTIVE_SESSIONS.keys()))
    if sid.startswith("#"):
        key = f"S{sid[1:]}"
    elif sid.isdigit():
        key = f"S{sid}"
    elif sid.upper().startswith("S") and sid[1:].isdigit():
        key = sid.upper()
    # Real ID direct
    if sid in ACTIVE_SESSIONS:
        return sid
    # Friendly map
    if key in FRIENDLY_SESSION_MAP:
        return FRIENDLY_SESSION_MAP[key]
    return None


def send_to_session(session_id, input_data):
    """Send input to a specific session"""
    resolved = _resolve_session_id(session_id)
    if not resolved or resolved not in ACTIVE_SESSIONS:
        return f"Session {session_id} not found"

    session = ACTIVE_SESSIONS[resolved]
    return session.send_input(input_data)


def get_session_output(session_id, clear=True, stdout=True):
    """Get output from a specific session"""
    resolved = _resolve_session_id(session_id)
    if not resolved or resolved not in ACTIVE_SESSIONS:
        return f"Session {session_id} not found"

    session = ACTIVE_SESSIONS[resolved]
    output = session.get_output(clear)

    return output


def terminate_session(session_id):
    """Terminate a specific session"""
    resolved = _resolve_session_id(session_id)
    if not resolved or resolved not in ACTIVE_SESSIONS:
        return f"Session {session_id} not found or already terminated."

    session = ACTIVE_SESSIONS[resolved]
    result = session.terminate()
    if resolved in ACTIVE_SESSIONS:
        del ACTIVE_SESSIONS[resolved]
        # Clean friendly maps
        friendly = REVERSE_SESSION_MAP.pop(resolved, None)
        if friendly:
            FRIENDLY_SESSION_MAP.pop(friendly, None)
    return result
