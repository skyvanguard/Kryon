#!/usr/bin/env python3
import json as _json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

import paramiko

from kryon.sdk.agents import function_tool

_SAFE_INTERFACE = re.compile(r'^[a-zA-Z0-9_-]+$')


def _capture_remote_traffic_impl(ip, username, password, interface, capture_filter="", port=22, timeout=10):
    """
    Captures network traffic from a remote VM and returns a FIFO path that can be read by tshark.

    Args:
        ip (str): IP address of the remote VM
        username (str): SSH username for the remote VM
        password (str): SSH password for the remote VM
        interface (str): Network interface to capture on (e.g., eth0)
        capture_filter (str, optional): tcpdump filter expression
        port (int, optional): SSH port (default: 22)
        timeout (int, optional): Connection timeout in seconds (default: 10)

    Returns:
        str: Path to the FIFO that tshark can read from

    Raises:
        ValueError: If interface name contains invalid characters
        ConnectionError: If connection to the remote VM fails
        RuntimeError: If traffic capture fails to start
    """
    if not _SAFE_INTERFACE.match(interface):
        raise ValueError(f"Invalid interface name: {interface}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())
    fifo_path = None
    tmpdir = None

    try:
        print(f"Connecting to {ip}:{port} as {username}...")
        client.connect(ip, port=port, username=username, password=password, timeout=timeout)

        # Verify interface exists
        _, stdout, stderr = client.exec_command(f"ip link show {interface}")
        if stdout.channel.recv_exit_status() != 0:
            error = stderr.read().decode().strip()
            raise RuntimeError(f"Interface {interface} not found: {error}")

        # Check if we have necessary permissions
        _, stdout, stderr = client.exec_command("which tcpdump")
        if stdout.channel.recv_exit_status() != 0:
            raise RuntimeError("tcpdump not found on remote system")

        # Build tcpdump command with filter if provided
        tcpdump_cmd = f"tcpdump -U -i {interface} -w - "
        if capture_filter:
            tcpdump_cmd += f"'{capture_filter}'"

        print(f"Starting capture on {ip}:{interface}...")

        # Start tcpdump process on remote machine and get its output
        stdin, stdout, stderr = client.exec_command(tcpdump_cmd)

        # Check if tcpdump started successfully (non-blocking check)
        time.sleep(1)
        if stdout.channel.exit_status_ready():
            error = stderr.read().decode().strip()
            raise RuntimeError(f"Failed to start tcpdump: {error}")

        # Create a named pipe (FIFO) inside a secure temp directory
        tmpdir = tempfile.mkdtemp()
        fifo_path = os.path.join(tmpdir, "capture.fifo")
        os.mkfifo(fifo_path)

        # Start a process to read from SSH and write to the FIFO
        _fifo_path = fifo_path

        def pipe_ssh_to_fifo():
            try:
                with open(_fifo_path, "wb") as fifo:
                    while True:
                        data = stdout.read(4096)
                        if not data:
                            break
                        fifo.write(data)
                        fifo.flush()
            except (BrokenPipeError, OSError) as e:
                print(f"Error in pipe_ssh_to_fifo: {str(e)}")
            finally:
                print("Closing FIFO due to error or completion.")
                try:
                    client.close()
                except Exception:
                    pass
                # Cleanup FIFO and tmpdir
                try:
                    os.unlink(_fifo_path)
                except OSError:
                    pass
                try:
                    os.rmdir(tmpdir)
                except OSError:
                    pass

        thread = threading.Thread(target=pipe_ssh_to_fifo, daemon=True)
        thread.start()

        print(f"Capture running. Data available at: {fifo_path}")
        print(f"You can now use: tshark -r {fifo_path} -c 100 [options]")

        subprocess.run(["tshark", "-r", fifo_path, "-c", "100"], timeout=300)

        return fifo_path

    except paramiko.AuthenticationException as e:
        raise ConnectionError("Authentication failed. Check username and password.") from e
    except paramiko.SSHException as e:
        raise ConnectionError(f"SSH connection error: {str(e)}") from e
    except TimeoutError as e:
        raise ConnectionError(f"Connection timed out after {timeout} seconds") from e
    except (ConnectionError, RuntimeError, ValueError):
        raise
    except Exception as e:
        raise RuntimeError(f"Unexpected error: {str(e)}") from e
    finally:
        # Ensure SSH client is closed on error paths (thread handles its own cleanup)
        try:
            client.close()
        except Exception:
            pass


@function_tool
def capture_remote_traffic(ip, username, password, interface, capture_filter="", port=22, timeout=10):
    """
    Captures network traffic from a remote VM and returns a pipe that can be read by tshark.

    Args:
        ip (str): IP address of the remote VM
        username (str): SSH username for the remote VM
        password (str): SSH password for the remote VM
        interface (str): Network interface to capture on (e.g., eth0)
        capture_filter (str, optional): tcpdump filter expression
        port (int, optional): SSH port (default: 22)
        timeout (int, optional): Connection timeout in seconds (default: 10)

    Returns:
        str: Path to the FIFO that tshark can read from
    """
    return _capture_remote_traffic_impl(ip, username, password, interface, capture_filter, port, timeout)


@function_tool
def remote_capture_session(ip, username, password, interface, capture_filter="", port=22):
    """
    Start a remote traffic capture session and return the FIFO path.

    Wraps capture_remote_traffic with automatic cleanup on failure.

    Args:
        ip: IP address of the remote VM
        username: SSH username
        password: SSH password
        interface: Network interface to capture on
        capture_filter: Optional tcpdump filter expression
        port: SSH port (default: 22)

    Returns:
        JSON with fifo_path for reading captured traffic
    """
    try:
        fifo_path = _capture_remote_traffic_impl(ip, username, password, interface, capture_filter=capture_filter, port=port)
        return _json.dumps({"success": True, "fifo_path": fifo_path, "ip": ip, "interface": interface})
    except Exception as e:
        return _json.dumps({"success": False, "error": str(e)})


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) < 5:
        print("Usage: capture_traffic.py <ip> <username> <password> <interface> [filter]")
        sys.exit(1)

    ip = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    interface = sys.argv[4]
    capture_filter = sys.argv[5] if len(sys.argv) > 5 else ""

    try:
        fifo_path = _capture_remote_traffic_impl(ip, username, password, interface, capture_filter)
        print(f"Capture running at: {fifo_path}")
        print("Press Ctrl+C to stop the capture")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nCapture stopped")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
