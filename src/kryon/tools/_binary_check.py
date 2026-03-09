"""Centralized binary availability check for external tools."""

from __future__ import annotations

import shutil


def require_binary(name: str) -> str:
    """Verify that an external binary is available on PATH.

    Args:
        name: The binary name (e.g. "nmap", "sqlmap", "nuclei").

    Returns:
        Absolute path to the binary.

    Raises:
        FileNotFoundError: If the binary is not found, with install hints.
    """
    path = shutil.which(name)
    if path is None:
        raise FileNotFoundError(
            f"Required binary '{name}' not found on PATH. "
            f"Install it (e.g. 'apt install {name}' or 'brew install {name}') and retry."
        )
    return path
