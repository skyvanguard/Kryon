"""
SKYNET Compatibility Layer

Legacy CAI compatibility for smooth migration from CAI to SKYNET.
This module provides backward compatibility for old CAI imports and functions.

Clearance Level: System-Core
Mission: Maintain backward compatibility during transition period
"""

import importlib
from typing import Any, Optional


def is_pentestperf_available() -> bool:
    """
    Check if pentestperf module is available.

    Legacy compatibility for: from cai import is_pentestperf_available

    Returns:
        True if pentestperf is available, False otherwise

    Example:
        >>> from skynet.compat import is_pentestperf_available
        >>> if is_pentestperf_available():
        ...     print("PentestPerf available")
    """
    try:
        importlib.import_module("skynet.pentestperf")
        return True
    except (ImportError, ModuleNotFoundError):
        try:
            # Try old cai module for backward compatibility
            importlib.import_module("cai.pentestperf")
            return True
        except (ImportError, ModuleNotFoundError):
            return False


def is_caiextensions_platform_available() -> bool:
    """
    Check if caiextensions platform module is available.

    Legacy compatibility for: from cai import is_caiextensions_platform_available

    Note: caiextensions is an optional external dependency that provides
    platform-specific integrations (e.g., HackTheBox, TryHackMe, etc.)

    Returns:
        True if caiextensions.platform is available, False otherwise

    Example:
        >>> from skynet.compat import is_caiextensions_platform_available
        >>> if is_caiextensions_platform_available():
        ...     from caiextensions.platform.base import platform_manager
    """
    try:
        importlib.import_module("caiextensions.platform")
        return True
    except (ImportError, ModuleNotFoundError):
        return False


def get_legacy_module(module_name: str) -> Optional[Any]:
    """
    Import legacy CAI module with fallback to SKYNET.

    Args:
        module_name: Module name (e.g., 'cai.internal.components.metrics')

    Returns:
        Imported module or None if not found

    Example:
        >>> module = get_legacy_module('cai.internal.components.metrics')
        >>> if module:
        ...     # Use module
    """
    # Try SKYNET version first
    skynet_name = module_name.replace("cai.", "skynet.")
    try:
        return importlib.import_module(skynet_name)
    except (ImportError, ModuleNotFoundError):
        pass

    # Fallback to original CAI name
    try:
        return importlib.import_module(module_name)
    except (ImportError, ModuleNotFoundError):
        return None


# Migration helpers
CAI_TO_SKYNET_MAPPING = {
    "cai": "skynet",
    "cai.agents": "skynet.agents",
    "cai.tools": "skynet.tools",
    "cai.internal": "skynet.internal",
    "cai.repl": "skynet.repl",
    "cai.sdk": "skynet.sdk",
}


def migrate_import(old_import: str) -> str:
    """
    Convert old CAI import to new SKYNET import.

    Args:
        old_import: Old import string (e.g., 'from cai.tools import X')

    Returns:
        New import string (e.g., 'from skynet.tools import X')

    Example:
        >>> migrate_import('from cai.tools.anonymity import setup_tor')
        'from skynet.tools.anonymity import setup_tor'
    """
    result = old_import
    for old, new in CAI_TO_SKYNET_MAPPING.items():
        result = result.replace(old, new)
    return result


# Environment variable compatibility
def get_env_var(key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Get environment variable with CAI/SKYNET compatibility.

    Checks both SKYNET_* and legacy CAI_* environment variables.

    Args:
        key: Variable name (without prefix)
        default: Default value if not found

    Returns:
        Environment variable value or default

    Example:
        >>> api_key = get_env_var('API_KEY')
        >>> # Checks: SKYNET_API_KEY, then CAI_API_KEY
    """
    import os

    # Try SKYNET prefix first
    skynet_key = f"SKYNET_{key}"
    value = os.getenv(skynet_key)
    if value is not None:
        return value

    # Fallback to CAI prefix
    cai_key = f"CAI_{key}"
    value = os.getenv(cai_key)
    if value is not None:
        return value

    return default


# Path compatibility
def get_config_dir() -> str:
    """
    Get configuration directory with migration from CAI to SKYNET.

    Returns:
        Configuration directory path

    Behavior:
        1. Checks for ~/.skynet/ directory
        2. If not found, checks for ~/.cai/ directory
        3. Creates ~/.skynet/ if neither exists

    Example:
        >>> config_dir = get_config_dir()
        >>> # Returns: ~/.skynet/ (preferred) or ~/.cai/ (legacy)
    """
    from pathlib import Path

    home = Path.home()

    # Preferred SKYNET directory
    skynet_dir = home / ".skynet"
    if skynet_dir.exists():
        return str(skynet_dir)

    # Legacy CAI directory
    cai_dir = home / ".cai"
    if cai_dir.exists():
        # TODO: Consider migrating .cai to .skynet automatically
        return str(cai_dir)

    # Create new SKYNET directory
    skynet_dir.mkdir(parents=True, exist_ok=True)
    return str(skynet_dir)


def get_workspace_dir() -> str:
    """
    Get workspace directory with CAI/SKYNET compatibility.

    Returns:
        Workspace directory path
    """
    from pathlib import Path

    # Check environment variables
    workspace = get_env_var("WORKSPACE")
    if workspace:
        return workspace

    # Use config directory
    config_dir = get_config_dir()
    workspace_dir = Path(config_dir) / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    return str(workspace_dir)


# Version information
__version__ = "1.0.0"
__legacy_version__ = "cai-compatible"


def print_migration_notice():
    """Print migration notice for users still using CAI references."""
    print("""
╔════════════════════════════════════════════════════════════════╗
║  SKYNET COMPATIBILITY MODE                                     ║
╚════════════════════════════════════════════════════════════════╝

You are using legacy CAI imports. Please update to SKYNET imports:

  OLD: from cai import is_pentestperf_available
  NEW: from skynet.compat import is_pentestperf_available

  OLD: from cai.tools.anonymity import setup_tor
  NEW: from skynet.tools.anonymity import setup_tor

For automatic migration, run:
  python -m skynet.compat.migrate /path/to/your/code

════════════════════════════════════════════════════════════════
""")


# Export all compatibility functions
__all__ = [
    "is_pentestperf_available",
    "is_caiextensions_platform_available",
    "get_legacy_module",
    "migrate_import",
    "get_env_var",
    "get_config_dir",
    "get_workspace_dir",
    "print_migration_notice",
    "CAI_TO_SKYNET_MAPPING",
]
