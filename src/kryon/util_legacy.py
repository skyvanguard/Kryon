"""
DEPRECATED: Import from kryon.util package instead.

This file is maintained for backward compatibility only.
All utilities have been moved to the kryon.util package with submodules:
- kryon.util.timing - Timer management
- kryon.util.cost_tracker - Cost tracking
- kryon.util.templates - Prompt loading
- kryon.util.visualization - Agent graph visualization
- kryon.util.message_utils - Message parsing/fixing
- kryon.util.streaming - Rich UI streaming
- kryon.util.ctf - CTF utilities
- kryon.util.thinking - Claude thinking display

Usage:
    # Old way (deprecated):
    from kryon.util_legacy import COST_TRACKER

    # New way (recommended):
    from kryon.util import COST_TRACKER
    # Or more specifically:
    from kryon.util.cost_tracker import COST_TRACKER
"""

import warnings

warnings.warn(
    "Importing from kryon.util_legacy is deprecated. "
    "Import from kryon.util submodules instead (e.g., from kryon.util import COST_TRACKER).",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new package structure for backward compatibility
from kryon.util import *  # noqa: F401, F403
