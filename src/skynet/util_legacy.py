"""
DEPRECATED: Import from skynet.util package instead.

This file is maintained for backward compatibility only.
All utilities have been moved to the skynet.util package with submodules:
- skynet.util.timing - Timer management
- skynet.util.cost_tracker - Cost tracking
- skynet.util.templates - Prompt loading
- skynet.util.visualization - Agent graph visualization
- skynet.util.message_utils - Message parsing/fixing
- skynet.util.streaming - Rich UI streaming
- skynet.util.ctf - CTF utilities
- skynet.util.thinking - Claude thinking display

Usage:
    # Old way (deprecated):
    from skynet.util_legacy import COST_TRACKER

    # New way (recommended):
    from skynet.util import COST_TRACKER
    # Or more specifically:
    from skynet.util.cost_tracker import COST_TRACKER
"""

import warnings

warnings.warn(
    "Importing from skynet.util_legacy is deprecated. "
    "Import from skynet.util submodules instead (e.g., from skynet.util import COST_TRACKER).",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the new package structure for backward compatibility
from skynet.util import *  # noqa: F401, F403
