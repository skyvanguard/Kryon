"""
Compatibility utilities for optional SKYNET features.
"""


def is_pentestperf_available() -> bool:
    """Check if PentestPerf integration is available."""
    try:
        import pentestperf  # noqa: F401

        return True
    except ImportError:
        return False


def is_skynet_extensions_platform_available() -> bool:
    """Check if SKYNET platform extensions are available."""
    try:
        import skynetextensions.platform  # noqa: F401

        return True
    except ImportError:
        return False
