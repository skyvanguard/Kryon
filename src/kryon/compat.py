"""
Compatibility utilities for optional KRYON features.
"""


def is_pentestperf_available() -> bool:
    """Check if PentestPerf integration is available."""
    try:
        import pentestperf  # noqa: F401

        return True
    except ImportError:
        return False


def is_kryon_extensions_platform_available() -> bool:
    """Check if KRYON platform extensions are available."""
    try:
        import skynetextensions.platform  # noqa: F401

        return True
    except ImportError:
        return False
