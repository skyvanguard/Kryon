"""
SKYNET - Autonomous Cybersecurity Intelligence System

An advanced framework for building autonomous AI-powered cybersecurity operations.
Inspired by advanced autonomous systems, SKYNET provides state-of-the-art
offensive and defensive security capabilities through intelligent agents.

Version: 1.0.0
Code Name: "Genesis"
"""

__version__ = "1.0.0"
__codename__ = "Genesis"

def is_pentestperf_available():
    """
    Check if pentestperf is available for CTF performance tracking
    """
    try:
        from pentestperf.ctf import CTF  # pylint: disable=import-error,import-outside-toplevel,unused-import  # noqa: E501,F401
    except ImportError:
        return False
    return True


def is_skynet_extensions_report_available():
    """
    Check if SKYNET reporting extensions are available
    """
    try:
        # Legacy support for caiextensions
        from caiextensions.report.common import get_base_instructions  # pylint: disable=import-error,import-outside-toplevel,unused-import  # noqa: E501,F401
        return True
    except ImportError:
        pass

    try:
        from skynetextensions.report.common import get_base_instructions  # pylint: disable=import-error,import-outside-toplevel,unused-import  # noqa: E501,F401
        return True
    except ImportError:
        return False


def is_skynet_extensions_memory_available():
    """
    Check if SKYNET memory extensions are available
    """
    try:
        # Legacy support for caiextensions
        from caiextensions.memory import is_memory_installed  # pylint: disable=import-error,import-outside-toplevel,unused-import  # noqa: E501,F401
        return True
    except ImportError:
        pass

    try:
        from skynetextensions.memory import is_memory_installed  # pylint: disable=import-error,import-outside-toplevel,unused-import  # noqa: E501,F401
        return True
    except ImportError:
        return False


def is_skynet_extensions_platform_available():
    """
    Check if SKYNET platform extensions are available
    """
    try:
        # Legacy support for caiextensions
        from caiextensions.platform.base import platform_manager  # pylint: disable=import-error,import-outside-toplevel,unused-import  # noqa: E501,F401
        return True
    except ImportError:
        pass

    try:
        from skynetextensions.platform.base import platform_manager  # pylint: disable=import-error,import-outside-toplevel,unused-import  # noqa: E501,F401
        return True
    except ImportError:
        return False


# Legacy aliases for backward compatibility
is_caiextensions_report_available = is_skynet_extensions_report_available
is_caiextensions_memory_available = is_skynet_extensions_memory_available
is_caiextensions_platform_available = is_skynet_extensions_platform_available
