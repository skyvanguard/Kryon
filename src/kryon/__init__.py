"""
KRYON - Autonomous Cybersecurity Intelligence Platform

An advanced framework for building autonomous AI-powered cybersecurity operations.
KRYON provides state-of-the-art offensive and defensive security capabilities
through intelligent agents powered by 300+ LLM models.

Version: 1.1.0
Code Name: "Genesis"

Website: https://kryon.com.py
"""

__version__ = "1.1.0"
__codename__ = "Genesis"

# Import submodules for proper namespace resolution
from kryon import repl as repl


def is_pentestperf_available():
    """
    Check if pentestperf is available for CTF performance tracking
    """
    try:
        from pentestperf.ctf import (
            CTF,  # pylint: disable=import-error,import-outside-toplevel,unused-import  # noqa: E501,F401
        )
    except ImportError:
        return False
    return True


def is_kryon_extensions_report_available():
    """
    Check if KRYON reporting extensions are available
    """
    try:
        from kryonextensions.report.common import (
            get_base_instructions,  # pylint: disable=import-error,import-outside-toplevel,unused-import  # noqa: E501,F401
        )

        return True
    except ImportError:
        return False


def is_kryon_extensions_memory_available():
    """
    Check if KRYON memory extensions are available
    """
    try:
        from kryonextensions.memory import (
            is_memory_installed,  # pylint: disable=import-error,import-outside-toplevel,unused-import  # noqa: E501,F401
        )

        return True
    except ImportError:
        return False


def is_kryon_extensions_platform_available():
    """
    Check if KRYON platform extensions are available
    """
    try:
        from kryonextensions.platform.base import (
            platform_manager,  # pylint: disable=import-error,import-outside-toplevel,unused-import  # noqa: E501,F401
        )

        return True
    except ImportError:
        return False
