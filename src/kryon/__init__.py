"""
KRYON - Self-Improving Autonomous Cybersecurity Platform

An autonomous cybersecurity platform that learns from every engagement.
Features dynamic skill system, self-improving loop with experience recall,
context management, and 204+ security tools. Optimized for local LLMs
via Ollama (Gemma 4 26B MoE recommended).

Version: 2.0.0
Code Name: "Hydra"

Website: https://kryon.com.py
"""

__version__ = "2.0.0"
__codename__ = "Hydra"

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
