"""
Exit command for KRYON REPL.
This module provides the command to exit the REPL.
"""

import sys
from typing import Optional

from kryon.repl.commands.base import Command, register_command
from kryon.sdk.agents.global_usage_tracker import GLOBAL_USAGE_TRACKER


class ExitCommand(Command):
    """Command for exiting the REPL."""

    def __init__(self):
        """Initialize the exit command."""
        super().__init__(name="/exit", description="Exit the KRYON REPL", aliases=["/q", "/quit"])

    def handle(self, args: Optional[list[str]] = None) -> bool:
        """Handle the exit command."""
        GLOBAL_USAGE_TRACKER.end_session()
        sys.exit(0)


# Register the command
register_command(ExitCommand())
