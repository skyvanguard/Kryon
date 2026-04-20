"""
Commands module for KRYON REPL.
This module exports all commands available
in the KRYON REPL.
"""

# Import all command modules
# These imports will register the commands with the registry
from kryon.repl.commands import (  # pylint: disable=import-error,unused-import,line-too-long,redefined-builtin # noqa: E501,F401
    agent,
    allow,  # /allow — F10.1 per-engagement allow-list
    compact,  # Add the compact command
    config,
    corpus,   # /corpus — inspect the CVE-with-diff corpus (F4.5)
    dry_run,  # /dry-run — toggle simulation of destructive commands
    env,
    exit,
    experiences,  # Add the experiences command (self-improving loop)
    findings,  # Add the findings command
    flush,
    graph,
    help,
    history,
    hunt,  # /hunt — 0-day hunter swarm (F3.8)
    kill,
    load,
    mcp,  # Add the MCP command
    memory,  # Add the memory command
    merge,  # Add the merge command (alias for /parallel merge)
    model,
    parallel,  # Add the new parallel command
    platform,
    quickstart,  # Add the quickstart command
    run,  # Add the run command for parallel mode
    shell,
    skill,  # /skill — on-demand skill management
    virtualization,
    webpentest,  # /webpentest — F61 end-to-end web pentest engagement
    workspace,
)

# Import base command structure
from kryon.repl.commands.base import (
    COMMAND_ALIASES,
    COMMANDS,
    Command,
    get_command,
    handle_command,
    register_command,
)
from kryon.repl.commands.completer import FuzzyCommandCompleter

# Define helper functions


def get_command_descriptions() -> dict[str, str]:
    """Get descriptions for all commands.

    Returns:
        A dictionary mapping command names to descriptions
    """
    return {cmd.name: cmd.description for cmd in COMMANDS.values()}


def get_subcommand_descriptions() -> dict[str, str]:
    """Get descriptions for all subcommands.

    Returns:
        A dictionary mapping command paths to descriptions
    """
    descriptions = {}
    for cmd in COMMANDS.values():
        for subcmd in cmd.get_subcommands():
            key = f"{cmd.name} {subcmd}"
            descriptions[key] = cmd.get_subcommand_description(subcmd)
    return descriptions


def get_all_commands() -> dict[str, list[str]]:
    """Get all commands and their subcommands.

    Returns:
        A dictionary mapping command names to lists of subcommand names
    """
    return {cmd.name: cmd.get_subcommands() for cmd in COMMANDS.values()}


# Import the command completer after defining the helper functions

# Export command registry
__all__ = [
    "Command",
    "COMMANDS",
    "COMMAND_ALIASES",
    "register_command",
    "get_command",
    "handle_command",
    "get_command_descriptions",
    "get_subcommand_descriptions",
    "get_all_commands",
    "FuzzyCommandCompleter",
]
