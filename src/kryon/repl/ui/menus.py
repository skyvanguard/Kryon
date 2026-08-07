"""
Interactive menu utilities for the KRYON REPL.

Uses questionary for rich interactive selection menus.
All functions gracefully degrade when questionary is not installed.
"""

from typing import Any


def is_interactive_available() -> bool:
    """Check if questionary is installed and available."""
    try:
        import questionary  # noqa: F401

        return True
    except ImportError:
        return False


def select_agent_interactive(
    agents: dict[str, Any],
    current_agent: str | None = None,
) -> str | None:
    """Show an interactive menu to select an agent.

    Args:
        agents: Dict of agent_key -> agent object.
        current_agent: Key of the currently active agent.

    Returns:
        Selected agent key, or None if cancelled / unavailable.
    """
    if not is_interactive_available():
        return None

    import questionary
    from questionary import Style

    choices = []
    for key, agent in agents.items():
        name = getattr(agent, "name", key)
        description = ""
        if hasattr(agent, "instructions") and isinstance(agent.instructions, str):
            description = agent.instructions[:80].replace("\n", " ")
        elif hasattr(agent, "description"):
            description = str(getattr(agent, "description", ""))[:80]

        marker = " *" if key == current_agent else ""
        label = f"{name}{marker} — {description}" if description else f"{name}{marker}"
        choices.append(questionary.Choice(title=label, value=key))

    kryon_style = Style(
        [
            ("qmark", "fg:cyan bold"),
            ("question", "bold"),
            ("pointer", "fg:cyan bold"),
            ("highlighted", "fg:green bold"),
            ("selected", "fg:green"),
            ("answer", "fg:green bold"),
        ]
    )

    try:
        result = questionary.select(
            "Select an agent:",
            choices=choices,
            style=kryon_style,
            use_shortcuts=False,
        ).ask()
        return result
    except (KeyboardInterrupt, EOFError):
        return None


def select_from_list(
    title: str,
    options: list[dict[str, str]],
) -> str | None:
    """Generic interactive list selection.

    Args:
        title: Prompt message.
        options: List of dicts with 'label' and 'value' keys.

    Returns:
        Selected value, or None if cancelled / unavailable.
    """
    if not is_interactive_available():
        return None

    import questionary
    from questionary import Style

    choices = [questionary.Choice(title=opt["label"], value=opt["value"]) for opt in options]

    kryon_style = Style(
        [
            ("qmark", "fg:cyan bold"),
            ("question", "bold"),
            ("pointer", "fg:cyan bold"),
            ("highlighted", "fg:green bold"),
            ("selected", "fg:green"),
        ]
    )

    try:
        return questionary.select(title, choices=choices, style=kryon_style).ask()
    except (KeyboardInterrupt, EOFError):
        return None


def confirm_action(message: str, default: bool = False) -> bool:
    """Interactive yes/no confirmation.

    Args:
        message: The question to ask.
        default: Default answer if user just presses Enter.

    Returns:
        True/False. Returns *default* if questionary is unavailable.
    """
    if not is_interactive_available():
        return default

    import questionary

    try:
        result = questionary.confirm(message, default=default).ask()
        return result if result is not None else default
    except (KeyboardInterrupt, EOFError):
        return default


def text_input(message: str, default: str = "") -> str | None:
    """Interactive text input.

    Args:
        message: Prompt message.
        default: Default text.

    Returns:
        User input string, or None if cancelled / unavailable.
    """
    if not is_interactive_available():
        return None

    import questionary

    try:
        return questionary.text(message, default=default).ask()
    except (KeyboardInterrupt, EOFError):
        return None
