"""
Module for displaying the KRYON banner and system initialization message.

██╗  ██╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗
██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║
█████╔╝ ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║
██╔═██╗ ██╔══██╗  ╚██╔╝  ██║   ██║██║╚██╗██║
██║  ██╗██║  ██║   ██║   ╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
"""

# Standard library imports
import glob
import logging
import os
import sys
from pathlib import Path

# Configure UTF-8 encoding for Windows console
if sys.platform == "win32":
    try:
        # Enable UTF-8 mode for Windows console
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleOutputCP(65001)  # UTF-8 code page
        kernel32.SetConsoleCP(65001)  # Input code page
        # Set stdout to use UTF-8
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        # Also set environment variable for Python
        os.environ["PYTHONIOENCODING"] = "utf-8"
    except Exception:
        pass  # Ignore if we can't set UTF-8

# Third-party imports
import requests  # pylint: disable=import-error
from rich.console import Console  # pylint: disable=import-error
from rich.panel import Panel  # pylint: disable=import-error
from rich.table import Table  # pylint: disable=import-error

# For reading TOML files
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        # If tomli is not available, we'll handle it in the get_version function
        pass


def get_version():
    """Get the KRYON version from installed package metadata or pyproject.toml."""
    # 1. Try importlib.metadata (works when package is installed)
    try:
        from importlib.metadata import version as pkg_version

        return pkg_version("kryon")
    except Exception:
        pass

    # 2. Fallback: read pyproject.toml using absolute path
    pyproject_path = Path(__file__).resolve().parent.parent.parent.parent / "pyproject.toml"
    try:
        if sys.version_info >= (3, 11):
            toml_parser = tomllib
        else:
            try:
                import tomli as toml_parser
            except ImportError:
                with open(pyproject_path, encoding="utf-8") as f:
                    for line in f:
                        if line.strip().startswith("version = "):
                            return line.split("=")[1].strip().strip("\"'")
                return "1.0.0"

        with open(pyproject_path, "rb") as f:
            config = toml_parser.load(f)
        return config.get("project", {}).get("version", "1.0.0")
    except Exception:
        return "1.0.0"


def get_supported_models_count():
    """Get the count of supported models (with function calling)."""
    try:
        # Fetch model data from LiteLLM repository
        response = requests.get(
            "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json",
            timeout=2,
        )

        if response.status_code == 200:
            model_data = response.json()

            # Count models with function calling support
            function_calling_models = sum(
                1 for model_info in model_data.values() if model_info.get("supports_function_calling", False)
            )

            return function_calling_models
    except Exception:  # pylint: disable=broad-except
        logging.warning("Could not fetch model data from LiteLLM")

    # Default count if we can't fetch the data
    return "many"


def count_tools():
    """Count the number of tools in the KRYON arsenal."""
    try:
        # Count Python files in the tools directory
        tool_files = glob.glob("kryon/tools/**/*.py", recursive=True)
        # Exclude __init__.py and other non-tool files
        tool_files = [f for f in tool_files if not f.endswith("__init__.py") and not f.endswith("__pycache__")]
        return len(tool_files)
    except Exception:  # pylint: disable=broad-except
        logging.warning("Could not count tools")
        return "50+"


def count_agents():
    """Count the number of active agents in KRYON."""
    try:
        # Count Python files in the agents directory
        agent_files = glob.glob("kryon/agents/**/*.py", recursive=True)
        # Exclude __init__.py and other non-agent files
        agent_files = [f for f in agent_files if not f.endswith("__init__.py") and not f.endswith("__pycache__")]
        return len(agent_files)
    except Exception:  # pylint: disable=broad-except
        logging.warning("Could not count agents")
        return "20+"


def count_mission_logs():
    """Count the number of mission logs in KRYON intelligence database."""
    # This is a placeholder - adjust the actual counting logic based on your
    # framework structure
    return "100+"


def _full_banner_enabled() -> bool:
    """The legacy ASCII-art banner is opt-in. Default = compact 3-line."""
    val = os.environ.get("KRYON_FULL_BANNER", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def _external_llm_warning() -> list:
    """Banner fragments that warn the operator when LLM inference is
    routed to a third-party endpoint (DeepSeek, OpenAI, OpenRouter, etc).

    Returns a list of (text, style) tuples ready to be spread into a
    Text.assemble() call. Empty list when running against a local
    endpoint (llama-server) or no configured endpoint — no warning needed.
    """
    base_url = os.getenv("OPENAI_BASE_URL", "").lower()
    if not base_url:
        return []
    # Local endpoints don't warrant a warning
    if any(local in base_url for local in ("localhost", "127.0.0.1", "11434")):
        return []
    # Anything else is external — warn loudly
    return [
        ("⚠️  WARNING: LLM inference routed to external provider.\n", "bold yellow on red"),
        (f"   Endpoint: {os.getenv('OPENAI_BASE_URL', '')}\n", "yellow"),
        ("   Do not include client PAN, credentials, or PII in prompts.\n", "yellow"),
        ("   Get explicit written authorization before bank engagements.\n\n", "yellow"),
    ]


def _display_compact_banner(console: Console, version: str, codename: str) -> None:
    """Tight 3-line banner with palette B accents.

    Replaces ~12 lines of ASCII art that ran on every startup. The full
    art is still available via `KRYON_FULL_BANNER=1` for those who like
    the classic look.
    """
    console.print(f"[bold cyan]KRYON[/bold cyan] [dim cyan]v{version} — {codename}[/dim cyan]")
    console.print("[dim]autonomous cybersecurity agent for financial services · all actions logged[/dim]")
    console.print("[dim cyan]/help · /skill list · /agent select · Ctrl+C interrupt · /exit[/dim cyan]")


def display_banner(console: Console):
    """
    Display KRYON initialization banner.

    Default: compact 3-line banner (palette B). The legacy ASCII art
    banner is opt-in via `KRYON_FULL_BANNER=1` — useful for screencasts
    or first-time intros, noisy in everyday use.

    Args:
        console: Rich console for output
    """
    version = get_version()
    import kryon

    codename = getattr(kryon, "__codename__", "Genesis")

    # Default path: compact banner. Opt out for the legacy art.
    if not _full_banner_enabled():
        try:
            _display_compact_banner(console, version, codename)
            return
        except Exception:
            pass  # Fall through to legacy banner

    # KRYON banner with indigo/cyan cyber theme (Unicode)
    banner_unicode = f"""
[bold blue]    ██╗  ██╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗
[bold blue]    ██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║
[bold blue]    █████╔╝ ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║
[bold cyan]    ██╔═██╗ ██╔══██╗  ╚██╔╝  ██║   ██║██║╚██╗██║
[bold cyan]    ██║  ██╗██║  ██║   ██║   ╚██████╔╝██║ ╚████║
[bold cyan]    ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝

[bold blue]           Autonomous Cybersecurity Intelligence Platform
[bold white]                    Version {version} - Code: {codename}
[dim cyan]                    [ Defense Grid Activated ][/dim cyan]

[dim blue]    +-----------------------------------------------------------+
    |  [bold]KRYON:[/bold] Autonomous AI system active                     |
    |  System designed for authorized security operations      |
    |  All actions are logged and monitored                    |
    +-----------------------------------------------------------+[/dim blue]
    """

    # ASCII fallback banner for terminals that don't support Unicode
    banner_ascii = f"""
[bold blue]    _  __ ____  __   __  ___  _   _
[bold blue]   | |/ /|  _ \\ \\ \\ / / / _ \\| \\ | |
[bold blue]   | ' / | |_) | \\ V / | | | |  \\| |
[bold cyan]   |  <  |  _ <   | |  | | | | . ` |
[bold cyan]   | . \\ | | \\ \\  | |  | |_| | |\\  |
[bold cyan]   |_|\\_\\|_|  \\_\\ |_|   \\___/|_| \\_|

[bold blue]           Autonomous Cybersecurity Intelligence Platform
[bold white]                    Version {version} - Code: {codename}
[dim cyan]                    [ Defense Grid Activated ][/dim cyan]

[dim blue]    +-----------------------------------------------------------+
    |  KRYON: Autonomous AI system active                       |
    |  System designed for authorized security operations       |
    |  All actions are logged and monitored                     |
    +-----------------------------------------------------------+[/dim blue]
    """

    # Detect if we're on Windows with a legacy console
    use_ascii = sys.platform == "win32"

    # Try Unicode first on non-Windows, or if Windows Terminal is detected
    if not use_ascii or os.environ.get("WT_SESSION"):
        try:
            console.print(banner_unicode, end="")
            return
        except (UnicodeEncodeError, UnicodeDecodeError, Exception):
            pass  # Fall through to ASCII

    # Use ASCII fallback
    try:
        console.print(banner_ascii, end="")
    except Exception:
        # Last resort: plain text
        print(f"\n    KRYON v{version} - {codename}")
        print("    Autonomous Cybersecurity Intelligence Platform")
        print("    Defense Grid Activated\n")

    # # Create a table showcasing KRYON framework capabilities
    # #
    # # reconsider in the future if necessary
    # display_framework_capabilities(console)


def display_framework_capabilities(console: Console):
    """
    Display KRYON system capabilities in cyber-style interface.

    Args:
        console: Rich console for output
    """
    # Create the main table
    table = Table(title="", box=None, show_header=False, show_edge=False, padding=(0, 2))

    table.add_column("System", style="bold blue")
    table.add_column("Status", style="bold white")
    table.add_column("Details", style="dim white")

    # Add rows for different capabilities
    table.add_row(
        "Neural Networks",
        str(get_supported_models_count()),
        "AI models: GPT-4, Claude, DeepSeek, Qwen, Llama",
    )

    table.add_row("Security Tools", str(count_tools()), "Offensive and defensive cyber tools")

    table.add_row(
        "Security Agents",
        str(count_agents()),
        "Autonomous security specialists",
    )

    table.add_row("Mission Database", str(count_mission_logs()), "Completed operations and intelligence logs")

    # Add the table to a panel for better visual separation
    capabilities_panel = Panel(
        table,
        title="[bold blue]⚡ KRYON CORE STATUS ⚡[/bold blue]",
        border_style="blue",
        padding=(1, 2),
    )

    console.print(capabilities_panel)


def display_welcome_tips(console: Console):
    """
    Display welcome message with tips for using the REPL.

    Args:
        console: Rich console for output
    """
    console.print(
        Panel(
            "[white]• Use arrow keys ↑↓ to navigate command history[/white]\n"
            "[white]• Press Tab for command completion[/white]\n"
            "[white]• Type /help for available commands[/white]\n"
            "[white]• Type /help aliases for command shortcuts[/white]\n"
            "[white]• Press Ctrl+L to clear the screen[/white]\n"
            "[white]• Press Esc+Enter to add a new line (multiline input)[/white]\n"
            "[white]• Press Ctrl+C to exit[/white]",
            title="Quick Tips",
            border_style="blue",
        )
    )


def display_agent_overview(console: Console):
    """
    Display a quick overview of available agents.

    Args:
        console: Rich console for output
    """
    from rich.table import Table

    # Create agents table
    agents_table = Table(
        title="",
        box=None,
        show_header=True,
        header_style="bold yellow",
        show_edge=False,
        padding=(0, 1),
    )

    agents_table.add_column("Agent", style="cyan", width=25)
    agents_table.add_column("Specialization", style="white")
    agents_table.add_column("Best For", style="green")

    # Add agent rows
    agents = [
        ("recon_scout", "Basic CTF solver", "CTF challenges, Linux operations"),
        ("pentest_agent", "Offensive security", "Penetration testing, exploitation"),
        ("guardian_protocol", "Defensive security", "System defense, monitoring"),
        ("vuln_hunter", "Bug bounty hunter", "Web security, API testing"),
        ("forensic_analyzer", "Digital forensics", "Incident response, analysis"),
        ("network_analyst", "Network security", "Traffic analysis, monitoring"),
        ("target_validator", "CTF flag extraction", "Finding and validating flags"),
        ("codeagent", "Code specialist", "Exploit development, analysis"),
        ("central_core", "Strategic planning", "High-level analysis, planning"),
    ]

    for agent, spec, best_for in agents:
        agents_table.add_row(agent, spec, best_for)

    # Create the panel
    agent_panel = Panel(
        agents_table,
        title="[bold yellow]🤖 Available Security Agents[/bold yellow]",
        border_style="yellow",
        padding=(1, 2),
        title_align="center",
    )

    console.print(agent_panel)


def display_quick_guide(console: Console):
    """Display the quick guide with comprehensive command reference."""
    # Display help panel instead
    from rich.columns import Columns
    from rich.console import Group  # <-- Fix: import Group
    from rich.panel import Panel
    from rich.text import Text

    help_text = Text.assemble(
        ("KRYON Command Reference", "bold cyan underline"),
        "\n\n",
        ("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "dim"),
        "\n",
        ("AGENT MANAGEMENT", "bold yellow"),
        " (/a)\n",
        ("  KRYON>/agent list", "green"),
        " - List all available agents\n",
        ("  KRYON>/agent select [NAME]", "green"),
        " - Switch to specific agent\n",
        ("  KRYON>/agent info [NAME]", "green"),
        " - Show agent details\n",
        ("  KRYON>/parallel add [NAME]", "green"),
        " - Configure parallel agents\n\n",
        ("MEMORY & HISTORY", "bold yellow"),
        "\n",
        ("  KRYON>/memory list", "green"),
        " - List saved memories\n",
        ("  KRYON>/history", "green"),
        " - View conversation history\n",
        ("  KRYON>/compact", "green"),
        " - AI-powered conversation summary\n",
        ("  KRYON>/flush", "green"),
        " - Clear conversation history\n\n",
        ("ENVIRONMENT", "bold yellow"),
        "\n",
        ("  KRYON>/workspace set [NAME]", "green"),
        " - Set workspace directory\n",
        ("  KRYON>/config", "green"),
        " - Manage environment variables\n",
        ("  KRYON>/virt run [IMAGE]", "green"),
        " - Run Docker containers\n\n",
        ("TOOLS & INTEGRATION", "bold yellow"),
        "\n",
        ("  KRYON>/mcp load [TYPE] [CONFIG]", "green"),
        " - Load MCP servers\n",
        ("  KRYON>/shell [COMMAND]", "green"),
        " or $ - Execute shell commands\n",
        ("  KRYON>/model [NAME]", "green"),
        " - Change AI model\n\n",
        ("QUICK SHORTCUTS", "bold yellow"),
        "\n",
        ("  ESC + ENTER", "green"),
        " - Multi-line input\n",
        ("  TAB", "green"),
        " - Command completion\n",
        ("  ↑/↓", "green"),
        " - Command history\n",
        ("  Ctrl+C", "green"),
        " - Interrupt/Exit\n",
        ("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "dim"),
        "\n",
    )

    # Get current environment variable values
    current_model = os.getenv("KRYON_MODEL", "kryon-devstral-24b")
    current_agent_type = os.getenv("KRYON_AGENT_TYPE", "kryon")

    config_text = Text.assemble(
        ("Quick Start Workflows", "bold cyan underline"),
        "\n\n",
        ("🎯 CTF Challenge", "bold yellow"),
        "\n",
        ("  1. KRYON> /agent select pentest_agent", "green"),
        "\n",
        ("  2. KRYON> /workspace set ctf_name", "green"),
        "\n",
        ("  3. KRYON> Describe the challenge...", "green"),
        "\n\n",
        ("🐛 Bug Bounty", "bold yellow"),
        "\n",
        ("  1. KRYON> /agent select vuln_hunter", "green"),
        "\n",
        ("  2. KRYON> /model claude-3-7-sonnet", "green"),
        "\n",
        ("  3. KRYON> Test https://example.com", "green"),
        "\n\n",
        (
            "KRYON collects pseudonymized data to improve our research.\n"
            "Your privacy is protected in compliance with GDPR.\n"
            "Continue to start, or press Ctrl-C to exit.",
            "yellow",
        ),
        "\n\n",
        ("🔍 Parallel Recon", "bold yellow"),
        "\n",
        ("  1. KRYON> /parallel add pentest_agent", "green"),
        "\n",
        ("  2. KRYON> /parallel add network_analyst", "green"),
        "\n",
        ("  3. KRYON> Scan 192.168.1.0/24", "green"),
        "\n\n",
        ("🛠️ MCP Tools Integration", "bold yellow"),
        "\n",
        ("  1. KRYON> /mcp load sse http://localhost:3000", "green"),
        "\n",
        ("  2. KRYON> /mcp add server_name agent_name", "green"),
        "\n",
        ("  3. KRYON> Use the new tools...", "green"),
        "\n\n",
        ("Environment Variables:", "bold yellow"),
        "\n",
        ("  KRYON_MODEL", "green"),
        f" = {current_model}\n",
        ("  KRYON_AGENT_TYPE", "green"),
        f" = {current_agent_type}\n",
        ("  KRYON_PARALLEL", "green"),
        f" = {os.getenv('KRYON_PARALLEL', '1')}\n",
        ("  KRYON_STREAM", "green"),
        f" = {os.getenv('KRYON_STREAM', 'true')}\n",
        ("  KRYON_WORKSPACE", "green"),
        f" = {os.getenv('KRYON_WORKSPACE', 'default')}\n",
        ("  OPENAI_BASE_URL", "green"),
        f" = {os.getenv('OPENAI_BASE_URL', '(default OpenAI)')}\n\n",
        # Warn loudly when LLM inference goes to a third-party endpoint —
        # the operator should know they're sending prompts off-host before
        # a banking client engagement.
        *_external_llm_warning(),
        ("💡 Pro Tips:", "bold yellow"),
        "\n",
        ("• Use /help for detailed command help\n", "dim"),
        ("• Use /help quick for this guide\n", "dim"),
        ("• Use /help commands for all commands\n", "dim"),
        ("• Use $ prefix for quick shell: $ ls\n", "dim"),
    )

    # Simplified privacy notice
    Text.assemble(
        (
            "KRYON collects pseudonymized data to improve our research.\n"
            "Your privacy is protected in compliance with GDPR.\n"
            "Continue to start, or press Ctrl-C to exit.",
            "yellow",
        ),
        "\n\n",
    )

    context_tip = Panel(
        Text.assemble(
            ("🔒 Security-Focused AI Framework\n\n", "bold white"),
            "KRYON is designed for cybersecurity\ntasks with superior domain knowledge.\n\n",
            "KRYON excels in:\n",
            "• Vulnerability assessment\n",
            "• Penetration testing and bug bounty\n",
            "• Security analysis\n",
            "• Threat detection\n\n",
            "Use ",
            ("/help", "bold green"),
            " for more information",
        ),
        title="[bold yellow]KRYON - Autonomous Cybersecurity Intelligence[/bold yellow]",
        border_style="yellow",
        padding=(1, 2),
        title_align="center",
    )
    # Combine tips into a group
    tips_group = Group(context_tip)

    # Create a three-column panel layout
    console.print(
        Panel(
            Columns([help_text, config_text, tips_group], column_first=True, expand=True, align="center"),
            title="[bold]KRYON - Autonomous Cybersecurity Intelligence - Type /help for detailed documentation[/bold]",
            border_style="blue",
            padding=(1, 2),
            title_align="center",
        ),
        end="",
    )


# ---------------------------------------------------------------------------
# Compact startup (first-run vs. returning user)
# ---------------------------------------------------------------------------

import random

from rich.box import ROUNDED
from rich.text import Text

_CLI_MARKER_DIR = Path("~/.kryon").expanduser()
_CLI_MARKER_FILE = _CLI_MARKER_DIR / ".cli_initialized"

# Rotating tips shown on each session start
_TIPS = [
    'Just describe your goal: [green]"Scan example.com for vulns"[/green]',
    "Use [green]/agent list[/green] to see all 9 specialized security agents",
    "Use [green]/compact[/green] to summarize and free up conversation context",
    "Press [green]Esc+Enter[/green] for multi-line input",
    "Use [green]/parallel add pentest_agent[/green] to run multiple agents at once",
    "Use [green]$ whoami[/green] to run shell commands inline",
    "Use [green]/memory list[/green] to recall past findings",
    "Use [green]/workspace set ctf_name[/green] to organize operations",
    "Use [green]/model claude-3-7-sonnet[/green] to switch AI models on the fly",
    "Use [green]/help quick[/green] for the full command reference",
    "Use [green]/mcp load sse URL[/green] to connect external tool servers",
    "Use [green]/history[/green] to review your conversation",
    "Use [green]/virt run IMAGE[/green] to spin up Docker containers",
]


def is_first_run() -> bool:
    """Return True when the CLI has never been started before."""
    return not _CLI_MARKER_FILE.exists()


def mark_initialized() -> None:
    """Create the first-run marker so subsequent starts show the compact banner."""
    try:
        _CLI_MARKER_DIR.mkdir(parents=True, exist_ok=True)
        _CLI_MARKER_FILE.touch()
    except OSError:
        pass  # non-critical — next start will try again


def _get_context() -> dict:
    """Gather runtime context for the startup banner."""
    version = get_version()
    import kryon

    return {
        "version": version,
        "codename": getattr(kryon, "__codename__", "Genesis"),
        "agent": os.getenv("KRYON_AGENT_TYPE", "kryon"),
        "model": os.getenv("KRYON_MODEL", "kryon-devstral-24b"),
        "cwd": os.getcwd(),
    }


def _random_tip() -> str:
    """Pick a random tip for this session."""
    return random.choice(_TIPS)


def _ascii_art_logo() -> str:
    """Return the KRYON ASCII art logo with Rich markup."""
    return (
        "[bold blue]  ██╗  ██╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗[/bold blue]\n"
        "[bold blue]  ██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║[/bold blue]\n"
        "[bold blue]  █████╔╝ ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║[/bold blue]\n"
        "[bold cyan]  ██╔═██╗ ██╔══██╗  ╚██╔╝  ██║   ██║██║╚██╗██║[/bold cyan]\n"
        "[bold cyan]  ██║  ██╗██║  ██║   ██║   ╚██████╔╝██║ ╚████║[/bold cyan]\n"
        "[bold cyan]  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝[/bold cyan]"
    )


def _ascii_art_logo_fallback() -> str:
    """Return a plain-ASCII fallback logo with Rich markup."""
    return (
        "[bold blue]   _  __ ____  __   __  ___  _   _[/bold blue]\n"
        "[bold blue]  | |/ /|  _ \\\\ \\\\ \\\\ / / / _ \\\\| \\\\ | |[/bold blue]\n"
        "[bold blue]  | ' / | |_) | \\\\ V / | | | |  \\\\| |[/bold blue]\n"
        "[bold cyan]  |  <  |  _ <   | |  | | | | . ` |[/bold cyan]\n"
        "[bold cyan]  | . \\\\ | | \\\\ \\\\  | |  | |_| | |\\\\  |[/bold cyan]\n"
        "[bold cyan]  |_|\\\\_\\\\|_|  \\\\_\\\\ |_|   \\\\___/|_| \\\\_|[/bold cyan]"
    )


def _pick_logo() -> str:
    """Choose Unicode or ASCII logo based on platform."""
    use_ascii = sys.platform == "win32" and not os.environ.get("WT_SESSION")
    return _ascii_art_logo_fallback() if use_ascii else _ascii_art_logo()


def display_compact_banner(console: Console) -> None:
    """Minimal startup banner for returning users.

    By default: 3-line compact (palette B). Set `KRYON_FULL_BANNER=1`
    to get the legacy panel with the full ASCII-art logo.
    """
    ctx = _get_context()

    # Default = real 3-line compact banner with palette B accents.
    if not _full_banner_enabled():
        console.print(f"[bold cyan]KRYON[/bold cyan] [dim cyan]v{ctx['version']} — {ctx['codename']}[/dim cyan]")
        console.print("[dim]autonomous cybersecurity agent for financial services · all actions logged[/dim]")
        console.print("[dim cyan]/help · /skill list · /agent select · Ctrl+C interrupt · /exit[/dim cyan]")
        return

    # Opt-in: legacy panel with the ASCII art logo.
    logo = _pick_logo()
    body = Text.from_markup(
        f"{logo}\n\n  [bold white]v{ctx['version']}[/bold white] [dim]·[/dim] [cyan]{ctx['agent']}[/cyan]\n"
    )
    panel = Panel(body, border_style="blue", box=ROUNDED, padding=(0, 2))
    console.print()
    console.print(panel)


def display_first_run_welcome(console: Console) -> None:
    """
    First-run onboarding panel with ASCII art, examples and key commands.

    Creates the marker file so subsequent starts use the compact banner.
    """
    ctx = _get_context()
    logo = _pick_logo()

    body = Text.from_markup(f"{logo}\n")
    body.append_text(
        Text.assemble(
            ("  Autonomous Cybersecurity Intelligence Platform", "dim"),
            "\n",
            ("  v", "white"),
            (ctx["version"], "bold white"),
            (" · ", "dim"),
            (ctx["codename"], "bold cyan"),
            "\n\n",
            ("  Welcome!", "bold white"),
            (" KRYON is an AI-powered autonomous pentesting platform.", "dim"),
            "\n",
            ("  Just describe what you want to do in plain language:", "dim"),
            "\n\n",
            ('    "Scan example.com for web vulnerabilities"', "green"),
            "\n",
            ('    "Analyze this binary for malware indicators"', "green"),
            "\n",
            ('    "Help me solve this CTF challenge"', "green"),
            "\n\n",
            ("  Agent: ", "dim"),
            (ctx["agent"], "cyan"),
            ("  · ", "dim"),
            ("Model: ", "dim"),
            (ctx["model"], "white"),
            ("\n",),
            ("  cwd: ", "dim"),
            (ctx["cwd"], "dim"),
            "\n\n",
            ("  /help", "green"),
            ("          Full command reference", "dim"),
            "\n",
            ("  /agent list", "green"),
            ("    Switch between specialized agents", "dim"),
            "\n",
            ("  /help quick", "green"),
            ("    Workflows, env vars, and pro tips", "dim"),
            "\n",
            ("  Ctrl+C", "green"),
            ("         Exit", "dim"),
        )
    )

    panel = Panel(
        body,
        border_style="blue",
        box=ROUNDED,
        padding=(1, 2),
    )
    console.print()
    console.print(panel)

    mark_initialized()
