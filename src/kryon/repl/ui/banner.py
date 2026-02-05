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
    """Get the KRYON version from pyproject.toml."""
    version = "1.0.0"
    try:
        # Determine which TOML parser to use
        if sys.version_info >= (3, 11):
            toml_parser = tomllib
        else:
            try:
                import tomli as toml_parser
            except ImportError:
                logging.warning("Could not import tomli. Falling back to manual parsing.")
                # Simple manual parsing for version only
                with open("pyproject.toml", encoding="utf-8") as f:
                    for line in f:
                        if line.strip().startswith("version = "):
                            # Extract version from line like 'version = "0.4.0"'
                            version = line.split("=")[1].strip().strip("\"'")
                            return version
                return version

        # Use proper TOML parser if available
        with open("pyproject.toml", "rb") as f:
            config = toml_parser.load(f)
        version = config.get("project", {}).get("version", "unknown")
    except Exception as e:  # pylint: disable=broad-except
        logging.warning("Could not read version from pyproject.toml: %s", e)
    return version


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

            # Try to get Ollama models count
            try:
                ollama_api_base = os.getenv("OLLAMA_API_BASE", "http://host.docker.internal:8000/v1")
                ollama_response = requests.get(f"{ollama_api_base.replace('/v1', '')}/api/tags", timeout=1)

                if ollama_response.status_code == 200:
                    ollama_data = ollama_response.json()
                    ollama_models = len(ollama_data.get("models", ollama_data.get("items", [])))
                    return function_calling_models + ollama_models
            except Exception:  # pylint: disable=broad-except
                logging.debug("Could not fetch Ollama models")
                # Continue without Ollama models

            return function_calling_models
    except Exception:  # pylint: disable=broad-except
        logging.warning("Could not fetch model data from LiteLLM")

    # Default count if we can't fetch the data
    return "many"


def count_tools():
    """Count the number of tools in the KRYON arsenal."""
    try:
        # Count Python files in the tools directory
        tool_files = glob.glob("skynet/tools/**/*.py", recursive=True)
        # Exclude __init__.py and other non-tool files
        tool_files = [f for f in tool_files if not f.endswith("__init__.py") and not f.endswith("__pycache__")]
        return len(tool_files)
    except Exception:  # pylint: disable=broad-except
        logging.warning("Could not count tools")
        return "50+"


def count_agents():
    """Count the number of active Terminator units in KRYON."""
    try:
        # Count Python files in the agents directory
        agent_files = glob.glob("skynet/agents/**/*.py", recursive=True)
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


def display_banner(console: Console):
    """
    Display KRYON initialization banner with cyber-themed aesthetics.

    Args:
        console: Rich console for output
    """
    version = get_version()
    import kryon

    codename = getattr(skynet, "__codename__", "Genesis")

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

    table.add_row("Weapon Systems", str(count_tools()), "Offensive and defensive cyber tools")

    table.add_row(
        "Terminator Units",
        str(count_agents()),
        "Autonomous security agents (T-800, T-1000, HK-Series)",
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
        ("t600_scout", "Basic CTF solver", "CTF challenges, Linux operations"),
        ("t800_infiltrator", "Offensive security", "Penetration testing, exploitation"),
        ("guardian_protocol", "Defensive security", "System defense, monitoring"),
        ("t1000_hunter", "Bug bounty hunter", "Web security, API testing"),
        ("forensic_analyzer", "Digital forensics", "Incident response, analysis"),
        ("hk_aerial", "Network security", "Traffic analysis, monitoring"),
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
    current_model = os.getenv("KRYON_MODEL", "gpt-4o")
    current_agent_type = os.getenv("KRYON_AGENT_TYPE", "t600_scout")

    config_text = Text.assemble(
        ("Quick Start Workflows", "bold cyan underline"),
        "\n\n",
        ("🎯 CTF Challenge", "bold yellow"),
        "\n",
        ("  1. KRYON> /agent select t800_infiltrator", "green"),
        "\n",
        ("  2. KRYON> /workspace set ctf_name", "green"),
        "\n",
        ("  3. KRYON> Describe the challenge...", "green"),
        "\n\n",
        ("🐛 Bug Bounty", "bold yellow"),
        "\n",
        ("  1. KRYON> /agent select bug_bounter_agent", "green"),
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
        ("  1. KRYON> /parallel add t800_infiltrator", "green"),
        "\n",
        ("  2. KRYON> /parallel add hk_aerial", "green"),
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
        f" = {os.getenv('KRYON_WORKSPACE', 'default')}\n\n",
        ("💡 Pro Tips:", "bold yellow"),
        "\n",
        ("• Use /help for detailed command help\n", "dim"),
        ("• Use /help quick for this guide\n", "dim"),
        ("• Use /help commands for all commands\n", "dim"),
        ("• Use $ prefix for quick shell: $ ls\n", "dim"),
    )

    # Create additional tips panels
    Panel(
        "To use Ollama models, configure OLLAMA_API_BASE\nbefore startup.\n\nDefault: host.docker.internal:8000/v1",
        title="[bold yellow]Ollama Configuration[/bold yellow]",
        border_style="yellow",
        padding=(1, 2),
        title_align="center",
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
    # tips_group = Group(ollama_tip, context_tip, privacy_notice)
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
