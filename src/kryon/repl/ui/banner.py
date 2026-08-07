"""KRYON REPL banner — startup identity (crystalline palette).

One banner system, one palette (steel-blue #2f6ea6 + electric-cyan #45e0ef).
The legacy CAI-fork art (double ASCII banners, framework-capabilities table,
inglés-mixed tips) was removed — it described a different product (33 static
agents, /model claude, RAG) and clashed with the v2.x skill-based identity.

Two entry points, both animate the Ghost boot-up then settle into a tight
tagline:
  * display_compact_banner   — returning users (default 3-line + rotating tip)
  * display_first_run_welcome — first run (onboarding panel with real commands)

`KRYON_FULL_BANNER=1` → static logo panel. `KRYON_NO_ANIMATION=1` / non-TTY →
static frame.
"""

# Standard library imports
import logging  # noqa: F401 — kept for callers importing it from here
import os
import random
import sys
from pathlib import Path

# Configure UTF-8 encoding for Windows console
if sys.platform == "win32":
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleOutputCP(65001)  # UTF-8 code page
        kernel32.SetConsoleCP(65001)  # Input code page
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        os.environ["PYTHONIOENCODING"] = "utf-8"
    except Exception:
        pass  # Ignore if we can't set UTF-8

# Third-party imports
from rich.box import ROUNDED  # pylint: disable=import-error
from rich.console import Console  # pylint: disable=import-error
from rich.panel import Panel  # pylint: disable=import-error
from rich.text import Text  # pylint: disable=import-error

# For reading TOML files
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
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


def _full_banner_enabled() -> bool:
    """The static logo panel is opt-in. Default = animated compact banner."""
    val = os.environ.get("KRYON_FULL_BANNER", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def _is_local_endpoint(base_url: str) -> bool:
    """True when `base_url`'s host is on-host / private-network.

    Precise on purpose: this gates a security warning (client PII must not
    leak to a third party), so we err toward *showing* the warning. A bare
    substring match would wrongly suppress it for hosts like
    ``api10.example.com`` (contains ``10.``), so we parse the host and test
    it exactly / via the ``ipaddress`` module.
    """
    from ipaddress import ip_address
    from urllib.parse import urlparse

    host = (urlparse(base_url).hostname or "").lower()
    if not host:
        return False

    # Named on-host / compose-service endpoints.
    if host in {"localhost", "llama-server", "llm-server", "llama.cpp", "host.docker.internal"}:
        return True
    if host.endswith((".internal", ".local")):
        return True

    # Numeric hosts: loopback / private / link-local ranges are on-network.
    try:
        ip = ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def _external_llm_warning() -> list:
    """Banner fragments that warn the operator when LLM inference is
    routed to a third-party endpoint (DeepSeek, OpenAI, OpenRouter, etc).

    Returns a list of (text, style) tuples ready to be spread into a
    Text.assemble() call. Empty list when running against a local
    endpoint (llama-server) or no configured endpoint — no warning needed.
    """
    # KRYON_LOCAL_LLM is the authoritative signal the whole stack uses for
    # "inference stays on-host". When it's set, trust it — no warning.
    from kryon.util.env import is_local_llm

    if is_local_llm():
        return []

    base_url = os.getenv("OPENAI_BASE_URL", "").strip()
    if not base_url:
        return []
    if _is_local_endpoint(base_url):
        return []
    # Anything else is external — warn loudly
    return [
        ("⚠️  ATENCIÓN: la inferencia del LLM sale a un proveedor externo.\n", "bold yellow on red"),
        (f"   Endpoint: {os.getenv('OPENAI_BASE_URL', '')}\n", "yellow"),
        ("   No incluyas PAN, credenciales ni PII de clientes en los prompts.\n", "yellow"),
        ("   Conseguí autorización escrita antes de engagements bancarios.\n\n", "yellow"),
    ]


# ---------------------------------------------------------------------------
# First-run marker + rotating tips
# ---------------------------------------------------------------------------

_CLI_MARKER_DIR = Path("~/.kryon").expanduser()
_CLI_MARKER_FILE = _CLI_MARKER_DIR / ".cli_initialized"

# Rotating tips shown on each session start. Kept CURRENT with v2.x — every
# command/flow here exists (skill-based, local models, learning loop). No CAI
# leftovers (33 agents / /model claude / RAG) that describe another product.
_TIPS = [
    'Describí tu objetivo en lenguaje natural: [#45e0ef]"auditá https://ejemplo.com"[/#45e0ef]',
    "Usá [#45e0ef]/skill list[/#45e0ef] para ver los playbooks (recon, pentest, compliance…)",
    "Usá [#45e0ef]/findings[/#45e0ef] para los hallazgos de la sesión y [#45e0ef]/report[/#45e0ef] para el informe",
    "Usá [#45e0ef]/skill drafts[/#45e0ef] para revisar skills que Kryon aprendió solo",
    "Usá [#45e0ef]/compact[/#45e0ef] para resumir y liberar contexto de la conversación",
    "Corré shell inline con [#45e0ef]$ whoami[/#45e0ef] — sin salir del REPL",
    "Usá [#45e0ef]/experiences[/#45e0ef] para revisar engagements pasados",
    "Presioná [#45e0ef]Esc+Enter[/#45e0ef] para entrada multilínea",
    "Presioná [#45e0ef]Ctrl+L[/#45e0ef] para limpiar la pantalla",
    "Usá [#45e0ef]/config[/#45e0ef] para ver la configuración efectiva (modelo, endpoint, perfil)",
    "Usá [#45e0ef]/help[/#45e0ef] para la referencia completa de comandos",
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
    from kryon.util.model_probe import real_model_name

    return {
        "version": version,
        "codename": getattr(kryon, "__codename__", "Genesis"),
        "agent": os.getenv("KRYON_AGENT_TYPE", "kryon"),
        "model": real_model_name(),
        "cwd": os.getcwd(),
    }


def _random_tip() -> str:
    """Pick a random tip for this session."""
    return random.choice(_TIPS)


def _ascii_art_logo() -> str:
    """Return the KRYON ASCII art logo with Rich markup (crystalline palette)."""
    return (
        "[bold #2f6ea6]  ██╗  ██╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗[/]\n"
        "[bold #2f6ea6]  ██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║[/]\n"
        "[bold #3a86c9]  █████╔╝ ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║[/]\n"
        "[bold #45e0ef]  ██╔═██╗ ██╔══██╗  ╚██╔╝  ██║   ██║██║╚██╗██║[/]\n"
        "[bold #45e0ef]  ██║  ██╗██║  ██║   ██║   ╚██████╔╝██║ ╚████║[/]\n"
        "[bold #45e0ef]  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝[/]"
    )


def _ascii_art_logo_fallback() -> str:
    """Return a plain-ASCII fallback logo with Rich markup (crystalline palette)."""
    return (
        "[bold #2f6ea6]   _  __ ____  __   __  ___  _   _[/]\n"
        "[bold #2f6ea6]  | |/ /|  _ \\\\ \\\\ \\\\ / / / _ \\\\| \\\\ | |[/]\n"
        "[bold #3a86c9]  | ' / | |_) | \\\\ V / | | | |  \\\\| |[/]\n"
        "[bold #45e0ef]  |  <  |  _ <   | |  | | | | . ` |[/]\n"
        "[bold #45e0ef]  | . \\\\ | | \\\\ \\\\  | |  | |_| | |\\\\  |[/]\n"
        "[bold #45e0ef]  |_|\\\\_\\\\|_|  \\\\_\\\\ |_|   \\\\___/|_| \\\\_|[/]"
    )


def _pick_logo() -> str:
    """Choose Unicode or ASCII logo based on platform."""
    use_ascii = sys.platform == "win32" and not os.environ.get("WT_SESSION")
    return _ascii_art_logo_fallback() if use_ascii else _ascii_art_logo()


def display_compact_banner(console: Console) -> None:
    """Startup for returning users: the crystalline "K" materializes (boot-up
    animation), then a tight tagline + command hint + a rotating tip in the
    Kryon palette.

    `KRYON_FULL_BANNER=1` → static ASCII-art panel.
    `KRYON_NO_ANIMATION=1` (or a non-TTY) → static logo, no animation.
    """
    ctx = _get_context()

    if _full_banner_enabled():
        logo = _pick_logo()
        body = Text.from_markup(
            f"{logo}\n\n  [bold white]v{ctx['version']}[/bold white] [dim]·[/dim] [#45e0ef]{ctx['agent']}[/#45e0ef]\n"
        )
        panel = Panel(body, border_style="#2f6ea6", box=ROUNDED, padding=(0, 2))
        console.print()
        console.print(panel)
        return

    # Default: animated Ghost boot-up with the wordmark + tagline settling in
    # to the RIGHT of the shell.
    from kryon.repl.ui.logo_animation import render_logo_animation

    render_logo_animation(
        console,
        version=ctx["version"],
        codename=ctx["codename"],
        subtitle_lines=[
            ("agente autónomo de ciberseguridad ofensiva y compliance", "#5f8bb0"),
            ("orquesta engines deterministas · toda acción queda registrada", "dim #5f8bb0"),
        ],
    )

    warn = _external_llm_warning()
    if warn:
        console.print(Text.assemble(*warn))
    console.print("  [dim #45e0ef]/help · /skill list · /findings · /report · Ctrl+C interrumpe · /exit[/]")
    # A rotating tip gives the startup a bit of personality without noise.
    try:
        console.print(f"  [dim]💡 {_random_tip()}[/dim]")
    except Exception:
        pass


def display_first_run_welcome(console: Console) -> None:
    """First-run onboarding: the boot-up logo animation + a crystalline
    onboarding panel with examples and the real command set.

    Creates the marker file so subsequent starts use the compact banner.
    """
    ctx = _get_context()

    # Materialization boot-up (animated in a TTY, static frame otherwise).
    from kryon.repl.ui.logo_animation import render_logo_animation

    console.print()
    render_logo_animation(console, version=ctx["version"], codename=ctx["codename"])

    body = Text.assemble(
        ("  agente autónomo de ciberseguridad ofensiva y compliance", "#5f8bb0"),
        "\n",
        ("  orquesta engines deterministas · toda acción queda registrada", "dim #5f8bb0"),
        "\n\n",
        ("  Describí lo que querés hacer en lenguaje natural:", "dim"),
        "\n\n",
        ('    "auditá https://target.com"', "#45e0ef"),
        "\n",
        ('    "qué CVEs aplican a nginx 1.18"', "#45e0ef"),
        "\n",
        ('    "compliance PCI-DSS de este segmento"', "#45e0ef"),
        "\n\n",
        ("  Modelo: ", "dim"),
        (ctx["model"], "white"),
        ("  · cwd: ", "dim"),
        (ctx["cwd"], "dim"),
        "\n\n",
        ("  /help", "#45e0ef"),
        ("        referencia completa de comandos", "dim"),
        "\n",
        ("  /skill list", "#45e0ef"),
        ("  playbooks disponibles (recon, pentest, compliance…)", "dim"),
        "\n",
        ("  /findings", "#45e0ef"),
        ("    hallazgos de la sesión  ·  ", "dim"),
        ("/report", "#45e0ef"),
        (" genera el informe", "dim"),
        "\n",
        ("  Ctrl+C", "#45e0ef"),
        ("       interrumpe / sale", "dim"),
    )

    panel = Panel(
        body,
        border_style="#2f6ea6",
        box=ROUNDED,
        padding=(1, 2),
    )
    console.print(panel)

    mark_initialized()
