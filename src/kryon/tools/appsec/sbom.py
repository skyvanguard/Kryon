"""Syft + Grype — Software Bill of Materials (SBOM) and vulnerability scanning."""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def generate_sbom(
    target: str,
    format: str = "cyclonedx-json",
    source_type: str = "dir",
    ctf=None,
) -> str:
    """
    Generate a Software Bill of Materials (SBOM) using Syft.

    Creates a comprehensive inventory of all software components, libraries,
    and dependencies in the target. Supports CycloneDX and SPDX formats.

    Args:
        target: Target to analyze (directory path, container image, or archive)
        format: SBOM format (cyclonedx-json, spdx-json, syft-json, spdx-tag-value)
        source_type: Source type (dir, image, file, registry)
        ctf: CTF context for execution

    Returns:
        str: Generated SBOM in the specified format
    """
    cmd_parts = ["syft", f"{source_type}:{target}", f"-o {format}"]
    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def scan_sbom_vulns(
    target: str,
    severity: str = "critical,high",
    only_fixed: bool = False,
    ctf=None,
) -> str:
    """
    Scan for vulnerabilities in dependencies using Grype.

    Grype matches software components against known vulnerability databases
    to identify security issues in project dependencies.

    Args:
        target: Target to scan (directory, SBOM file, or container image)
        severity: Minimum severity to report (critical, high, medium, low, negligible)
        only_fixed: Only show vulnerabilities with available fixes
        ctf: CTF context for execution

    Returns:
        str: Vulnerability scan results with affected packages and CVEs
    """
    cmd_parts = ["grype", target, f"--fail-on {severity.split(',')[0]}", "-o json"]

    if only_fixed:
        cmd_parts.append("--only-fixed")

    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def dependency_tree(
    project_path: str,
    package_manager: str = "auto",
    depth: int = 3,
    ctf=None,
) -> str:
    """
    Generate a dependency tree for a project.

    Analyzes the project's package manager files to produce a tree view
    of all direct and transitive dependencies.

    Args:
        project_path: Path to the project root
        package_manager: Package manager (auto, npm, pip, maven, gradle, cargo, go)
        depth: Maximum depth of the dependency tree
        ctf: CTF context for execution

    Returns:
        str: Dependency tree visualization
    """
    pm_commands = {
        "npm": f"cd {project_path} && npm ls --all --depth={depth}",
        "pip": f"cd {project_path} && pipdeptree --depth {depth}",
        "maven": f"cd {project_path} && mvn dependency:tree -DoutputType=text",
        "gradle": f"cd {project_path} && gradle dependencies --configuration runtimeClasspath",
        "cargo": f"cd {project_path} && cargo tree --depth {depth}",
        "go": f"cd {project_path} && go mod graph",
    }

    if package_manager != "auto":
        cmd = pm_commands.get(package_manager)
        if not cmd:
            return f"Error: Unknown package manager '{package_manager}'. Supported: {', '.join(pm_commands.keys())}"
        return run_command(cmd, ctf=ctf)

    # Auto-detect: try syft for universal SBOM
    return run_command(f"syft dir:{project_path} -o syft-table", ctf=ctf)
