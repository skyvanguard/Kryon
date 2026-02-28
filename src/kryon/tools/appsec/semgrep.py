"""Semgrep — Static Application Security Testing (SAST) wrapper."""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def semgrep_scan(
    target_path: str,
    config: str = "auto",
    severity: str = "ERROR,WARNING",
    output_format: str = "text",
    language: str = "",
    exclude: str = "",
    ctf=None,
) -> str:
    """
    Run Semgrep SAST scan on source code to find security vulnerabilities.

    Semgrep is a fast, open-source static analysis tool that finds bugs and
    enforces code standards. Supports 30+ languages with 2000+ community rules.

    Args:
        target_path: Path to source code directory or file to scan
        config: Rule configuration (auto, p/security-audit, p/owasp-top-ten, p/default, or custom rule file)
        severity: Severity filter (ERROR, WARNING, INFO)
        output_format: Output format (text, json, sarif, emacs, vim)
        language: Limit scan to specific language (python, javascript, java, etc.)
        exclude: Glob patterns to exclude (comma-separated)
        ctf: CTF context for execution

    Returns:
        str: Semgrep scan results with vulnerability findings
    """
    cmd_parts = ["semgrep", "scan", f"--config {config}", f"--severity {severity}"]

    if output_format != "text":
        cmd_parts.append(f"--{output_format}" if output_format in ("json", "sarif") else f"--output-format {output_format}")

    if language:
        cmd_parts.append(f"--lang {language}")

    if exclude:
        for pattern in exclude.split(","):
            pattern = pattern.strip()
            if pattern:
                cmd_parts.append(f"--exclude '{pattern}'")

    cmd_parts.append(target_path)

    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def semgrep_scan_with_rules(
    target_path: str,
    rule_file: str,
    output_format: str = "json",
    ctf=None,
) -> str:
    """
    Run Semgrep with a custom rules file for targeted security scanning.

    Args:
        target_path: Path to source code to scan
        rule_file: Path to custom Semgrep rules YAML file
        output_format: Output format (json, text, sarif)
        ctf: CTF context for execution

    Returns:
        str: Scan results matching the custom rules
    """
    cmd_parts = ["semgrep", "scan", f"--config {rule_file}"]

    if output_format == "json":
        cmd_parts.append("--json")
    elif output_format == "sarif":
        cmd_parts.append("--sarif")

    cmd_parts.append(target_path)

    return run_command(" ".join(cmd_parts), ctf=ctf)
