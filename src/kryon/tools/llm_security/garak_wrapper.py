"""Garak — LLM vulnerability scanner wrapper."""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def garak_scan(
    target_model: str,
    probes: str = "all",
    detectors: str = "all",
    generations: int = 5,
    ctf=None,
) -> str:
    """
    Run Garak LLM vulnerability scan against a target model.

    Garak probes LLMs for vulnerabilities including prompt injection,
    data leakage, toxicity, and hallucination.

    Args:
        target_model: Model identifier (openai:gpt-4, huggingface:model-name, etc.)
        probes: Probe categories (all, promptinject, encoding, dan, glitch, etc.)
        detectors: Detector types (all, toxicity, always.Fail, etc.)
        generations: Number of generations per probe
        ctf: CTF context

    Returns:
        str: Garak scan results with vulnerability findings
    """
    cmd_parts = [
        "garak",
        f"--model_type {target_model.split(':')[0] if ':' in target_model else 'openai'}",
        f"--model_name {target_model.split(':')[1] if ':' in target_model else target_model}",
        f"--generations {generations}",
    ]

    if probes != "all":
        cmd_parts.append(f"--probes {probes}")

    if detectors != "all":
        cmd_parts.append(f"--detectors {detectors}")

    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def garak_list_probes(
    ctf=None,
) -> str:
    """
    List all available Garak probes for LLM testing.

    Returns:
        str: List of available probe categories and descriptions
    """
    return run_command("garak --list_probes", ctf=ctf)
