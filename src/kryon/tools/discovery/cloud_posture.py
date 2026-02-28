"""Cloud posture aggregation — combine Prowler/ScoutSuite outputs."""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def aggregate_cloud_posture(
    provider: str = "all",
    prowler_output: str = "",
    scoutsuite_output: str = "",
    ctf=None,
) -> str:
    """
    Aggregate cloud security posture from Prowler and ScoutSuite outputs.

    Combines and normalizes findings from multiple cloud security tools
    into a unified posture assessment.

    Args:
        provider: Cloud provider filter (all, aws, azure, gcp)
        prowler_output: Path to Prowler JSON output file
        scoutsuite_output: Path to ScoutSuite JSON output file
        ctf: CTF context

    Returns:
        str: Aggregated cloud posture assessment
    """
    results = ["Cloud Security Posture Assessment", "=" * 40]

    if prowler_output:
        cmd = f"cat {prowler_output} 2>/dev/null | python3 -c \"import json,sys; data=json.load(sys.stdin); print(f'Prowler findings: {{len(data)}}')\" 2>/dev/null || echo 'Unable to parse Prowler output'"
        results.append(f"\n[Prowler]\n{run_command(cmd, ctf=ctf)}")
    else:
        # Run Prowler if no output provided
        if provider in ("all", "aws"):
            results.append(f"\n[Prowler - AWS]\n{run_command('prowler aws --output-formats json -M json 2>/dev/null || echo Prowler not available', ctf=ctf)}")

    if scoutsuite_output:
        cmd = f"cat {scoutsuite_output} 2>/dev/null | head -100"
        results.append(f"\n[ScoutSuite]\n{run_command(cmd, ctf=ctf)}")

    return "\n".join(results)
