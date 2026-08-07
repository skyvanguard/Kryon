"""Cloud posture aggregation — combine Prowler/ScoutSuite outputs."""

from kryon.sdk.agents import function_tool
from kryon.server.logging_config import get_logger
from kryon.tools.common import run_command

logger = get_logger(__name__)


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
    logger.info("aggregate_cloud_posture started provider=%s", provider)
    results = ["Cloud Security Posture Assessment", "=" * 40]

    try:
        if prowler_output:
            cmd = f"cat {prowler_output} 2>/dev/null | python3 -c \"import json,sys; data=json.load(sys.stdin); print(f'Prowler findings: {{len(data)}}')\" 2>/dev/null || echo 'Unable to parse Prowler output'"
            results.append(f"\n[Prowler]\n{run_command(cmd, ctf=ctf)}")
        else:
            # Run Prowler if no output provided
            if provider in ("all", "aws"):
                results.append(
                    f"\n[Prowler - AWS]\n{run_command('prowler aws --output-formats json -M json 2>/dev/null || echo Prowler not available', ctf=ctf)}"
                )

        if scoutsuite_output:
            cmd = f"cat {scoutsuite_output} 2>/dev/null | head -100"
            results.append(f"\n[ScoutSuite]\n{run_command(cmd, ctf=ctf)}")
    except Exception as exc:
        logger.error("aggregate_cloud_posture failed: %s", exc)
        import json

        return json.dumps({"error": str(exc), "status": "failed"})

    return "\n".join(results)
