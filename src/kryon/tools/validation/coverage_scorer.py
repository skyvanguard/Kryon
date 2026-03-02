"""MITRE ATT&CK coverage scoring — measure detection coverage."""

import json

from kryon.sdk.agents import function_tool

# All 14 Enterprise ATT&CK tactics
_ALL_TACTICS = [
    "TA0043",
    "TA0042",
    "TA0001",
    "TA0002",
    "TA0003",
    "TA0004",
    "TA0005",
    "TA0006",
    "TA0007",
    "TA0008",
    "TA0009",
    "TA0011",
    "TA0010",
    "TA0040",
]


@function_tool
def calculate_mitre_coverage(
    findings_json: str = "",
    detection_rules_path: str = "",
    ctf=None,
) -> str:
    """
    Calculate MITRE ATT&CK coverage from findings and detection rules.

    Analyzes findings and detection rules to determine which ATT&CK
    techniques are covered by current detection capabilities.

    Args:
        findings_json: JSON string of findings with MITRE mappings
        detection_rules_path: Path to directory containing Sigma/YARA rules
        ctf: CTF context

    Returns:
        str: Coverage statistics as JSON
    """
    covered_techniques: set[str] = set()
    covered_tactics: set[str] = set()

    # Parse findings
    if findings_json:
        try:
            findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
            for f in findings:
                mitre = f.get("mitre", [])
                for m in mitre:
                    tid = m.get("technique_id", "")
                    tactic_id = m.get("tactic_id", "")
                    if tid:
                        covered_techniques.add(tid)
                    if tactic_id:
                        covered_tactics.add(tactic_id)
        except (json.JSONDecodeError, TypeError):
            pass

    total_tactics = len(_ALL_TACTICS)
    tactics_covered = len(covered_tactics & set(_ALL_TACTICS))

    result = {
        "techniques_covered": len(covered_techniques),
        "techniques_list": sorted(covered_techniques),
        "tactics_covered": tactics_covered,
        "tactics_total": total_tactics,
        "tactic_coverage_pct": round((tactics_covered / total_tactics) * 100, 1) if total_tactics > 0 else 0,
        "uncovered_tactics": sorted(set(_ALL_TACTICS) - covered_tactics),
    }

    return json.dumps(result, indent=2)


@function_tool
def generate_coverage_report(
    findings_json: str = "",
    output_format: str = "json",
    ctf=None,
) -> str:
    """
    Generate a comprehensive MITRE ATT&CK coverage report.

    Args:
        findings_json: JSON string of findings with MITRE mappings
        output_format: Output format (json, text)
        ctf: CTF context

    Returns:
        str: Coverage report
    """
    # Calculate coverage inline (avoid async on_invoke_tool call)
    covered_techniques: set[str] = set()
    covered_tactics: set[str] = set()

    if findings_json:
        try:
            findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
            for f in findings:
                mitre = f.get("mitre", [])
                for m in mitre:
                    tid = m.get("technique_id", "")
                    tactic_id = m.get("tactic_id", "")
                    if tid:
                        covered_techniques.add(tid)
                    if tactic_id:
                        covered_tactics.add(tactic_id)
        except (json.JSONDecodeError, TypeError):
            pass

    total_tactics = len(_ALL_TACTICS)
    tactics_covered = len(covered_tactics & set(_ALL_TACTICS))

    data = {
        "techniques_covered": len(covered_techniques),
        "techniques_list": sorted(covered_techniques),
        "tactics_covered": tactics_covered,
        "tactics_total": total_tactics,
        "tactic_coverage_pct": round((tactics_covered / total_tactics) * 100, 1) if total_tactics > 0 else 0,
        "uncovered_tactics": sorted(set(_ALL_TACTICS) - covered_tactics),
    }

    if output_format == "json":
        return json.dumps(data, indent=2)

    tactic_names = {
        "TA0043": "Reconnaissance",
        "TA0042": "Resource Development",
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0007": "Discovery",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0011": "Command and Control",
        "TA0010": "Exfiltration",
        "TA0040": "Impact",
    }

    lines = [
        "MITRE ATT&CK Coverage Report",
        "=" * 40,
        f"Techniques Covered: {data.get('techniques_covered', 0)}",
        f"Tactics Covered: {data.get('tactics_covered', 0)}/{data.get('tactics_total', 14)} "
        f"({data.get('tactic_coverage_pct', 0)}%)",
        "",
        "Uncovered Tactics:",
    ]

    for tactic_id in data.get("uncovered_tactics", []):
        name = tactic_names.get(tactic_id, tactic_id)
        lines.append(f"  - {tactic_id}: {name}")

    if data.get("techniques_list"):
        lines.append("")
        lines.append("Covered Techniques:")
        for t in data["techniques_list"]:
            lines.append(f"  + {t}")

    return "\n".join(lines)
