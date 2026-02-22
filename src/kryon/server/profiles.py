"""Pre-defined scan profiles."""

from __future__ import annotations

SCAN_PROFILES: dict[str, dict] = {
    "quick": {
        "description": "Fast surface scan (5-10 min)",
        "agents": ["recon_scout"],
        "max_turns": 5,
        "tools_focus": ["nmap_quick", "whatweb"],
    },
    "standard": {
        "description": "Standard assessment (30-60 min)",
        "agents": ["recon_scout", "vuln_hunter"],
        "max_turns": 15,
        "tools_focus": ["nmap", "nuclei", "nikto"],
    },
    "deep": {
        "description": "Deep penetration test (2-4 hours)",
        "agents": ["pentest_agent", "vuln_hunter", "network_analyst"],
        "max_turns": 50,
        "pattern": "hierarchical",
    },
    "compliance": {
        "description": "Compliance-focused scan (1-2 hours)",
        "agents": ["vuln_hunter"],
        "max_turns": 30,
        "report_type": "compliance",
        "compliance_frameworks": ["pci-dss", "mitic"],
    },
}


def get_profile(name: str) -> dict | None:
    """Get a scan profile by name."""
    return SCAN_PROFILES.get(name)


def list_profiles() -> list[dict]:
    """List all available scan profiles."""
    return [
        {"name": k, **v}
        for k, v in SCAN_PROFILES.items()
    ]
