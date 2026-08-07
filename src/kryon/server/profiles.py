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
    # Enterprise autonomous profiles
    "enterprise_quick": {
        "description": "Enterprise quick recon + vuln scan (30 min)",
        "agents": ["recon_scout", "vuln_hunter"],
        "max_turns": 10,
        "max_time_hours": 0.5,
        "objectives": ["recon", "vuln_assessment"],
        "stealth": "normal",
    },
    "enterprise_standard": {
        "description": "Enterprise standard assessment (2 hours)",
        "agents": ["recon_scout", "vuln_hunter", "pentest_agent"],
        "max_turns": 30,
        "max_time_hours": 2.0,
        "objectives": ["recon", "vuln_assessment", "exploitation"],
        "stealth": "normal",
    },
    "enterprise_deep": {
        "description": "Enterprise deep penetration test (8 hours)",
        "agents": ["recon_scout", "vuln_hunter", "pentest_agent", "network_analyst"],
        "max_turns": 100,
        "max_time_hours": 8.0,
        "objectives": ["recon", "vuln_assessment", "exploitation", "lateral_movement"],
        "stealth": "low",
    },
    "enterprise_compliance": {
        "description": "Enterprise compliance assessment (4 hours)",
        "agents": ["vuln_hunter"],
        "max_turns": 40,
        "max_time_hours": 4.0,
        "objectives": ["recon", "vuln_assessment", "compliance_check"],
        "stealth": "normal",
        "report_type": "compliance",
        "compliance_frameworks": ["pci-dss", "mitic", "iso-27001"],
    },
}


def get_profile(name: str) -> dict | None:
    """Get a scan profile by name."""
    return SCAN_PROFILES.get(name)


def list_profiles() -> list[dict]:
    """List all available scan profiles."""
    return [{"name": k, **v} for k, v in SCAN_PROFILES.items()]
