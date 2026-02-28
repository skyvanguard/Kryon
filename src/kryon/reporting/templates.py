"""Report templates — predefined styles for different report audiences."""

from __future__ import annotations

TEMPLATES = {
    "military": {
        "name": "Military Grade",
        "description": "High-contrast dark theme with severity color coding",
        "css": """
body { background: #0a0a1a; color: #e0e0e0; font-family: 'Courier New', monospace; }
h1, h2, h3 { color: #00ff41; border-bottom: 1px solid #00ff41; padding-bottom: 8px; }
.section { background: #111; border: 1px solid #333; border-radius: 4px; padding: 20px; margin: 15px 0; }
.findings-table { width: 100%; border-collapse: collapse; }
.findings-table th { background: #1a1a2e; color: #00d4ff; padding: 8px; text-align: left; }
.findings-table td { padding: 8px; border-bottom: 1px solid #222; }
.severity-critical { color: #ff0000; font-weight: bold; }
.severity-high { color: #ff6600; }
.severity-medium { color: #ffcc00; }
.severity-low { color: #00cc00; }
""",
    },
    "executive": {
        "name": "Executive Summary",
        "description": "Clean, professional theme for C-suite presentations",
        "css": """
body { background: #fff; color: #333; font-family: 'Segoe UI', 'Inter', sans-serif; max-width: 900px; margin: 0 auto; padding: 40px; }
h1 { color: #1a365d; font-size: 28px; }
h2 { color: #2d3748; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }
.section { margin: 25px 0; }
.findings-table { width: 100%; border-collapse: collapse; }
.findings-table th { background: #edf2f7; color: #2d3748; padding: 10px; text-align: left; font-size: 13px; }
.findings-table td { padding: 10px; border-bottom: 1px solid #e2e8f0; font-size: 14px; }
.severity-critical { background: #fed7d7; color: #9b2c2c; padding: 2px 8px; border-radius: 4px; }
.severity-high { background: #feebc8; color: #c05621; padding: 2px 8px; border-radius: 4px; }
.severity-medium { background: #fefcbf; color: #975a16; padding: 2px 8px; border-radius: 4px; }
.severity-low { background: #c6f6d5; color: #276749; padding: 2px 8px; border-radius: 4px; }
""",
    },
    "technical": {
        "name": "Technical Detail",
        "description": "Detailed technical report with evidence and code blocks",
        "css": """
body { background: #fafafa; color: #1a202c; font-family: 'JetBrains Mono', 'Fira Code', monospace; padding: 30px; }
h1 { color: #2b6cb0; }
h2 { color: #2c5282; border-left: 4px solid #3182ce; padding-left: 12px; }
pre, code { background: #1a202c; color: #e2e8f0; padding: 12px; border-radius: 6px; overflow-x: auto; }
.section { margin: 20px 0; }
.findings-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.findings-table th { background: #2b6cb0; color: white; padding: 8px; text-align: left; }
.findings-table td { padding: 8px; border-bottom: 1px solid #e2e8f0; }
.severity-critical { color: #e53e3e; font-weight: bold; }
.severity-high { color: #dd6b20; font-weight: bold; }
""",
    },
    "compliance": {
        "name": "Compliance Audit",
        "description": "Formal audit report with control mapping and evidence references",
        "css": """
body { background: #fff; color: #2d3748; font-family: 'Times New Roman', serif; padding: 40px; line-height: 1.8; }
h1 { color: #1a365d; text-align: center; border-bottom: 3px double #1a365d; padding-bottom: 15px; }
h2 { color: #2c5282; }
.section { margin: 20px 0; page-break-inside: avoid; }
.findings-table { width: 100%; border-collapse: collapse; margin: 15px 0; }
.findings-table th { background: #1a365d; color: white; padding: 10px; text-align: left; }
.findings-table td { padding: 10px; border: 1px solid #cbd5e0; }
.severity-critical { background: #fc8181; color: #742a2a; }
.severity-high { background: #f6ad55; color: #7b341e; }
""",
    },
}


def get_template_css(template_name: str) -> str:
    """Get CSS for a named template."""
    template = TEMPLATES.get(template_name.lower())
    if not template:
        return TEMPLATES["technical"]["css"]
    return template["css"]


def list_templates() -> list[dict]:
    """List available report templates."""
    return [
        {"id": k, "name": v["name"], "description": v["description"]}
        for k, v in TEMPLATES.items()
    ]
