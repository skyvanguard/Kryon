"""Parse NVD CVE JSON for F13.0 corpus. Fixes prior f-string quoting bug."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def summarize(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    vulns = data.get("vulnerabilities", [])
    print(f"\n=== {path.name} — {len(vulns)} CVE(s) ===")
    print(f"{'CVE':<18} {'Published':<12} {'CVSS':<9} Description")
    print("-" * 110)
    for v in vulns:
        c = v.get("cve", {})
        cve_id = c.get("id", "?")
        pub = (c.get("published") or "")[:10]
        metrics = c.get("metrics", {})
        cvss = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                cvss = str(entries[0].get("cvssData", {}).get("baseScore", ""))
                break
        desc_entries = c.get("descriptions", [])
        desc = next((d.get("value", "") for d in desc_entries if d.get("lang") == "en"), "")
        desc = desc.replace("\n", " ")[:70]
        print(f"{cve_id:<18} {pub:<12} {cvss:<9} {desc}")


if __name__ == "__main__":
    base = Path(__file__).parent / "cve"
    for name in sys.argv[1:] or ["fineract-nvd.json", "gnucash-nvd.json"]:
        summarize(base / name)
