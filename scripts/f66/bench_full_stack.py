"""F66.1.c — End-to-end bench of the full F66/F67 stack vs Juice Shop.

Pipeline (deterministic, no LLM):
  1. WAF probe (F67.1)
  2. Dispatch 6 experts (F66.1.a)
  3. Ingest findings into knowledge graph + chain (F67.2)
  4. Final Judge audit (F67.5)
  5. Consolidated score
"""
from __future__ import annotations

import json
import sys

from kryon.webexploit.experts import dispatch_experts
from kryon.webexploit.final_judge import run_final_judge
from kryon.webexploit.knowledge_graph import KnowledgeGraph
from kryon.webexploit.proxy import HttpSession
from kryon.webexploit.waf_evasion import probe_waf_presence


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "http://juice.local:3000"

    def sf() -> HttpSession:
        return HttpSession()

    # STEP 1 — WAF probe
    print(f"=== STEP 1: WAF probe against {target} ===")
    waf = probe_waf_presence(sf, target)
    print(f"  waf: {'None (clean)' if waf is None else waf.title}")

    # STEP 2 — Experts
    print()
    print("=== STEP 2: Dispatch 6 experts (budget=60) ===")
    results = dispatch_experts(target, sf, total_budget=60)
    all_findings = []
    for r in results:
        print(f"  {r.expert_id:12} findings={len(r.findings):2} "
              f"budget={r.budget_used}/{r.budget_available}")
        all_findings.extend(r.findings)
    print(f"  total: {len(all_findings)} findings")

    # STEP 3 — Knowledge graph
    print()
    print("=== STEP 3: Knowledge graph + chaining ===")
    g = KnowledgeGraph("f66-bench")
    g.ingest_findings(all_findings)
    chains = g.find_chains()
    print(f"  nodes={len(g.nodes)} edges={len(g.edges)} chains={len(chains)}")
    chain_ids_seen = set()
    for c in chains:
        if c.chain_id not in chain_ids_seen:
            print(f"    [{c.chain_id}] +{c.severity_bump}")
            chain_ids_seen.add(c.chain_id)

    upgraded = g.apply_severity_upgrades(all_findings, chains)
    bumps = sum(1 for o, u in zip(all_findings, upgraded)
                if o.severity != u.severity)
    print(f"  severity bumps applied: {bumps}")

    # STEP 4 — Final Judge
    print()
    print("=== STEP 4: Final Judge audit ===")
    verdict = run_final_judge(
        upgraded,
        expert_results=results,
        crawl_endpoints=[],
        waf_probed=True,
        chain_matches=chains,
    )
    print(f"  verdict: {verdict.verdict}")
    print(f"  items: {len(verdict.action_items)} "
          f"(CRIT={verdict.critical_count()} HIGH={verdict.high_count()})")
    for a in verdict.action_items:
        print(f"    [{a.severity}] {a.anti_pattern}: {a.message[:90]}")

    # STEP 5 — Summary
    print()
    print("=== STEP 5: Consolidated score ===")
    by_sev = {}
    by_type = {}
    by_cwe = {}
    for f in upgraded:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_type[f.finding_type] = by_type.get(f.finding_type, 0) + 1
        by_cwe[f.cwe_id] = by_cwe.get(f.cwe_id, 0) + 1

    print(f"  findings emitted: {len(upgraded)}")
    print(f"  by severity: {json.dumps(by_sev, sort_keys=True)}")
    print(f"  by finding_type: {json.dumps(by_type, sort_keys=True)}")
    print(f"  by CWE: {json.dumps(dict(sorted(by_cwe.items())))}")

    critical = [f for f in upgraded if f.severity.upper() == "CRITICAL"]
    print(f"  CRITICAL findings ({len(critical)}):")
    for f in critical:
        print(f"    - {f.cwe_id}: {f.title[:70]}")

    return 0 if verdict.verdict != "FAIL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
