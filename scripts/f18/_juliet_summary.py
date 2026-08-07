import json
import sys

d = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "/tmp/bench_juliet_f74c.json"))
recall = d["recall"]
pooled = {}
for r in recall:
    rn = r["runner"]
    if rn not in pooled:
        pooled[rn] = {"total": 0, "any_hits": 0, "cwe_hits": 0}
    n = r["files_total"]
    pooled[rn]["total"] += n
    pooled[rn]["any_hits"] += int(round(r["recall_any"] * n))
    pooled[rn]["cwe_hits"] += int(round(r["recall_cwe"] * n))

for rn, p in pooled.items():
    any_pct = p["any_hits"] / max(1, p["total"]) * 100
    cwe_pct = p["cwe_hits"] / max(1, p["total"]) * 100
    t = p["total"]
    print(f"{rn:10}  recall@any={any_pct:.1f}%  recall@CWE={cwe_pct:.1f}%  N={t}")

print()
print(f"Duration: {d['duration_s']:.1f}s")
print(f"FPR baseline: {d['baseline_repo']}  ({d['baseline_files_scanned']} files)")
print("FPR:")
for rn, f in d["fpr"].items():
    if isinstance(f, dict):
        rate_pct = f.get("rate", 0) * 100
        n_hit = f.get("files_with_finding", 0)
        n_tot = f.get("total", 0)
        print(f"  {rn:10}  {n_hit}/{n_tot} = {rate_pct:.1f}%")
