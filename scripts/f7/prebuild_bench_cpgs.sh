#!/usr/bin/env bash
# F7.5 — pre-parse CPGs for the Juliet samples that the recall bench will
# hit. Uses the SAME seeding as scripts/bench_juliet.py (find_cwe_files,
# seed=42) so the CPG cache lines up with the files the bench picks.
#
# Only CWE-121 and CWE-190 are pre-parsed because the current Joern
# queries target those families. For other CWEs the JoernHunter falls
# back to importCode() with timeout — any timeouts show up in
# hunters_failed in the final report.
set -euo pipefail

OUT=/tmp/f7-cpgs
JOERN=/tmp/joern/joern-cli
SAMPLES=${1:-20}
mkdir -p "$OUT"

# Enumerate target files using the same seed as scripts/bench_juliet.py.
python3 - <<'PY'
import json, os, pathlib, random
JULIET = pathlib.Path("/workspace/.juliet/juliet-test-suite-c/testcases")
SAMPLES = int(os.environ.get("SAMPLES", "20"))

def find_cwe_files(cwe: int, n: int, seed: int = 42):
    """MUST match scripts/bench_juliet.py::find_cwe_files exactly."""
    rng = random.Random(seed)
    candidates = []
    for d in JULIET.glob(f"CWE{cwe}_*"):
        if not d.is_dir():
            continue
        for f in d.rglob("*.c"):
            name = f.name
            if any(suf in name for suf in ("a.c", "b.c", "c.c", "d.c", "e.c")):
                continue
            candidates.append(f)
    rng.shuffle(candidates)
    return candidates[:n]

out = {}
for cwe in (121, 190):
    out[cwe] = [str(p) for p in find_cwe_files(cwe, SAMPLES, seed=42)]
with open("/tmp/f7-bench-targets.json", "w") as f:
    json.dump(out, f, indent=2)
print(f"[enum] {sum(len(v) for v in out.values())} files")
PY

# Pre-parse each file into OUT/<basename>.cpg
python3 - <<PY
import json, os, pathlib, subprocess, sys, time
targets = json.load(open("/tmp/f7-bench-targets.json"))
joern_parse = "/tmp/joern/joern-cli/joern-parse"
out_dir = pathlib.Path("$OUT")
stage_root = pathlib.Path("/tmp/f7-stage")
stage_root.mkdir(exist_ok=True)
t0 = time.time()
done, skipped = 0, 0
for cwe, files in targets.items():
    for src in files:
        stem = pathlib.Path(src).stem
        cpg = out_dir / f"{stem}.cpg"
        if cpg.is_file():
            skipped += 1
            continue
        stage = stage_root / stem
        stage.mkdir(exist_ok=True)
        dst = stage / pathlib.Path(src).name
        if not dst.exists():
            dst.write_bytes(pathlib.Path(src).read_bytes())
        try:
            subprocess.run(
                [joern_parse, str(stage), "--output", str(cpg)],
                capture_output=True, text=True, timeout=180, check=True,
            )
            done += 1
        except subprocess.TimeoutExpired:
            print(f"[timeout] {stem}")
        except subprocess.CalledProcessError as e:
            print(f"[fail] {stem}: {e.stderr[-200:]}")
print(f"[done] parsed={done}  skipped(cached)={skipped}  elapsed={time.time()-t0:.1f}s")
PY

ls "$OUT"/*.cpg | wc -l
echo "CPGs ready in $OUT"
