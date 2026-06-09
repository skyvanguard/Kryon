"""Fase 1 (v3) — combine the Pentest-R1 conversion with the anti-loop negatives.

Run AFTER convert_dataset.py (writes train.jsonl/val.jsonl from Pentest-R1) and
make_antiloop.py (writes antiloop.jsonl). Produces v3 train/val by mixing the
anti-loop examples in, with a deterministic shuffle and a held-out split so
some anti-loop examples land in val too.

    python scripts/finetune/convert_dataset.py --out data/finetune
    python scripts/finetune/make_antiloop.py --out data/finetune/antiloop.jsonl --min 500
    python scripts/finetune/combine_dataset.py --out data/finetune

Writes data/finetune/train.jsonl + val.jsonl (overwrites with the combined set).
Idempotent within a fixed input set: it reads the *pentest* split from
pentest_train.jsonl / pentest_val.jsonl if present, else snapshots the current
train/val into those files first so re-runs don't double-count.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path


def _read(p: Path) -> list[dict]:
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def _write(p: Path, rows: list[dict]) -> None:
    with p.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/finetune")
    ap.add_argument("--antiloop", default="data/finetune/antiloop.jsonl")
    ap.add_argument("--val-frac", type=float, default=0.1)
    args = ap.parse_args()

    out = Path(args.out)
    # Snapshot the pentest-only split on first run so re-running combine doesn't
    # keep appending anti-loop into an already-combined train set.
    pen_train_f, pen_val_f = out / "pentest_train.jsonl", out / "pentest_val.jsonl"
    if not pen_train_f.exists():
        (out / "train.jsonl").replace(pen_train_f)
        (out / "val.jsonl").replace(pen_val_f)
    pen_train, pen_val = _read(pen_train_f), _read(pen_val_f)

    anti = _read(Path(args.antiloop))
    rng = random.Random(42)
    rng.shuffle(anti)
    n_val = max(1, int(len(anti) * args.val_frac))
    anti_val, anti_train = anti[:n_val], anti[n_val:]

    train = pen_train + anti_train
    val = pen_val + anti_val
    rng.shuffle(train)
    rng.shuffle(val)

    _write(out / "train.jsonl", train)
    _write(out / "val.jsonl", val)
    print(f"pentest: train={len(pen_train)} val={len(pen_val)}")
    print(f"antiloop: train={len(anti_train)} val={len(anti_val)}")
    print(f"COMBINED v3: train={len(train)} val={len(val)}")
    print(f"  anti-loop share of train: {len(anti_train) / len(train) * 100:.0f}% of examples")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
