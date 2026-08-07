"""F84.7 — Offline ITR tool-index builder.

Embeds every tool's docstring with the configured Ollama embedder
and persists the index to $KRYON_HOME/itr_index.npz. Run once after
installing Kryon, and again whenever the tool registry changes (the
sidecar's per-doc hash + the `is_index_stale` helper let an installer
detect this automatically).

Usage:
  python -m scripts.build_itr_index               # rebuild always
  python -m scripts.build_itr_index --check       # check staleness, exit 1 if stale
  python -m scripts.build_itr_index --if-stale    # only rebuild when stale
  python -m scripts.build_itr_index --out /custom/idx.npz
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

from kryon.skills.itr_tool_index import (
    DEFAULT_EMBEDDING_MODEL,
    DEFAULT_INDEX_PATH,
    OllamaEmbedder,
    build_index,
    is_index_stale,
    save_index,
)
from kryon.skills.tool_budget import build_tool_registry

logger = logging.getLogger("build_itr_index")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="F84.7 ITR index builder")
    ap.add_argument("--out", default=str(DEFAULT_INDEX_PATH), help="output .npz path")
    ap.add_argument(
        "--model",
        default=DEFAULT_EMBEDDING_MODEL,
        help="Ollama embedding model (default: nomic-embed-text)",
    )
    g = ap.add_mutually_exclusive_group()
    g.add_argument(
        "--check",
        action="store_true",
        help="exit 1 when the index is stale; do not rebuild",
    )
    g.add_argument(
        "--if-stale",
        action="store_true",
        help="rebuild only when the index is stale; otherwise no-op",
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )

    out_path = Path(args.out)
    logger.info("Building registry...")
    registry = build_tool_registry()
    logger.info("Registry: %d tools indexed", len(registry))

    if args.check:
        stale = is_index_stale(registry, path=out_path, embedder_model=args.model)
        logger.info("Index at %s is %s", out_path, "STALE" if stale else "FRESH")
        return 1 if stale else 0

    if args.if_stale and not is_index_stale(registry, path=out_path, embedder_model=args.model):
        logger.info("Index at %s is FRESH — skipping rebuild.", out_path)
        return 0

    logger.info("Embedding %d tools with %s ...", len(registry), args.model)
    embedder = OllamaEmbedder(model=args.model)
    started = time.monotonic()
    index, hashes = build_index(registry, embedder)
    elapsed = time.monotonic() - started
    logger.info("Embedded %d/%d tools in %.1fs", len(index), len(registry), elapsed)

    if not index:
        logger.error("Index is empty — embedder produced no vectors. Aborting save.")
        return 2

    written = save_index(index, hashes, path=out_path, embedder_model=args.model)
    logger.info("Wrote %s (%d tools).", written, len(index))
    return 0


if __name__ == "__main__":
    sys.exit(main())
