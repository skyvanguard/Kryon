"""F145 — ``kryon api serve`` subcommand."""

from __future__ import annotations

import argparse
import sys


def add_api_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser("api", help="F145 — REST API server")
    sub = p.add_subparsers(dest="api_action", required=True)
    serve = sub.add_parser("serve", help="Start the FastAPI server (uvicorn)")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8800)
    serve.add_argument("--reload", action="store_true")
    return p


def run_api_command(args) -> int:
    if args.api_action != "serve":
        print(f"api: unknown action '{args.api_action}'", file=sys.stderr)
        return 2
    try:
        import uvicorn

        from kryon.api import build_app
    except ImportError as exc:
        print(f"api serve: missing dep ({exc}). Install fastapi + uvicorn.", file=sys.stderr)
        return 2

    app = build_app()
    uvicorn.run(app, host=args.host, port=args.port, reload=args.reload)
    return 0
