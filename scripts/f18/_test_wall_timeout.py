"""Smoke test for the F18 hard-wall LLM timeout.

Starts a tiny HTTP server that trickles bytes forever (simulating a hung
Ollama), points the bench at it, and asserts that call_llm() raises within
`timeout_s + tolerance` seconds. This isolates the urllib-replacement fix
from real Ollama availability.
"""
from __future__ import annotations

import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class SlowTrickleHandler(BaseHTTPRequestHandler):
    """Streams one byte every 200ms, never completes. Mimics a stuck model."""

    def do_POST(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            for i in range(600):  # up to 2 minutes of trickle
                chunk = f"1\r\n{chr(ord('a') + (i % 26))}\r\n".encode()
                self.wfile.write(chunk)
                self.wfile.flush()
                time.sleep(0.2)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format: str, *args: object) -> None:
        pass  # silence


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> None:
    port = _free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), SlowTrickleHandler)
    # daemon_threads=True so outstanding trickle handlers die with the
    # interpreter when main() finishes.
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"slow-trickle server listening on port {port}")

    os.environ["OLLAMA_HOST_URL"] = f"http://127.0.0.1:{port}/v1"
    os.environ["KRYON_MODEL"] = "stub"

    import importlib
    import sys

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    bench = importlib.import_module("juice_shop_llm_bench")

    budget = 5
    t0 = time.time()
    try:
        bench.call_llm(
            [{"role": "user", "content": "ping"}],
            timeout_s=budget,
            retries=0,
        )
        print("FAIL: call_llm returned without raising")
        raise SystemExit(1)
    except TimeoutError as exc:
        elapsed = time.time() - t0
        print(f"OK: TimeoutError after {elapsed:.2f}s — {exc}")
        # Tolerance: executor cleanup + thread pool shutdown can add ~1s.
        if elapsed > budget + 3:
            print(f"FAIL: too slow ({elapsed:.2f}s > {budget + 3}s)")
            raise SystemExit(1)
    except Exception as exc:
        elapsed = time.time() - t0
        print(f"FAIL: wrong exception type after {elapsed:.2f}s: {type(exc).__name__}: {exc}")
        raise SystemExit(1)
    finally:
        # server.shutdown() would block until serve_forever() returns; we
        # rely on daemon=True to kill the server thread at interpreter exit
        # instead, because outstanding trickle connections would keep
        # shutdown() blocked on a join().
        pass

    print("wall-timeout smoke test passed")


if __name__ == "__main__":
    main()
