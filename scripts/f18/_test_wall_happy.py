"""Happy-path test: mock Ollama returns a valid chat completion quickly;
assert call_llm() parses the JSON and returns it.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FAKE_RESPONSE = {
    "choices": [{
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "call_0",
                "type": "function",
                "function": {
                    "name": "shell",
                    "arguments": '{"command": "curl -s http://juice.local:3000/api/Challenges | head -c 200"}',
                }
            }]
        }
    }]
}


class FastHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = json.dumps(FAKE_RESPONSE).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> None:
    port = _free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), FastHandler)
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"fast mock listening on port {port}")

    os.environ["OLLAMA_HOST_URL"] = f"http://127.0.0.1:{port}/v1"
    os.environ["KRYON_MODEL"] = "stub"

    import importlib
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    bench = importlib.import_module("juice_shop_llm_bench")

    t0 = time.time()
    try:
        result = bench.call_llm(
            [{"role": "user", "content": "ping"}],
            timeout_s=10,
            retries=0,
        )
    except Exception as exc:
        print(f"FAIL: unexpected exception {type(exc).__name__}: {exc}")
        raise SystemExit(1)
    elapsed = time.time() - t0

    if elapsed > 2:
        print(f"FAIL: happy path too slow ({elapsed:.2f}s)")
        raise SystemExit(1)

    msg = result["choices"][0]["message"]
    tcs = msg.get("tool_calls") or []
    if len(tcs) != 1 or tcs[0]["function"]["name"] != "shell":
        print(f"FAIL: unexpected response {result!r}")
        raise SystemExit(1)

    print(f"OK: happy path returned in {elapsed:.2f}s with tool_call={tcs[0]['function']['name']}")
    print("happy-path smoke test passed")


if __name__ == "__main__":
    main()
