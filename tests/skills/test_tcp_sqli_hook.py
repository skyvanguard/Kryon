"""F206 — interactive-TCP-SQLi pre_hook (tcp_sqli_hook.py).

The hook drives a live SQL injection over a raw TCP socket, so the high-value check is end-to-end
against a faithful mock of the THM Light service: a real sqlite3 backend queried as
``SELECT password FROM usertable WHERE username='<input>' LIMIT 30``, fronted by the exact "--badr"
keyword filter (blocks ``--``, ``/*``, the word ``or``, ``%0b``). If the hook's socket transport +
filter-bypass (mixed-case UNION + quote-balancing) + sqlite_master dump all work against that mock,
they work against the real box (the SQL technique was already confirmed live on Light v1.2). Plus the
pure-logic units and the graceful-on-unreachable invariant.
"""

from __future__ import annotations

import importlib.util
import re
import socketserver
import sqlite3
import threading
from pathlib import Path

import pytest

_HOOK = Path(__file__).resolve().parents[2] / "src/kryon/skills/playbooks/cwe-detection/tcp_sqli_hook.py"


def _load():
    spec = importlib.util.spec_from_file_location("tcp_sqli_hook", _HOOK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- faithful Light mock: sqlite3 + the --badr keyword filter ------------------------------

_BLOCKED_SUBSTR = ("--", "/*", "%0b")


def _is_blocked(s: str) -> bool:
    low = s.lower()
    if any(b in low for b in _BLOCKED_SUBSTR):
        return True
    return bool(re.search(r"\bor\b", low))  # word 'or' only -> 'password' (passwORd) still passes


class _LightHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        db = sqlite3.connect(":memory:")
        db.execute("CREATE TABLE usertable(username text, password text)")
        db.execute("INSERT INTO usertable VALUES('smokey','vYQ5ngPpw8AdUmL')")
        db.execute("CREATE TABLE admintable(username text, password text)")
        db.executemany(
            "INSERT INTO admintable VALUES(?,?)",
            [("TryHackMeAdmin", "mamZtAuMlrsEy5bp6q17"), ("flag", "THM{mock_sqli_flag}")],
        )
        db.commit()
        self.request.sendall(b"Welcome to the Light database!\nPlease enter your username: ")
        self.request.settimeout(3)
        while True:
            try:
                data = self.request.recv(4096)
            except OSError:
                break
            if not data:
                break
            line = data.decode("utf-8", "replace").strip()
            if _is_blocked(line):
                self.request.sendall(
                    b"any input containing /*, -- or, %0b is not allowed :)\nPlease enter your username: "
                )
                continue
            try:
                rows = db.execute(
                    f"SELECT password FROM usertable WHERE username='{line}' LIMIT 30"  # noqa: S608 (mock SQLi target)
                ).fetchall()
                val = rows[0][0] if rows else ""
                self.request.sendall(f"Password: {val}\nPlease enter your username: ".encode())
            except Exception as exc:  # surface the SQL error like the real app
                self.request.sendall(f"Error: {exc}\nPlease enter your username: ".encode())


class _ReuseServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@pytest.fixture
def mock_light():
    srv = _ReuseServer(("127.0.0.1", 0), _LightHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield "127.0.0.1", port
    finally:
        srv.shutdown()
        srv.server_close()


# --- end-to-end: the whole chain against the mock -----------------------------------------


def test_hook_extracts_admin_creds_and_flag(mock_light):
    host, port = mock_light
    report = _load().run({"target": f"{host}:{port}"})
    assert "SQLi CONFIRMED (SQLite)" in report
    assert "uNiOn SeLeCt" in report or "quote-balancing" in report  # the bypass it chose/announced
    assert "TryHackMeAdmin:mamZtAuMlrsEy5bp6q17" in report  # dumped from admintable via UNION
    assert "THM{mock_sqli_flag}" in report
    assert "FLAG(S)" in report and "GROUND TRUTH" in report


def test_hook_finds_tables_via_sqlite_master(mock_light):
    host, port = mock_light
    report = _load().run({"target": f"{host}:{port}"})
    assert "usertable" in report and "admintable" in report  # enumerated, not hardcoded


# --- pure logic ----------------------------------------------------------------------------


def test_host_port_parsing():
    mod = _load()
    assert mod._host_port("10.0.0.5:1337") == ("10.0.0.5", 1337)
    assert mod._host_port("tcp://10.0.0.5:1337/x") == ("10.0.0.5", 1337)
    assert mod._host_port("10.0.0.5") == ("10.0.0.5", None)
    assert mod._host_port("") == ("", None)


def test_payload_build_styles():
    mod = _load()
    # comment style uses -- (blocked by --badr); balance style avoids comments entirely.
    assert mod._build("uNiOn SeLeCt 1", "comment").endswith("-- -")
    assert "WHERE 'a'='a" in mod._build("uNiOn SeLeCt 1", "balance")
    assert "--" not in mod._build("uNiOn SeLeCt 1", "balance")


def test_result_extraction_and_filter_and_error():
    mod = _load()
    assert (
        mod._result("Please enter your username: Password: vYQ5ngPpw8AdUmL\nPlease enter your username:")
        == "vYQ5ngPpw8AdUmL"
    )
    assert mod._is_sql_error("Error: unrecognized token: \"''' LIMIT 30\"")
    assert mod._is_filtered("any input containing /*, -- or, %0b is not allowed :)")
    assert not mod._is_sql_error("Password: hunter2")


def test_parse_columns_from_create():
    cols = _load()._parse_columns(
        "CREATE TABLE admintable(id int, username text, password text);CREATE TABLE usertable(username text, password text)"
    )
    assert cols["admintable"] == ["id", "username", "password"]
    assert cols["usertable"] == ["username", "password"]


def test_graceful_on_no_host_and_unreachable():
    mod = _load()
    assert "no target host" in mod.run({})
    # closed port on loopback -> connect refused fast -> no prompt service found, never raises.
    out = mod.run({"target": "127.0.0.1:9"})
    assert isinstance(out, str) and ("skipped" in out or "no injection" in out)
