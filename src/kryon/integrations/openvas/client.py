"""GMP client for OpenVAS / Greenbone.

Kryon talks to a **stock, unmodified** Greenbone Community Edition (own
container) over the Greenbone Management Protocol (GMP). Two transports:

* ``gmp_socket_runner`` (**default**) — speaks GMP directly over gvmd's socket.
  Depends on ZERO Greenbone code — just a documented protocol, like HTTP.
  Nothing GPL/AGPL is imported, bundled or distributed.
* ``gvm_cli_runner`` (opt-in via KRYON_OPENVAS_TRANSPORT=cli) — shells out to
  ``gvm-cli`` (GPL-3.0) at arm's length (subprocess, never imported). Needs
  gvm-tools installed separately.

Both keep Kryon and Greenbone as *separate programs* (mere aggregation), a
clean license boundary. **Do not fork or modify the Greenbone components** —
running them stock reduces our obligation to "point at the upstream source".

The scan lifecycle (create_target → create_task → start_task → poll →
get_results) is orchestrated here; the actual GMP execution is behind an
injectable ``runner`` so the whole client is unit-testable without a live
Greenbone.
"""

from __future__ import annotations

import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field

# Well-known GMP object UUIDs — stable across Greenbone installs.
SCAN_CONFIG_FULL_AND_FAST = "daba56c8-73ec-11df-a475-002264764cea"
SCANNER_OPENVAS_DEFAULT = "08b69003-5fc2-4037-a479-93b440211c73"
PORT_LIST_ALL_IANA_TCP = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"

_DONE = "Done"
_TERMINAL_BAD = {"Stopped", "Interrupted", "Stop Requested"}

# A runner takes one GMP XML command and returns the response XML text.
GmpRunner = Callable[[str], str]


class OpenVASError(RuntimeError):
    """A GMP call failed, timed out, or returned a non-OK status."""


# --------------------------------------------------------------------------
# Default runner — shells out to gvm-cli over the local gvmd socket.
# --------------------------------------------------------------------------
def gvm_cli_runner(
    *,
    socket_path: str = "/run/gvmd/gvmd.sock",
    username: str,
    password: str,
    timeout_s: int = 900,
) -> GmpRunner:
    """Build a runner that executes GMP via `gvm-cli` (arm's-length subprocess)."""

    def run(gmp_xml: str) -> str:
        binary = shutil.which("gvm-cli") or "gvm-cli"
        argv = [
            binary,
            "--gmp-username",
            username,
            "--gmp-password",
            password,
            "socket",
            "--socketpath",
            socket_path,
            "--xml",
            gmp_xml,
        ]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s)  # noqa: S603
        except subprocess.TimeoutExpired as exc:
            raise OpenVASError(f"gvm-cli timed out after {timeout_s}s") from exc
        except (FileNotFoundError, OSError) as exc:
            raise OpenVASError(f"gvm-cli not runnable: {exc}") from exc
        if proc.returncode != 0:
            raise OpenVASError(f"gvm-cli exit {proc.returncode}: {proc.stderr[:500]}")
        return proc.stdout

    return run


# --------------------------------------------------------------------------
# Raw GMP-over-socket runner — zero Greenbone code (max license cleanliness).
#
# gvm_cli_runner (above) shells out to gvm-cli (GPL-3.0). This path speaks GMP
# directly over gvmd's socket, so Kryon depends on NO Greenbone code at all —
# just a documented protocol, like talking HTTP. Nothing to distribute, nothing
# to attribute. The transport (`connect`) is injectable so it's fully testable
# with a fake socket.
# --------------------------------------------------------------------------
class GmpConnection:
    """Frames GMP request/response over a stream socket.

    GMP responses are a single XML root element with no length prefix, so we
    read until the root element closes (incremental parse tracks element depth).
    """

    def __init__(self, sock, *, recv_size: int = 8192):
        self._sock = sock
        self._recv = recv_size

    def send(self, gmp_xml: str) -> None:
        self._sock.sendall(gmp_xml.encode("utf-8"))

    def read_response(self) -> str:
        # GMP sends exactly one root element per response, with no length
        # prefix. Read until the accumulated buffer is a complete, well-formed
        # XML document. (Incremental start/end events defer the 'end' of a
        # self-closing root — e.g. <authenticate_response .../> — so we test
        # completeness by parsing, gated on the tail looking like a closing '>'
        # to avoid re-parsing every partial chunk.)
        chunks: list[bytes] = []
        while True:
            chunk = self._sock.recv(self._recv)
            if not chunk:
                raise OpenVASError("GMP connection closed before a complete response")
            chunks.append(chunk)
            buf = b"".join(chunks)
            if buf.rstrip().endswith(b">"):
                try:
                    ET.fromstring(buf)
                except ET.ParseError:
                    continue  # not a complete document yet — keep reading
                return buf.decode("utf-8", "replace")


def _default_connect(
    *, socket_path: str, use_tls: bool, host: str, port: int, cafile: str, insecure_tls: bool, timeout_s: int
):
    import socket as _sock

    if use_tls:
        import ssl as _ssl

        raw = _sock.create_connection((host, port), timeout=timeout_s)
        if cafile:
            ctx = _ssl.create_default_context(cafile=cafile)
            return ctx.wrap_socket(raw, server_hostname=host)
        if insecure_tls:
            # Opt-in only: gvmd ships a self-signed CA. Prefer providing cafile.
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            return ctx.wrap_socket(raw)
        raise OpenVASError("TLS requested without a CA file (set cafile or opt into insecure_tls)")

    s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
    s.settimeout(timeout_s)
    s.connect(socket_path)
    return s


def gmp_socket_runner(
    *,
    username: str,
    password: str,
    socket_path: str = "/run/gvmd/gvmd.sock",
    use_tls: bool = False,
    host: str = "127.0.0.1",
    port: int = 9390,
    cafile: str = "",
    insecure_tls: bool = False,
    timeout_s: int = 900,
    connect: Callable[[], object] | None = None,
) -> GmpRunner:
    """Build a runner that speaks GMP directly (no gvm-cli). Authenticates, sends
    one command, returns the response XML. ``connect`` is injectable for tests."""

    def _open():
        if connect is not None:
            return connect()
        return _default_connect(
            socket_path=socket_path,
            use_tls=use_tls,
            host=host,
            port=port,
            cafile=cafile,
            insecure_tls=insecure_tls,
            timeout_s=timeout_s,
        )

    def run(gmp_xml: str) -> str:
        sock = _open()
        try:
            conn = GmpConnection(sock)
            conn.send(
                f"<authenticate><credentials><username>{_esc(username)}</username>"
                f"<password>{_esc(password)}</password></credentials></authenticate>"
            )
            _root_ok(conn.read_response(), "authenticate")
            conn.send(gmp_xml)
            return conn.read_response()
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001 — best-effort cleanup
                pass

    return run


# --------------------------------------------------------------------------
# Pure GMP command builders (testable, no I/O).
# --------------------------------------------------------------------------
def _esc(text: str) -> str:
    """Minimal XML-attribute/text escaping for values we inject into GMP."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def build_create_target(name: str, hosts: str, port_list_id: str = PORT_LIST_ALL_IANA_TCP) -> str:
    return (
        f"<create_target><name>{_esc(name)}</name>"
        f"<hosts>{_esc(hosts)}</hosts>"
        f'<port_list id="{_esc(port_list_id)}"/></create_target>'
    )


def build_create_task(
    name: str,
    target_id: str,
    config_id: str = SCAN_CONFIG_FULL_AND_FAST,
    scanner_id: str = SCANNER_OPENVAS_DEFAULT,
) -> str:
    return (
        f"<create_task><name>{_esc(name)}</name>"
        f'<config id="{_esc(config_id)}"/>'
        f'<target id="{_esc(target_id)}"/>'
        f'<scanner id="{_esc(scanner_id)}"/></create_task>'
    )


def build_start_task(task_id: str) -> str:
    return f'<start_task task_id="{_esc(task_id)}"/>'


def build_get_task(task_id: str) -> str:
    return f'<get_tasks task_id="{_esc(task_id)}"/>'


def build_get_results(task_id: str) -> str:
    # details=1 pulls the NVT refs/solution/tags we need for the normalizer.
    return f'<get_results task_id="{_esc(task_id)}" details="1"/>'


# --------------------------------------------------------------------------
# Pure GMP response parsers (testable, no I/O).
# --------------------------------------------------------------------------
def _root_ok(resp_xml: str, action: str) -> ET.Element:
    try:
        root = ET.fromstring(resp_xml)
    except ET.ParseError as exc:
        raise OpenVASError(f"{action}: unparseable GMP response ({exc})") from exc
    status = root.get("status", "")
    if not status.startswith("2"):
        raise OpenVASError(f"{action} failed: status={status or '?'} {root.get('status_text', '')}")
    return root


def parse_created_id(resp_xml: str, action: str = "create") -> str:
    """create_* responses carry the new object's UUID as the `id` attribute."""
    root = _root_ok(resp_xml, action)
    obj_id = root.get("id", "")
    if not obj_id:
        raise OpenVASError(f"{action}: response has no id attribute")
    return obj_id


def parse_report_id(resp_xml: str) -> str:
    """start_task returns the report UUID in a <report_id> child element."""
    root = _root_ok(resp_xml, "start_task")
    rid = root.findtext("report_id", default="").strip()
    if not rid:
        raise OpenVASError("start_task: response has no report_id")
    return rid


def parse_task_status(resp_xml: str) -> tuple[str, int]:
    """get_tasks → (status, progress%). Progress defaults to 0 if absent."""
    root = _root_ok(resp_xml, "get_tasks")
    task = root.find("task")
    if task is None:
        raise OpenVASError("get_tasks: no <task> in response")
    status = (task.findtext("status") or "").strip()
    try:
        progress = int((task.findtext("progress") or "0").strip())
    except ValueError:
        progress = 0
    return status, progress


# --------------------------------------------------------------------------
# Client — composes builders + runner + parsers.
# --------------------------------------------------------------------------
@dataclass
class OpenVASClient:
    """Thin arm's-length façade over a stock Greenbone via an injectable runner."""

    runner: GmpRunner
    poll_interval_s: int = 15
    max_wait_s: int = 3600
    sleep: Callable[[float], None] = field(default=time.sleep)

    def create_target(self, name: str, hosts: str) -> str:
        return parse_created_id(self.runner(build_create_target(name, hosts)), "create_target")

    def create_task(self, name: str, target_id: str) -> str:
        return parse_created_id(self.runner(build_create_task(name, target_id)), "create_task")

    def start_task(self, task_id: str) -> str:
        return parse_report_id(self.runner(build_start_task(task_id)))

    def task_status(self, task_id: str) -> tuple[str, int]:
        return parse_task_status(self.runner(build_get_task(task_id)))

    def get_results_xml(self, task_id: str) -> str:
        return self.runner(build_get_results(task_id))

    def run_scan(self, hosts: str, *, name: str = "kryon-openvas") -> str:
        """Full lifecycle → returns the raw get_results XML for the normalizer.

        Polls task status until Done or ``max_wait_s`` elapses. ``sleep`` and
        the intervals are injectable so this is unit-testable with no real wait.
        """
        target_id = self.create_target(name, hosts)
        task_id = self.create_task(name, target_id)
        self.start_task(task_id)

        waited = 0
        while True:
            status, _progress = self.task_status(task_id)
            if status == _DONE:
                break
            if status in _TERMINAL_BAD:
                raise OpenVASError(f"scan ended in terminal state: {status}")
            if waited >= self.max_wait_s:
                raise OpenVASError(f"scan did not finish within {self.max_wait_s}s (last status={status})")
            self.sleep(self.poll_interval_s)
            waited += self.poll_interval_s

        return self.get_results_xml(task_id)
