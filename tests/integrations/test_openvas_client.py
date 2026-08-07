"""OpenVAS GMP client — builders, parsers, and the run_scan orchestration.
The GMP execution is an injectable runner, so no live Greenbone is needed."""

from __future__ import annotations

import pytest

from kryon.integrations.openvas import client as C
from kryon.integrations.openvas.client import OpenVASClient, OpenVASError

_RESULTS = '<get_results_response status="200"><result id="r"/></get_results_response>'


# --- pure builders ---


def test_build_create_target_escapes_and_includes_fields():
    xml = C.build_create_target("net & co", "10.0.0.0/24")
    assert "<hosts>10.0.0.0/24</hosts>" in xml
    assert "net &amp; co" in xml
    assert C.PORT_LIST_ALL_IANA_TCP in xml


def test_build_create_task_wires_ids():
    xml = C.build_create_task("scan1", "target-1")
    assert 'target id="target-1"' in xml
    assert C.SCAN_CONFIG_FULL_AND_FAST in xml
    assert C.SCANNER_OPENVAS_DEFAULT in xml


def test_build_get_results_requests_details():
    assert 'details="1"' in C.build_get_results("task-1")


# --- pure parsers ---


def test_parse_created_id_ok():
    assert C.parse_created_id('<create_target_response status="201" id="t-1"/>', "create_target") == "t-1"


def test_parse_created_id_bad_status():
    with pytest.raises(OpenVASError):
        C.parse_created_id('<create_target_response status="400" status_text="bad"/>', "create_target")


def test_parse_created_id_missing_id():
    with pytest.raises(OpenVASError):
        C.parse_created_id('<create_target_response status="201"/>', "create_target")


def test_parse_report_id():
    xml = '<start_task_response status="202"><report_id>r-1</report_id></start_task_response>'
    assert C.parse_report_id(xml) == "r-1"


def test_parse_task_status():
    xml = '<get_tasks_response status="200"><task id="x"><status>Running</status><progress>42</progress></task></get_tasks_response>'
    assert C.parse_task_status(xml) == ("Running", 42)


def test_parse_unparseable_raises():
    with pytest.raises(OpenVASError):
        C.parse_created_id("not xml <<<", "create_target")


# --- run_scan orchestration (stateful fake runner) ---


class _FakeGmp:
    def __init__(self, status_sequence):
        self._statuses = list(status_sequence)
        self.status_calls = 0

    def __call__(self, xml: str) -> str:
        if xml.startswith("<create_target"):
            return '<create_target_response status="201" id="target-1"/>'
        if xml.startswith("<create_task"):
            return '<create_task_response status="201" id="task-1"/>'
        if xml.startswith("<start_task"):
            return '<start_task_response status="202"><report_id>report-1</report_id></start_task_response>'
        if xml.startswith("<get_tasks"):
            st = self._statuses[min(self.status_calls, len(self._statuses) - 1)]
            self.status_calls += 1
            return f'<get_tasks_response status="200"><task id="task-1"><status>{st}</status><progress>100</progress></task></get_tasks_response>'
        if xml.startswith("<get_results"):
            return _RESULTS
        raise AssertionError(f"unexpected GMP command: {xml}")


def test_run_scan_polls_until_done():
    fake = _FakeGmp(["Running", "Done"])
    cli = OpenVASClient(runner=fake, poll_interval_s=15, max_wait_s=600, sleep=lambda _s: None)
    out = cli.run_scan("10.0.0.0/24")
    assert "get_results_response" in out
    assert fake.status_calls == 2  # Running, then Done


def test_run_scan_terminal_bad_state():
    fake = _FakeGmp(["Stopped"])
    cli = OpenVASClient(runner=fake, sleep=lambda _s: None)
    with pytest.raises(OpenVASError, match="terminal"):
        cli.run_scan("10.0.0.0/24")


def test_run_scan_times_out():
    fake = _FakeGmp(["Running"])  # never finishes
    cli = OpenVASClient(runner=fake, poll_interval_s=15, max_wait_s=30, sleep=lambda _s: None)
    with pytest.raises(OpenVASError, match="did not finish"):
        cli.run_scan("10.0.0.0/24")
