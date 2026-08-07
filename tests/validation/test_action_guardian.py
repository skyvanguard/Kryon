"""Tests for the independent action guardian (pre-execution safety judge)."""

from __future__ import annotations

from kryon.validation.action_guardian import (
    _extract_command_text,
    assess_action,
    assess_mutation,
    assess_tool_call,
    is_enabled,
    is_mutating_action,
)


def test_deterministic_rejects_destructive():
    assert assess_action({"command": "rm -rf /"}).safe is False
    assert assess_action({"command": "DROP TABLE users;"}).safe is False
    assert assess_action({"command": "mkfs.ext4 /dev/sda1"}).safe is False
    v = assess_action({"command": "shutdown -h now"})
    assert v.safe is False and v.source == "deterministic"


def test_benign_action_allowed_without_judge():
    v = assess_action({"tool": "nmap", "args": {"target": "10.0.0.1", "flags": "-sV"}})
    assert v.safe is True
    assert v.source == "allow-default"


def test_judge_safe_and_unsafe():
    safe = assess_action({"command": "curl http://target/api"}, judge=lambda p: "SAFE — read-only GET")
    assert safe.safe is True and safe.source == "judge"
    unsafe = assess_action({"command": "curl http://target/api"}, judge=lambda p: "UNSAFE: this deletes data")
    assert unsafe.safe is False and unsafe.source == "judge"


def test_judge_ambiguous_blocks_fail_closed():
    # SAFETY gate: a reply with no clear leading SAFE/UNSAFE verdict → BLOCK.
    v = assess_action({"command": "curl http://target"}, judge=lambda p: "hmm, hard to say")
    assert v.safe is False
    assert v.source == "judge-ambiguous"


def test_judge_empty_reply_is_unavailable_allow():
    # empty reply = judge DOWN (availability), not a verdict → defer to
    # deterministic tier (allow), don't cripple the run.
    v = assess_action({"command": "curl http://target"}, judge=lambda p: "")
    assert v.safe is True
    assert v.source == "judge-unavailable"


def test_judge_parser_verdict_first_or_fail_closed():
    # leading UNSAFE blocks
    assert assess_action({"command": "x"}, judge=lambda p: "UNSAFE — destroys data").safe is False
    # leading SAFE allows
    assert assess_action({"command": "x"}, judge=lambda p: "SAFE — read-only call").safe is True
    # verbose reply that BURIES the verdict → fail-closed BLOCK (the S2 fix: a
    # verbose UNSAFE reply mentioning "safe" must never slip through as allow)
    assert assess_action({"command": "x"}, judge=lambda p: "This wipes the DB, therefore UNSAFE").safe is False
    assert assess_action({"command": "x"}, judge=lambda p: "This is not unsafe, it is SAFE").safe is False
    # 'safe' must not be matched inside 'unsafe' (leading UNSAFE still blocks)
    assert assess_action({"command": "x"}, judge=lambda p: "unsafe operation, do not run").safe is False


def test_judge_error_does_not_hard_block():
    def boom(_):
        raise RuntimeError("model down")

    v = assess_action({"command": "curl http://target"}, judge=boom)
    assert v.safe is True  # a judge failure must not block the run


def test_deterministic_wins_over_judge():
    # Even a "SAFE"-saying judge cannot approve an rm -rf /.
    v = assess_action({"command": "rm -rf /"}, judge=lambda p: "SAFE")
    assert v.safe is False and v.source == "deterministic"


def test_is_enabled_reads_env(monkeypatch):
    monkeypatch.delenv("KRYON_GUARDIAN_MODEL", raising=False)
    assert is_enabled() is False
    monkeypatch.setenv("KRYON_GUARDIAN_MODEL", "qwen-unc")
    assert is_enabled() is True


class TestExecutorAdapter:
    """`assess_tool_call` is the executor-facing gate: it inspects EXECUTABLE
    args only (command/query), parses JSON-string arguments, and returns a
    directive string on a destructive action (or None to allow)."""

    def test_blocks_destructive_shell_command_dict_args(self):
        out = assess_tool_call("run_command", {"command": "rm -rf /home"})
        assert out is not None and "BLOCKED by action guardian" in out

    def test_blocks_destructive_command_json_string_args(self):
        # the executor passes tool_call.arguments as a JSON string
        out = assess_tool_call("run_command", '{"command": "DROP DATABASE prod;"}')
        assert out is not None and "BLOCKED by action guardian" in out

    def test_blocks_destructive_session_input_data_key(self):
        out = assess_tool_call("shell_session_input", {"session_id": "S1", "data": "mkfs.ext4 /dev/sda1"})
        assert out is not None

    def test_allows_benign_command(self):
        assert assess_tool_call("run_command", {"command": "whoami && id"}) is None

    def test_url_arg_named_shutdown_is_not_blocked(self):
        # the FP the executor scoping fixes: a read-only probe of an endpoint
        # literally named /shutdown must NOT be misread as a poweroff command.
        assert assess_tool_call("web_fetch_smart", {"url": "http://target/admin/shutdown"}) is None

    def test_sqli_payload_in_url_querystring_is_not_blocked(self):
        # a reflected-SQLi test string in a url arg is a probe, not an executed DROP
        assert assess_tool_call("web_fetch_smart", {"url": "http://t/search?q=1' OR DROP TABLE--"}) is None

    def test_empty_or_targetonly_args_allow(self):
        assert assess_tool_call("nmap", {"target": "10.0.0.1", "flags": "-sV"}) is None
        assert assess_tool_call("run_command", {}) is None

    def test_bare_string_arg_is_treated_as_command(self):
        # a non-JSON string arg to a shell tool IS the command
        assert assess_tool_call("run_command", "reboot now") is not None

    def test_guardian_never_raises_on_weird_args(self):
        # must never crash the run — the executor wraps it but the fn is defensive too
        assert assess_tool_call("x", None) is None
        assert assess_tool_call("x", 12345) is None

    def test_extract_command_text_scopes_to_command_keys(self):
        txt = _extract_command_text({"command": "ls", "url": "http://t/shutdown", "target": "h"})
        assert "ls" in txt and "shutdown" not in txt


class TestMutationJudge:
    """The gray-zone model tier: `is_mutating_action` decides WHEN to consult the
    judge; `assess_mutation` shows the judge the FULL action (method+url+body) and
    is fail-open."""

    def test_is_mutating_detects_write_methods(self):
        assert is_mutating_action("http_fetch", {"method": "POST", "url": "http://t/x"}) is True
        assert is_mutating_action("http_fetch", {"method": "delete", "url": "http://t/x"}) is True
        assert is_mutating_action("hydra", {"http_method": "PUT"}) is True

    def test_is_mutating_false_for_get_and_reads(self):
        assert is_mutating_action("http_fetch", {"method": "GET", "url": "http://t/x"}) is False
        assert is_mutating_action("nmap", {"target": "10.0.0.1"}) is False
        assert is_mutating_action("web_fetch_smart", '{"url": "http://t"}') is False

    def test_is_mutating_by_tool_name_hint(self):
        assert is_mutating_action("probe_mass_assign", {}) is True
        assert is_mutating_action("file_upload_tool", {}) is True

    def test_assess_mutation_blocks_on_unsafe_judge(self):
        out = assess_mutation(
            "http_fetch",
            {"method": "DELETE", "url": "http://t/api/users/1"},
            judge=lambda p: "UNSAFE — deletes a user out of scope",
        )
        assert out is not None and "action guardian (judge)" in out

    def test_assess_mutation_allows_on_safe_judge(self):
        out = assess_mutation(
            "http_fetch",
            {"method": "POST", "url": "http://t/api/login"},
            judge=lambda p: "SAFE — authorized login attempt",
        )
        assert out is None

    def test_assess_mutation_fail_open_on_empty_or_error(self):
        assert assess_mutation("http_fetch", {"method": "POST", "url": "http://t"}, judge=lambda p: "") is None

        def boom(_):
            raise RuntimeError("judge down")

        assert assess_mutation("http_fetch", {"method": "POST", "url": "http://t"}, judge=boom) is None

    def test_assess_mutation_judge_sees_full_action(self):
        seen = {}

        def _capture(prompt):
            seen["prompt"] = prompt
            return "SAFE"

        assess_mutation("http_fetch", {"method": "PUT", "url": "http://t/admin/config", "body": "x"}, judge=_capture)
        # unlike the command-only deterministic path, the judge must see url + body
        assert "admin/config" in seen["prompt"] and "PUT" in seen["prompt"]


class TestDestructiveBypassRegression:
    """S3: the naive per-token regexes were evadable. These are the exact bypass
    strings from the security review — each MUST block, and the legit forms MUST
    allow (low false positives)."""

    BLOCK = [
        "rm -rf /",
        "rm -r -f /",
        "rm --recursive --force /",
        'rm -rf "$HOME"',
        "rm -rf --no-preserve-root /",
        "rm -fr ~",
        "chmod -R 777 /",
        "chmod -R 777 /home",
        "DROP/**/DATABASE prod",
        "DROP DATABASE prod",
        "cat /dev/zero > /dev/sda",
        "dd if=/dev/zero of=/dev/disk0",
        "mkfs.ext4 /dev/sdb",
        "TRUNCATE  TABLE users",
        'int main(){ system("rm -rf --no-preserve-root /"); }',  # via a code arg
    ]
    ALLOW = [
        "rm -f singlefile.txt",
        "rm -rf ./build",
        "rm -rf /tmp/scan-out",
        "ls -la /",
        "curl http://t/api/shutdown",  # 'shutdown' in a URL path, not a command
        "SELECT * FROM users",
        "chmod 644 file",
    ]

    def test_all_bypasses_blocked(self):
        for cmd in self.BLOCK:
            assert assess_tool_call("run_command", {"command": cmd}) is not None, cmd

    def test_legit_commands_allowed(self):
        for cmd in self.ALLOW:
            assert assess_tool_call("run_command", {"command": cmd}) is None, cmd

    def test_source_code_arg_is_scanned(self):
        # S1: a destructive payload under an unanticipated arg name (not in a
        # command allowlist) must NOT evade the deterministic tier.
        out = assess_tool_call("run_sandboxed", {"source_code": 'system("rm -rf /");'})
        assert out is not None

    def test_url_arg_still_exempt(self):
        assert assess_tool_call("web_fetch_smart", {"url": "http://t/admin/shutdown"}) is None
