"""Contract for the placeholder-target guard."""

from __future__ import annotations

import pytest

from kryon.validation.target_guard import (
    command_reason,
    guard_tool_args,
    is_placeholder,
    placeholder_reason,
)


@pytest.mark.parametrize(
    "target",
    [
        "HOST",
        "host",
        "https://HOST",
        "http://TARGET/path",
        "https://HOST:443",
        "target",
        "TARGET_HOST",
        "<target>",
        "<host>",
        "{host}",
        "https://<your-domain>",
        "x.x.x.x",
        "1.2.3.4",
        "",
        "   ",
    ],
)
def test_placeholders_are_flagged(target: str) -> None:
    assert is_placeholder(target) is True
    assert placeholder_reason(target) is not None


def test_none_is_flagged() -> None:
    assert is_placeholder(None) is True


@pytest.mark.parametrize(
    "target",
    [
        "https://juice-shop.local",
        "http://localhost:3003",
        "10.10.10.5",
        "192.168.1.1",
        "example.com",
        "https://target.com",  # dotted host that merely contains "target"
        "host.docker.internal",  # multi-label; "host" is only the first label
        "scanme.nmap.org",
    ],
)
def test_real_targets_pass(target: str) -> None:
    assert is_placeholder(target) is False
    assert placeholder_reason(target) is None


def test_reason_mentions_the_placeholder() -> None:
    msg = placeholder_reason("https://HOST")
    assert msg is not None
    assert "placeholder" in msg.lower()
    assert "HOST" in msg


# ---------- command_reason: shell commands ----------


@pytest.mark.parametrize(
    "command",
    [
        "curl -s https://HOST/",
        "curl -sI https://HOST/robots.txt",
        "wpscan --url HOST",
        "openssl s_client -connect HOST:443",
        "nmap TARGET -sV",
        "nikto -h <target>",
        "sqlmap -u {host}/login",
        "curl -s http://TARGET_HOST/",
    ],
)
def test_command_with_placeholder_is_flagged(command: str) -> None:
    assert command_reason(command) is not None


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "session list",
        "curl -s https://juice-shop.local/robots.txt",
        "wpscan --url https://blog.example.com",
        "nmap -sV -sC 10.10.10.5",
        "echo $HOST",  # shell var — not a placeholder
        "curl ${HOST}/path",  # shell var expansion
        "export HOST=10.0.0.5 && curl $HOST",  # assignment + var
        "curl --host-header foo https://real.com",  # lowercase 'host' in flag
        "cat file.txt < input.txt",  # shell redirect, not a <slot>
    ],
)
def test_legit_command_not_flagged(command: str) -> None:
    assert command_reason(command) is None


# ---------- guard_tool_args: the generic executor chokepoint ----------


@pytest.mark.parametrize(
    "tool,args",
    [
        ("nmap", '{"target":"HOST","args":"-sV"}'),
        ("sqlmap", '{"url":"https://HOST/login"}'),
        ("nuclei", '{"target":"http://TARGET"}'),
        ("gobuster", '{"url":"https://HOST/"}'),
        ("run_command", '{"command":"curl -s https://HOST/robots.txt"}'),
        ("nikto", '{"host":"<target>"}'),
        ("web_fetch_smart", {"url": "https://HOST"}),  # dict input too
    ],
)
def test_guard_tool_args_flags_placeholders(tool, args) -> None:
    assert guard_tool_args(tool, args) is not None


@pytest.mark.parametrize(
    "tool,args",
    [
        ("nmap", '{"target":"10.10.10.5","args":"-sV"}'),
        ("sqlmap", '{"url":"http://localhost:3003/rest/products"}'),
        ("web_fetch_smart", '{"url":"https://juice-shop.local/"}'),
        ("run_command", '{"command":"ls -la"}'),
        ("some_tool", '{"note":"just a note","count":3}'),  # no target key
        ("x", "not-json-at-all"),  # unparseable → no opinion
        ("x", '{"target":""}'),  # empty target → not a placeholder here
        ("x", "[1,2,3]"),  # non-dict json
    ],
)
def test_guard_tool_args_passes_real_and_unknown(tool, args) -> None:
    assert guard_tool_args(tool, args) is None


# ---------- XML/HTML payloads in commands must NOT false-positive ----------


@pytest.mark.parametrize(
    "command",
    [
        "curl -s -X POST http://real.com/xmlrpc.php -d '<methodCall><methodName>x</methodName></methodCall>'",
        "curl -d '<script>alert(1)</script>' https://real.com/",
        "echo '<html><body>hi</body></html>' | curl --data-binary @- https://real.com",
        "curl -H 'Content-Type: application/xml' -d '<root><item>1</item></root>' https://api.real.com",
    ],
)
def test_xml_html_in_command_not_flagged(command: str) -> None:
    assert command_reason(command) is None


@pytest.mark.parametrize("command", ["nikto -h <target>", "sqlmap -u {host}/x", "curl https://<host>/"])
def test_bracket_slot_word_still_flagged(command: str) -> None:
    assert command_reason(command) is not None


# ---------- Token-based key matching covers unconventional arg names ----------


@pytest.mark.parametrize(
    "args",
    [
        {"scan_url": "https://HOST"},
        {"victim_host": "HOST"},
        {"target_ip": "TARGET"},
        {"remote_addr": "<target>"},
        {"server": "http://HOST"},
        {"endpoint_uri": "https://HOST/api"},
    ],
)
def test_unconventional_target_keys_are_covered(args) -> None:
    assert guard_tool_args("future_tool", args) is not None


@pytest.mark.parametrize(
    "args",
    [
        {"scan_url": "https://juice-shop.local"},
        {"target_ip": "10.0.0.5"},
        {"recipient": "HOST"},  # 'recipient' is NOT a target token
        {"description": "scan the HOST thoroughly"},  # prose, not a target arg
        {"payload": "<script>alert(1)</script>"},  # payload arg, not scanned
    ],
)
def test_non_target_or_real_values_pass(args) -> None:
    assert guard_tool_args("future_tool", args) is None


# ---------- Coverage regression across the real tool registry ----------


def test_guard_covers_every_registered_target_param() -> None:
    """Enumerate the real tool registry; every arg whose name is target-rooted
    must be guarded. Fails if a tool ships a target param the guard can't see."""
    from kryon.skills.tool_budget import build_tool_registry
    from kryon.validation.target_guard import _TARGET_ROOTS, _key_tokens

    registry = build_tool_registry()
    checked = 0
    gaps: list[str] = []
    for name, tool in registry.items():
        schema = getattr(tool, "params_json_schema", None) or {}
        props = schema.get("properties", {}) if isinstance(schema, dict) else {}
        for param in props:
            if _key_tokens(param) & _TARGET_ROOTS:
                checked += 1
                if guard_tool_args(name, {param: "HOST"}) is None:
                    gaps.append(f"{name}.{param}")
    assert not gaps, f"target params NOT guarded (rename to a canonical root or extend _TARGET_ROOTS): {gaps}"
    assert checked >= 10, f"expected many target params across the registry, found only {checked}"
