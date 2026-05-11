"""Tests for kryon.learning.profiler.

Pure heuristic tests — no network, no DB. Validates the regex extractors
that turn raw nmap/HTTP/text into a structured target profile.
"""

from __future__ import annotations

import pytest

from kryon.learning.profiler import build_profile

# ---------- Host extraction ----------


def test_extracts_hostname_from_nmap_report() -> None:
    text = "Nmap scan report for app.example.com (203.0.113.10)\n"
    profile = build_profile(user_message=text)
    assert profile["host"] == "app.example.com"
    assert profile["resolved_ip"] == "203.0.113.10"


def test_extracts_ipv4_when_only_ip_present() -> None:
    profile = build_profile(user_message="probar 192.168.1.50 con nmap")
    # IPv4 falls back to host when no domain/nmap line is present.
    assert profile["host"] == "192.168.1.50"


def test_extracts_url_host() -> None:
    profile = build_profile(user_message="Auditá https://target.empresa.com/login")
    assert profile["host"] == "target.empresa.com"


def test_returns_none_host_when_no_signal() -> None:
    profile = build_profile(user_message="hola, ayudame con algo")
    assert profile["host"] is None
    assert profile["resolved_ip"] is None


# ---------- Ports + services ----------


def test_extracts_open_ports_from_nmap_lines() -> None:
    # Real nmap output: port lines start at column 0, no leading whitespace.
    text = (
        "Nmap scan report for db.example.com (10.0.0.5)\n"
        "PORT     STATE    SERVICE  VERSION\n"
        "22/tcp   open     ssh      OpenSSH 8.4\n"
        "80/tcp   open     http     Apache 2.4.41\n"
        "443/tcp  open     https    Apache 2.4.41\n"
        "3306/tcp filtered mysql\n"
    )
    profile = build_profile(user_message=text)
    # filtered ports are excluded — only `open` counts.
    assert sorted(profile["ports"]) == [22, 80, 443]
    assert "OpenSSH 8.4" in profile["services"]["22"]
    assert "Apache" in profile["services"]["80"]


def test_dedupes_repeated_ports() -> None:
    text = (
        "Nmap scan report for x (1.2.3.4)\n"
        "22/tcp open ssh\n"
        "22/tcp open ssh\n"
        "80/tcp open http\n"
    )
    profile = build_profile(user_message=text)
    assert profile["ports"] == [22, 80]


# ---------- Tech detection ----------


def test_detects_wordpress_via_signal_word() -> None:
    text = "GET /wp-login.php HTTP/1.1 ... wp-content found"
    profile = build_profile(user_message=text)
    assert "wordpress" in profile["tech"]


def test_detects_multiple_tech_in_text() -> None:
    text = "Server: nginx/1.18.0 Apache/2.4 X-Powered-By: PHP/7.4 OpenSSH_8.4"
    profile = build_profile(user_message=text)
    found = set(profile["tech"])
    # Each banner should produce its tech label.
    assert {"nginx", "apache", "php", "openssh"} <= found


def test_detects_wordpress_from_http_title() -> None:
    text = "http-title: My Site — Just another WordPress site"
    profile = build_profile(user_message=text)
    assert "wordpress" in profile["tech"]


def test_no_tech_signal_returns_empty_list() -> None:
    profile = build_profile(user_message="Just a generic chat message")
    assert profile["tech"] == []


# ---------- OS guessing ----------


@pytest.mark.parametrize("text,expected_os", [
    ("Linux server with apache/2.4", "linux"),
    ("ubuntu 22.04 found", "linux"),
    ("OpenSSH_8.0 detected", "linux"),
    ("Windows Server 2019 microsoft-iis", "windows"),
    ("hello world", None),
])
def test_os_hint_classifier(text: str, expected_os: str | None) -> None:
    profile = build_profile(user_message=text)
    assert profile["os_hint"] == expected_os


# ---------- Multiple input sources ----------


def test_combines_user_message_and_tool_outputs() -> None:
    profile = build_profile(
        user_message="audit https://shop.example.com",
        tool_outputs=[
            "Nmap scan report for shop.example.com (198.51.100.5)\n80/tcp open http",
        ],
    )
    assert profile["host"] == "shop.example.com"
    assert profile["resolved_ip"] == "198.51.100.5"
    assert 80 in profile["ports"]


def test_history_messages_contribute_to_profile() -> None:
    history = [
        {"role": "user", "content": "scan target"},
        {"role": "assistant", "content": "running nmap"},
        {"role": "tool", "content": "Server: nginx/1.19\n443/tcp open https"},
    ]
    profile = build_profile(history=history)
    assert "nginx" in profile["tech"]
    assert 443 in profile["ports"]


def test_notes_pass_through_unchanged() -> None:
    profile = build_profile(user_message="x", notes="banking client BCP")
    assert profile["notes"] == "banking client BCP"


# ---------- Edge: nothing at all ----------


def test_empty_input_returns_skeleton_profile() -> None:
    profile = build_profile()
    assert profile == {
        "host": None,
        "resolved_ip": None,
        "ports": [],
        "services": {},
        "tech": [],
        "os_hint": None,
    }


def test_none_in_history_does_not_crash() -> None:
    profile = build_profile(history=[None, {}, {"content": ""}])
    assert profile["host"] is None
