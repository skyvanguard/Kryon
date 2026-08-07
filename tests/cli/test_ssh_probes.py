"""Batch R — SSH handshake posture (Terrapin / weak algos / banner→CVE).
The KEXINIT analysis is unit-tested on parsed name-lists; the wire reader is
exercised against a crafted fake socket."""

from __future__ import annotations

import kryon.cli.ssh_probes as sp
from kryon.cli.engage import DiscoveredService

_S = DiscoveredService(host="h", port=22, state="open", service="ssh")


def test_terrapin_vulnerable_chacha_no_strict():
    f = sp._check_terrapin(_S, ["curve25519-sha256"], ["chacha20-poly1305@openssh.com"], ["hmac-sha2-256"])
    assert f is not None and f.rule_id == "ssh-terrapin"


def test_terrapin_safe_with_strict():
    f = sp._check_terrapin(_S, ["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
                           ["chacha20-poly1305@openssh.com"], ["hmac-sha2-256"])
    assert f is None


def test_terrapin_safe_without_vuln_cipher():
    assert sp._check_terrapin(_S, ["curve25519-sha256"], ["aes256-gcm@openssh.com"], ["hmac-sha2-256"]) is None


def test_weak_algorithms_detected():
    f = sp._check_weak_algos(_S, ["diffie-hellman-group1-sha1"], ["ssh-rsa"], ["3des-cbc"], ["hmac-md5"])
    assert f is not None and f.rule_id == "ssh-weak-algorithms"
    assert "3des-cbc" in f.evidence


def test_modern_algorithms_clean():
    assert sp._check_weak_algos(_S, ["curve25519-sha256"], ["ssh-ed25519"],
                                ["aes256-gcm@openssh.com"], ["hmac-sha2-256-etm@openssh.com"]) is None


def test_banner_cve_correlation_via_engine():
    # banner→CVE is now owned by version_cve; regreSSHion in range, clean out of range.
    from kryon.cli.version_cve import correlate_banner

    hits = correlate_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu", "h", 22)
    assert any(f.rule_id == "cve-2024-6387" for f in hits)
    assert correlate_banner("SSH-2.0-OpenSSH_9.8p1", "h", 22) == []


class _FakeSock:
    def __init__(self, stream):
        self._b = stream

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def settimeout(self, _):
        pass

    def sendall(self, _):
        pass

    def recv(self, n):
        c, self._b = self._b[:n], self._b[n:]
        return c


def _kexinit_packet(lists):
    payload = bytes([20]) + b"\x00" * 16
    for lst in lists:
        b = lst.encode()
        payload += len(b).to_bytes(4, "big") + b
    payload += b"\x00" + b"\x00\x00\x00\x00"  # first_kex_follows + reserved
    pad = 8 - ((len(payload) + 5) % 8) or 8
    body = bytes([pad]) + payload + b"\x00" * pad
    return len(body).to_bytes(4, "big") + body


def test_read_handshake_parses_lists(monkeypatch):
    lists = ["curve25519-sha256", "ssh-ed25519", "aes256-gcm@openssh.com", "aes256-gcm@openssh.com",
             "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""]
    stream = b"SSH-2.0-OpenSSH_9.6p1\r\n" + _kexinit_packet(lists)
    monkeypatch.setattr(sp.socket, "create_connection", lambda *a, **k: _FakeSock(stream))
    out = sp.run_ssh_probes(_S)
    # 9.6 banner → regreSSHion CVE via the correlation engine; modern algos → no weak/terrapin.
    assert any(f.rule_id == "cve-2024-6387" for f in out)
