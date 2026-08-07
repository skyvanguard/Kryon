"""Vhost detection from the response BODY — for targets that don't 30x-redirect but hard-code their
canonical vhost in the page (WordPress siteurl). Found live on THM Internal: the bare IP returns 200
with http://internal.thm/blog/... links, so the redirect-only detector missed it and /etc/hosts was
never seeded, blocking the agent from using the cracked wp-admin creds.
"""

from __future__ import annotations

import io
from unittest import mock

import kryon.cli.investigate as inv


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_a):
        self.close()


def _detect(body: bytes) -> str:
    with mock.patch("urllib.request.urlopen", return_value=_Resp(body)):
        return inv._detect_body_vhost("http://10.67.166.177")


def test_detects_wordpress_siteurl_vhost():
    body = (
        b'<link rel="canonical" href="http://internal.thm/blog/">'
        b'<a href="http://internal.thm/blog/index.php/2020/08/">post</a>'
        b'<link href="https://fonts.googleapis.com/css">'  # public CDN must be ignored
    )
    assert _detect(body) == "internal.thm"


def test_ignores_public_hosts_only():
    body = b'<a href="https://www.google.com">g</a><script src="https://code.jquery.com/x.js">'
    assert _detect(body) == ""


def test_prefers_lab_tld_over_more_frequent_public_lookalike():
    # A .htb host appears once; a non-lab internal host appears more often — the lab TLD wins.
    body = (
        b'<a href="http://app.corp.example/a">x</a><a href="http://app.corp.example/b">y</a>'
        b'<a href="http://target.htb/">z</a>'
    )
    # example.com-family is a public needle, so app.corp.example is dropped → target.htb remains.
    assert _detect(body) == "target.htb"


def test_returns_empty_on_no_body():
    with mock.patch("urllib.request.urlopen", side_effect=OSError("down")):
        assert inv._detect_body_vhost("http://10.67.166.177") == ""
