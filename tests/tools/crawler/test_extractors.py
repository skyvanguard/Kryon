"""F108 — TDD contract for the crawler extractors."""

from __future__ import annotations

import pytest

from kryon.tools.crawler.extractors import (
    extract_endpoints_from_js,
    extract_forms_from_html,
    extract_links_from_html,
    extract_meta_tags_from_html,
    extract_script_srcs_from_html,
    urljoin_safe,
)


BASE = "https://target.example/page"


# =====================================================================
# urljoin_safe
# =====================================================================


@pytest.mark.parametrize(
    "ref,expected",
    [
        ("/api/v1/users", "https://target.example/api/v1/users"),
        ("../other", "https://target.example/other"),
        ("https://cdn.example/x.js", "https://cdn.example/x.js"),
        ("//cdn.example/x.js", "https://cdn.example/x.js"),
        ("page.html", "https://target.example/page.html"),
        ("", ""),
        ("javascript:alert(1)", ""),
        ("data:text/html,foo", ""),
        ("mailto:a@b.c", ""),
        ("#fragment", ""),
        ("/path#fragment", "https://target.example/path"),  # fragment stripped
        ("file:///etc/passwd", ""),
        ("vbscript:msgbox(1)", ""),
    ],
)
def test_urljoin_safe(ref, expected):
    assert urljoin_safe(BASE, ref) == expected


# =====================================================================
# extract_links_from_html
# =====================================================================


def test_extract_a_href():
    body = '<a href="/dashboard">Dashboard</a>'
    links = extract_links_from_html(body, BASE)
    assert len(links) == 1
    assert links[0].url == "https://target.example/dashboard"
    assert links[0].source_tag == "a"


def test_extract_multiple_tags():
    body = """
    <a href="/about">About</a>
    <link rel="stylesheet" href="/static/app.css">
    <script src="/static/app.js"></script>
    <img src="/img/logo.png">
    <iframe src="https://external.example/embed"></iframe>
    """
    links = extract_links_from_html(body, BASE)
    urls = {l.url for l in links}
    tags = {l.source_tag for l in links}
    assert "https://target.example/about" in urls
    assert "https://target.example/static/app.css" in urls
    assert "https://target.example/static/app.js" in urls
    assert "https://target.example/img/logo.png" in urls
    assert "https://external.example/embed" in urls
    assert tags == {"a", "link", "script", "img", "iframe"}


def test_dedupes_within_extraction():
    body = '<a href="/x">a</a><a href="/x">b</a><a href="/x">c</a>'
    links = extract_links_from_html(body, BASE)
    assert len(links) == 1


def test_javascript_href_is_dropped():
    body = '<a href="javascript:alert(1)">x</a>'
    links = extract_links_from_html(body, BASE)
    assert links == []


def test_single_quoted_attr():
    body = "<a href='/single'>x</a>"
    links = extract_links_from_html(body, BASE)
    assert links[0].url == "https://target.example/single"


def test_unquoted_attr():
    body = "<a href=/unquoted>x</a>"
    links = extract_links_from_html(body, BASE)
    assert links[0].url == "https://target.example/unquoted"


def test_html_entity_decoded():
    body = '<a href="/path?a=1&amp;b=2">x</a>'
    links = extract_links_from_html(body, BASE)
    assert links[0].url == "https://target.example/path?a=1&b=2"


def test_empty_body_returns_empty():
    assert extract_links_from_html("", BASE) == []


# =====================================================================
# extract_script_srcs_from_html
# =====================================================================


def test_script_srcs_only():
    body = """
    <a href="/about">a</a>
    <script src="/main.js"></script>
    <script src="https://cdn/lib.js"></script>
    <script>inline()</script>
    """
    srcs = extract_script_srcs_from_html(body, BASE)
    assert "https://target.example/main.js" in srcs
    assert "https://cdn/lib.js" in srcs
    assert len(srcs) == 2  # inline script ignored


# =====================================================================
# extract_meta_tags_from_html
# =====================================================================


def test_meta_generator():
    body = '<meta name="generator" content="WordPress 6.4.1">'
    metas = extract_meta_tags_from_html(body)
    assert metas.get("generator") == "WordPress 6.4.1"


def test_meta_csrf_token():
    body = '<meta name="csrf-token" content="abc123token">'
    metas = extract_meta_tags_from_html(body)
    assert metas.get("csrf-token") == "abc123token"


def test_meta_http_equiv():
    body = '<meta http-equiv="X-UA-Compatible" content="IE=edge">'
    metas = extract_meta_tags_from_html(body)
    assert metas.get("x-ua-compatible") == "IE=edge"


def test_meta_og_property():
    body = '<meta property="og:title" content="My Site">'
    metas = extract_meta_tags_from_html(body)
    assert metas.get("og:title") == "My Site"


# =====================================================================
# extract_forms_from_html
# =====================================================================


def test_form_with_inputs():
    body = """
    <form method="post" action="/login">
      <input name="username" type="text" required>
      <input name="password" type="password">
      <input name="remember" type="checkbox">
      <input type="submit" value="Login">
    </form>
    """
    forms = extract_forms_from_html(body, BASE)
    assert len(forms) == 1
    f = forms[0]
    assert f.action == "https://target.example/login"
    assert f.method == "POST"
    field_names = {fl.name for fl in f.fields}
    assert "username" in field_names
    assert "password" in field_names
    assert "remember" in field_names


def test_form_default_method_is_get():
    body = '<form action="/search"><input name="q"></form>'
    forms = extract_forms_from_html(body, BASE)
    assert forms[0].method == "GET"


def test_form_default_action_is_current_page():
    body = '<form method="post"><input name="x"></form>'
    forms = extract_forms_from_html(body, BASE)
    assert forms[0].action == BASE


def test_form_required_field_detected():
    body = '<form action="/x"><input name="email" type="email" required></form>'
    forms = extract_forms_from_html(body, BASE)
    field = next(f for f in forms[0].fields if f.name == "email")
    assert field.required is True


def test_form_textarea_select():
    body = """
    <form action="/x">
      <textarea name="bio"></textarea>
      <select name="country"><option>PY</option></select>
    </form>
    """
    forms = extract_forms_from_html(body, BASE)
    names = {f.name for f in forms[0].fields}
    assert "bio" in names
    assert "country" in names


def test_multiple_forms():
    body = """
    <form action="/login"><input name="u"></form>
    <form action="/search" method="get"><input name="q"></form>
    """
    forms = extract_forms_from_html(body, BASE)
    assert len(forms) == 2


def test_form_with_method_put_normalized_to_get():
    """HTML forms only support GET/POST natively; anything else falls back."""
    body = '<form method="put" action="/x"><input name="a"></form>'
    forms = extract_forms_from_html(body, BASE)
    assert forms[0].method == "GET"


# =====================================================================
# extract_endpoints_from_js
# =====================================================================


def test_js_fetch_call():
    js = 'fetch("/api/v1/users").then(r => r.json())'
    eps = extract_endpoints_from_js(js, BASE)
    assert "https://target.example/api/v1/users" in eps


def test_js_axios_get():
    js = 'axios.get("/api/account/profile")'
    eps = extract_endpoints_from_js(js, BASE)
    assert "https://target.example/api/account/profile" in eps


def test_js_axios_post():
    js = 'axios.post("/api/transfer", {amount: 100})'
    eps = extract_endpoints_from_js(js, BASE)
    assert "https://target.example/api/transfer" in eps


def test_js_jquery_ajax():
    js = '$.ajax({url: "/api/list", method: "GET"})'
    eps = extract_endpoints_from_js(js, BASE)
    assert "https://target.example/api/list" in eps


def test_js_jquery_get():
    js = '$.get("/api/users", function(d) {})'
    eps = extract_endpoints_from_js(js, BASE)
    assert "https://target.example/api/users" in eps


def test_js_xhr_open():
    js = 'var xhr = new XMLHttpRequest(); xhr.open("POST", "/api/submit")'
    eps = extract_endpoints_from_js(js, BASE)
    assert "https://target.example/api/submit" in eps


def test_js_full_url_extracted():
    js = 'const API = "https://api.example.com/v2/data"; fetch(API);'
    eps = extract_endpoints_from_js(js, BASE)
    assert "https://api.example.com/v2/data" in eps


def test_js_relative_path_extracted():
    js = 'const ENDPOINT = "/graphql"; fetch(ENDPOINT);'
    eps = extract_endpoints_from_js(js, BASE)
    assert "https://target.example/graphql" in eps


def test_js_template_literal_no_interpolation():
    js = "fetch(`/api/static`)"
    eps = extract_endpoints_from_js(js, BASE)
    assert "https://target.example/api/static" in eps


def test_js_noise_strings_filtered_out():
    js = """
    const color = "#ff0000";
    const label = "Click here";
    const word = "hello world";
    const css = "background: red;";
    """
    eps = extract_endpoints_from_js(js, BASE)
    assert eps == []


def test_js_dedupes_repeated_endpoints():
    js = 'fetch("/api/x"); axios.get("/api/x"); $.get("/api/x");'
    eps = extract_endpoints_from_js(js, BASE)
    assert len(eps) == 1


def test_js_empty_returns_empty():
    assert extract_endpoints_from_js("", BASE) == []


def test_js_admin_path_extracted():
    js = 'const adminPath = "/admin/users/delete";'
    eps = extract_endpoints_from_js(js, BASE)
    assert "https://target.example/admin/users/delete" in eps


def test_js_auth_path_extracted():
    js = 'fetch("/login", {method: "POST", body: data})'
    eps = extract_endpoints_from_js(js, BASE)
    assert "https://target.example/login" in eps
