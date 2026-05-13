"""F111 — Auth Flow Runner.

One-shot login execution: GET the login page, optionally parse the
form to auto-discover field names + CSRF tokens, POST the
credentials, and classify the response as success / failure based on
operator-supplied signals.

**Banca-safety contract**:

  * Single attempt per execute(). No brute-force, no credential
    spraying. Operator drives multiple runs explicitly if desired.
  * Credentials are operator-supplied; the runner NEVER generates
    or guesses them.
  * Captured cookies + Authorization-style headers live in-memory
    only on the returned AuthSession. Caller decides what to
    persist.
  * POST is restricted to the operator-supplied login_url. The
    runner won't post anywhere else.
  * Body sample cap (5KB by default) + response timeout enforced.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter

from kryon.tools.crawler.extractors import (
    ExtractedForm,
    extract_forms_from_html,
)

__all__ = [
    "AuthFlowConfig",
    "AuthFlowRunner",
    "AuthSession",
    "AuthSuccessSignal",
    "LoginCredentials",
    "execute_auth_flow",
]


@dataclass(frozen=True)
class LoginCredentials:
    """Operator-supplied credentials.

    `username_field` / `password_field` are the POST field NAMES (not
    values). The runner uses them to construct the payload alongside
    any auto-extracted hidden fields (csrf_token, etc.).
    """

    username: str
    password: str
    username_field: str = "username"
    password_field: str = "password"
    # Extra POST fields the operator wants to inject (e.g. legacy
    # captcha bypass, "remember me" flag). Survives auto-extracted
    # hidden fields with the same name — operator wins.
    extra_fields: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class AuthSuccessSignal:
    """How to detect a successful login. ANY matching signal counts
    as success. Empty signals mean "operator didn't specify"."""

    expected_status: int | None = None  # e.g. 302 for redirect-based
    expected_cookie_name: str = ""      # e.g. "JSESSIONID", "session"
    expected_body_substring: str = ""   # case-insensitive
    expected_redirect_path: str = ""    # match against Location header
    expected_jwt_in_body: bool = False  # JWT shape regex
    # If all of the above are empty AND a Set-Cookie WITH a session-y
    # name was returned, we treat that as success. Banca-safe default
    # — operator can disable via require_explicit_signal=True.


@dataclass(frozen=True)
class AuthFlowConfig:
    login_url: str
    credentials: LoginCredentials
    success_signal: AuthSuccessSignal = field(default_factory=AuthSuccessSignal)
    # If True, AuthFlowRunner won't fall back to the "session-like
    # cookie present" heuristic; it'll only succeed if a signal
    # matches.
    require_explicit_signal: bool = False
    # Auto-extract hidden inputs (csrf, return_url, ...) from the
    # GET login_page form. Off → operator must supply every field
    # via extra_fields.
    auto_detect_form: bool = True
    # If form action="" or action="/login" → join against login_url
    # (default). Operator can pin form_action_override.
    form_action_override: str = ""
    # HTTP method for the POST. Almost always "POST"; setting "GET"
    # is useful for old-style login systems.
    method: str = "POST"
    user_agent: str = "Kryon-Auth/1.0 (banca-safe)"
    timeout_seconds: float = 10.0
    max_body_bytes: int = 5_000
    follow_redirects: bool = True
    # Extra headers to send on both GET and POST (e.g. tenant-id
    # header for multi-tenant apps).
    extra_headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class AuthSession:
    """Captured auth state. Plug into CrawlerConfig.auth_cookies +
    auth_headers, or PipelineConfig via the same fields."""

    success: bool
    cookies: tuple[tuple[str, str], ...] = ()  # (name, value)
    headers: tuple[tuple[str, str], ...] = ()  # e.g. Authorization
    csrf_token: str = ""
    detected_signal: str = ""  # which signal fired (for debug)
    login_response_status: int = 0
    final_url: str = ""
    failure_reason: str = ""
    elapsed_seconds: float = 0.0


# ---- helpers --------------------------------------------------------------


# Names that look "session-y" enough to count as implicit success.
_SESSION_COOKIE_HINTS: tuple[str, ...] = (
    "session",
    "sessid",
    "sess",
    "auth",
    "token",
    "jwt",
    "id_token",
    "access_token",
    "phpsessid",
    "jsessionid",
    "asp.net_sessionid",
    "connect.sid",
    "laravel_session",
)


_FAILURE_HINTS: tuple[str, ...] = (
    "invalid credentials",
    "invalid username",
    "invalid password",
    "incorrect password",
    "wrong password",
    "login failed",
    "authentication failed",
    "credenciales inválidas",
    "credenciales invalidas",
    "usuario o contraseña",
    "usuario o clave",
)


# CSRF / authenticity-token field names (case-insensitive lookup)
_CSRF_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "csrf_token",
        "csrftoken",
        "_csrf",
        "_csrf_token",
        "_token",
        "authenticity_token",
        "csrfmiddlewaretoken",  # Django
        "__requestverificationtoken",  # ASP.NET
        "anti_forgery_token",
        "xsrf_token",
    }
)


_JWT_BODY_RE = re.compile(r'\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b')


def _is_session_like(name: str) -> bool:
    low = name.lower()
    return any(hint in low for hint in _SESSION_COOKIE_HINTS)


def _looks_like_csrf(field_name: str) -> bool:
    norm = field_name.lower().replace("-", "_")
    return norm in _CSRF_FIELD_NAMES


def _select_login_form(forms: list[ExtractedForm]) -> ExtractedForm | None:
    """Pick the form that contains a `password` input. If multiple,
    prefer the first."""
    for form in forms:
        for f in form.fields:
            if f.field_type.lower() == "password":
                return form
    return None


def _build_payload(
    credentials: LoginCredentials,
    form: ExtractedForm | None,
) -> tuple[dict[str, str], str]:
    """Return (payload_dict, detected_csrf_token).

    Combines:
      * username + password fields (operator names take priority)
      * hidden fields auto-extracted from form (csrf, return_url, ...)
      * operator-supplied extra_fields (override anything)
    """
    payload: dict[str, str] = {}
    csrf_token = ""
    if form is not None:
        for f in form.fields:
            if f.field_type.lower() == "hidden" and f.name:
                payload[f.name] = f.value
                if _looks_like_csrf(f.name) and f.value:
                    csrf_token = f.value
    # username + password fields override any auto-extracted defaults
    payload[credentials.username_field] = credentials.username
    payload[credentials.password_field] = credentials.password
    # Operator extras win
    for k, v in credentials.extra_fields:
        payload[k] = v
    return payload, csrf_token


def _detect_jwt_in_text(text: str) -> str:
    if not text:
        return ""
    m = _JWT_BODY_RE.search(text)
    return m.group(0) if m else ""


def _classify_response(
    config: AuthFlowConfig,
    resp: requests.Response,
    response_body: str,
    history: list[requests.Response],
    all_cookies: tuple[tuple[str, str], ...] = (),
) -> tuple[bool, str, str]:
    """Return (is_success, signal_name, failure_reason).

    `all_cookies` is the accumulated session cookie jar (across
    redirects). Required so cookie-based signals can match when the
    Set-Cookie happens on an intermediate hop (e.g. login POST 302 +
    /dashboard GET with no new cookies)."""
    signal = config.success_signal

    # Hard-evidence failure: error string in body wins over anything
    body_lower = response_body.lower()
    for hint in _FAILURE_HINTS:
        if hint in body_lower:
            return False, "", f"failure-hint matched: {hint!r}"

    # Explicit signals — any match counts
    if signal.expected_status is not None:
        if resp.status_code == signal.expected_status:
            return True, "status-match", ""
        # If operator pinned a status AND it didn't match, this is
        # probably a failure (don't fall through to heuristics)
        return False, "", f"status {resp.status_code} != expected {signal.expected_status}"

    if signal.expected_cookie_name:
        target = signal.expected_cookie_name.lower()
        # Look at final response cookies, history cookies, AND the
        # accumulated jar (covers all redirect hops).
        if any(c.name.lower() == target for c in resp.cookies):
            return True, "cookie-match", ""
        for h in history:
            if any(c.name.lower() == target for c in h.cookies):
                return True, "cookie-match", ""
        if any(name.lower() == target for name, _ in all_cookies):
            return True, "cookie-match", ""
        # Operator pinned a cookie name; absence == failure
        return False, "", f"expected cookie {signal.expected_cookie_name!r} not set"

    if signal.expected_body_substring:
        if signal.expected_body_substring.lower() in body_lower:
            return True, "body-substring-match", ""
        return False, "", f"expected body substring not found"

    if signal.expected_redirect_path:
        # Check Location header on the FIRST redirect (history) or
        # on the final response.
        for r in history + [resp]:
            loc = r.headers.get("Location", "")
            if signal.expected_redirect_path in loc:
                return True, "redirect-match", ""
        # Also check final URL
        if signal.expected_redirect_path in resp.url:
            return True, "redirect-match", ""
        return False, "", "expected redirect path not in any Location header"

    if signal.expected_jwt_in_body:
        if _detect_jwt_in_text(response_body):
            return True, "jwt-in-body", ""
        return False, "", "no JWT-shaped token in response body"

    # No explicit signal — fall back to heuristics unless operator
    # forbade it.
    if config.require_explicit_signal:
        return False, "", "no explicit signal matched + require_explicit_signal=True"

    # Heuristic: any session-like cookie set on the final response?
    session_cookie_names = [
        c.name for c in resp.cookies if _is_session_like(c.name)
    ]
    if session_cookie_names:
        return True, f"session-cookie-set:{session_cookie_names[0]}", ""

    # Status in 2xx with redirect history that exited the login URL
    # is also "probably success".
    if 200 <= resp.status_code < 400 and history:
        # If we left the login page (final URL != login_url path), success.
        if urlparse(resp.url).path != urlparse(config.login_url).path:
            return True, "redirected-off-login-page", ""

    return False, "", "no signal matched"


# ---- main runner ----------------------------------------------------------


class AuthFlowRunner:
    def __init__(self, config: AuthFlowConfig) -> None:
        if not config.login_url:
            raise ValueError("AuthFlowConfig.login_url is required")
        if not config.credentials.username and not config.credentials.password:
            # Empty credentials are technically permitted (some endpoints
            # accept anonymous tokens), but warn via failure_reason later.
            pass
        self.config = config

    def _build_session(self) -> requests.Session:
        sess = requests.Session()
        sess.headers["User-Agent"] = self.config.user_agent
        for name, value in self.config.extra_headers:
            sess.headers[name] = value
        adapter = HTTPAdapter(pool_connections=1, pool_maxsize=1, max_retries=0)
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        return sess

    def execute(self) -> AuthSession:
        t0 = time.monotonic()
        # 0. Eagerly validate operator-supplied form_action_override
        # for off-origin. We do this BEFORE the network GET so a
        # mis-configured target rejects immediately + the failure
        # reason is informative.
        if self.config.form_action_override:
            lp = urlparse(self.config.login_url)
            ap = urlparse(self.config.form_action_override)
            if (lp.scheme, lp.hostname, lp.port) != (ap.scheme, ap.hostname, ap.port):
                return AuthSession(
                    success=False,
                    failure_reason=(
                        f"form_action_override {self.config.form_action_override!r} "
                        f"would post off-origin (login is on "
                        f"{lp.scheme}://{lp.netloc})"
                    ),
                    elapsed_seconds=time.monotonic() - t0,
                )
        session = self._build_session()
        # 1. GET the login page to pick up CSRF + initial cookies
        try:
            r_get = session.get(
                self.config.login_url,
                timeout=self.config.timeout_seconds,
                allow_redirects=True,
            )
        except requests.exceptions.RequestException as e:
            return AuthSession(
                success=False,
                failure_reason=f"GET login page failed: {type(e).__name__}: {e}",
                elapsed_seconds=time.monotonic() - t0,
            )

        login_body = (r_get.text or "")[: self.config.max_body_bytes]
        form: ExtractedForm | None = None
        if self.config.auto_detect_form:
            forms = extract_forms_from_html(login_body, r_get.url)
            form = _select_login_form(forms)
        payload, csrf_token = _build_payload(self.config.credentials, form)

        # 2. Resolve form action URL
        action_url = self.config.form_action_override
        if not action_url:
            if form is not None and form.action:
                action_url = form.action
            else:
                action_url = self.config.login_url
        # Guard: form_action_override OR form-discovered action MUST be
        # same-origin with login_url to avoid being tricked into posting
        # credentials off-site.
        lp = urlparse(self.config.login_url)
        ap = urlparse(action_url)
        if (lp.scheme, lp.hostname, lp.port) != (ap.scheme, ap.hostname, ap.port):
            return AuthSession(
                success=False,
                failure_reason=(
                    f"form action {action_url!r} would post off-origin "
                    f"(login is on {lp.scheme}://{lp.netloc})"
                ),
                elapsed_seconds=time.monotonic() - t0,
            )

        # 3. Submit credentials
        method = self.config.method.upper()
        try:
            if method == "POST":
                r_post = session.post(
                    action_url,
                    data=payload,
                    timeout=self.config.timeout_seconds,
                    allow_redirects=self.config.follow_redirects,
                )
            elif method == "GET":
                r_post = session.get(
                    action_url,
                    params=payload,
                    timeout=self.config.timeout_seconds,
                    allow_redirects=self.config.follow_redirects,
                )
            else:
                return AuthSession(
                    success=False,
                    failure_reason=f"unsupported method {method!r}",
                    elapsed_seconds=time.monotonic() - t0,
                )
        except requests.exceptions.RequestException as e:
            return AuthSession(
                success=False,
                failure_reason=f"login POST failed: {type(e).__name__}: {e}",
                elapsed_seconds=time.monotonic() - t0,
            )

        body = (r_post.text or "")[: self.config.max_body_bytes]
        # Capture cookies + headers we should bring forward.
        captured_cookies = tuple(
            (c.name, c.value) for c in session.cookies if c.value
        )
        success, signal_name, failure_reason = _classify_response(
            self.config,
            r_post,
            body,
            history=list(r_post.history),
            all_cookies=captured_cookies,
        )
        captured_headers: list[tuple[str, str]] = []
        # If we found a JWT in the body, expose it as Authorization
        jwt = _detect_jwt_in_text(body) if success else ""
        if jwt:
            captured_headers.append(("Authorization", f"Bearer {jwt}"))
        # Always preserve CSRF token in a non-cookie field too, for
        # post-auth requests that need it as a header
        if csrf_token:
            captured_headers.append(("X-CSRF-Token", csrf_token))

        return AuthSession(
            success=success,
            cookies=captured_cookies,
            headers=tuple(captured_headers),
            csrf_token=csrf_token,
            detected_signal=signal_name,
            login_response_status=r_post.status_code,
            final_url=r_post.url,
            failure_reason=failure_reason,
            elapsed_seconds=time.monotonic() - t0,
        )


def execute_auth_flow(config: AuthFlowConfig) -> AuthSession:
    """Functional shortcut."""
    return AuthFlowRunner(config).execute()
