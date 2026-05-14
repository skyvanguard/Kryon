"""F111 — agent-facing tool wrapper for the auth flow runner."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.auth.runner import (
    AuthFlowConfig,
    AuthFlowRunner,
    AuthSession,
    AuthSuccessSignal,
    LoginCredentials,
)

__all__ = ["execute_login_flow"]


def _session_to_dict(s: AuthSession) -> dict[str, Any]:
    # NOTE: cookie values + auth headers carry credentials. The tool
    # returns the cookie + header NAMES + presence flags, NOT values,
    # by default. Operator can re-run with a side-channel to pull
    # the actual values if needed.
    return {
        "success": s.success,
        "detected_signal": s.detected_signal,
        "login_response_status": s.login_response_status,
        "final_url": s.final_url,
        "csrf_token_captured": bool(s.csrf_token),
        "cookie_names": [name for name, _ in s.cookies],
        "header_names": [name for name, _ in s.headers],
        "failure_reason": s.failure_reason,
        "elapsed_seconds": round(s.elapsed_seconds, 3),
    }


@function_tool
def execute_login_flow(config_json: str) -> str:
    """Execute a single operator-supplied login flow.

    Banca-safe: single attempt, operator-supplied credentials only,
    POST restricted to same-origin form action. Captured cookies +
    headers are returned by NAME only (no values) — see source for
    raw access.

    Args:
        config_json: JSON object with:
          - login_url (required)
          - username (required)
          - password (required)
          - username_field (default "username")
          - password_field (default "password")
          - extra_fields: [{name, value}]
          - success_signal: {
              expected_status, expected_cookie_name,
              expected_body_substring, expected_redirect_path,
              expected_jwt_in_body
            }
          - require_explicit_signal (default false)
          - auto_detect_form (default true)
          - form_action_override
          - method (default "POST")
          - timeout_seconds (default 10)
          - extra_headers: [{name, value}]

    Returns:
        JSON summary: success flag, signal that fired, cookie/header
        NAMES captured (values redacted), failure reason if any.
    """
    try:
        doc = json.loads(config_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(doc, dict):
        return json.dumps({"error": "config_json must be a JSON object"})

    login_url = doc.get("login_url")
    if not login_url:
        return json.dumps({"error": "login_url is required"})
    if "username" not in doc or "password" not in doc:
        return json.dumps({"error": "username + password are required"})

    extra_fields = tuple(
        (str(e.get("name") or ""), str(e.get("value") or ""))
        for e in (doc.get("extra_fields") or [])
        if isinstance(e, dict) and e.get("name")
    )
    extra_headers = tuple(
        (str(h.get("name") or ""), str(h.get("value") or ""))
        for h in (doc.get("extra_headers") or [])
        if isinstance(h, dict) and h.get("name")
    )
    creds = LoginCredentials(
        username=str(doc["username"]),
        password=str(doc["password"]),
        username_field=str(doc.get("username_field") or "username"),
        password_field=str(doc.get("password_field") or "password"),
        extra_fields=extra_fields,
    )
    sig_doc = doc.get("success_signal") or {}
    if not isinstance(sig_doc, dict):
        sig_doc = {}
    sig = AuthSuccessSignal(
        expected_status=(int(sig_doc["expected_status"]) if sig_doc.get("expected_status") is not None else None),
        expected_cookie_name=str(sig_doc.get("expected_cookie_name") or ""),
        expected_body_substring=str(sig_doc.get("expected_body_substring") or ""),
        expected_redirect_path=str(sig_doc.get("expected_redirect_path") or ""),
        expected_jwt_in_body=bool(sig_doc.get("expected_jwt_in_body", False)),
    )
    try:
        cfg = AuthFlowConfig(
            login_url=str(login_url),
            credentials=creds,
            success_signal=sig,
            require_explicit_signal=bool(doc.get("require_explicit_signal", False)),
            auto_detect_form=bool(doc.get("auto_detect_form", True)),
            form_action_override=str(doc.get("form_action_override") or ""),
            method=str(doc.get("method") or "POST"),
            user_agent=str(doc.get("user_agent") or "Kryon-Auth/1.0 (banca-safe)"),
            timeout_seconds=float(doc.get("timeout_seconds") or 10.0),
            max_body_bytes=int(doc.get("max_body_bytes") or 5_000),
            follow_redirects=bool(doc.get("follow_redirects", True)),
            extra_headers=extra_headers,
        )
    except ValueError as e:
        return json.dumps({"error": f"invalid config: {e}"})

    sess = AuthFlowRunner(cfg).execute()
    return json.dumps(_session_to_dict(sess), ensure_ascii=False)
