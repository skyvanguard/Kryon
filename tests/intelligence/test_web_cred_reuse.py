"""Camino #1 (XBOW) — cerrar la cadena de explotación end-to-end.

``_rule_web_cred_reuse_admin`` es el eslabón que le faltaba a la cadena
``SQLi → dump creds → crack → login-as-admin → admin action``. El dump
determinista (F191) + ``_rule_crack_local_ntlm`` ya entregan una cred
plaintext en ``facts.creds``; esta regla la REUSA: hace login contra los
endpoints REST/JWT canónicos, extrae el token y lo usa contra un endpoint
admin-only, emitiendo proof-of-exploit como ground truth.

Es el análogo genérico (REST/JWT) de ``_rule_wp_admin_webshell`` (que
maneja el caso WordPress). Validado contra OWASP Juice Shop (lab de
entrenamiento autorizado): admin cred → ``/rest/user/login`` → JWT →
``/rest/user/whoami`` + ``/api/Users`` (admin-only).
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import (
    _rule_web_cred_reuse_admin,
    plan_next_action,
)
from kryon.intelligence.fact_extractor import ExtractedFacts

H = ("127.0.0.1",)


def test_cred_reuse_fires_with_cred_and_web():
    f = ExtractedFacts(
        creds=(("admin@juice-sh.op", "admin123"),),
        services=((3000, "http"),),
        hosts=H,
    )
    rec = _rule_web_cred_reuse_admin(f, [], "active sqli pentest")
    assert rec is not None
    # drives login → JWT → admin-only endpoint as proof-of-exploit
    for marker in (
        "cred_reuse",
        "admin@juice-sh.op",  # the reused username
        "admin123",  # the cracked password
        "/rest/user/login",  # canonical REST login endpoint
        "Authorization: Bearer",  # token reuse
        "CRED-REUSE-ADMIN",  # proof marker
    ):
        assert marker in rec.args, marker
    # confirms both identity (whoami) and an admin-only action (Users list)
    assert "whoami" in rec.args
    assert "/api/Users" in rec.args
    # base URL carries the discovered web port
    assert ":3000" in rec.args
    # regression guard: curl -w must be a single-brace %{http_code}. A double
    # brace ("%{{http_code}}") makes curl emit "}" instead of the status code,
    # so the admin loop never matches 200 (caught live on the server).
    assert "%{http_code}" in rec.args
    assert "%{{" not in rec.args
    # regression guard: SPA/HTML fallback (index.html + 200 on unknown paths)
    # must be filtered so it isn't reported as an admin API hit.
    assert "<(!doctype|html|!--)" in rec.args


def test_cred_reuse_prefers_email_candidate_when_cred_user_is_a_hash():
    # crack rule emits [CRACKED] <hash>:<pw> → cred user is the bare MD5, not
    # a login name. The rule must substitute a real email from facts.users.
    f = ExtractedFacts(
        creds=(("0192023a7bbd73250516f069df18b500", "admin123"),),
        users=("admin@juice-sh.op", "jim@juice-sh.op"),
        services=((3000, "http"),),
        hosts=H,
    )
    rec = _rule_web_cred_reuse_admin(f, [], "active sqli pentest")
    assert rec is not None
    assert "admin@juice-sh.op" in rec.args
    # the bare hash must NOT be used as a username candidate
    assert "0192023a7bbd73250516f069df18b500" not in rec.args


def test_cred_reuse_https_scheme_on_tls_port():
    f = ExtractedFacts(
        creds=(("admin", "s3cr3t"),),
        services=((443, "https"),),
        hosts=H,
    )
    rec = _rule_web_cred_reuse_admin(f, [], "")
    assert rec is not None
    assert "https://" in rec.args


def test_cred_reuse_abstains_without_web_service():
    f = ExtractedFacts(creds=(("admin", "x"),), services=((22, "ssh"),), hosts=H)
    assert _rule_web_cred_reuse_admin(f, [], "") is None


def test_cred_reuse_abstains_without_creds():
    f = ExtractedFacts(services=((3000, "http"),), hosts=H)
    assert _rule_web_cred_reuse_admin(f, [], "") is None


def test_cred_reuse_abstains_on_wordpress_signal():
    # WordPress is driven end-to-end by _rule_wp_admin_webshell; this generic
    # rule must not double-drive it.
    f = ExtractedFacts(
        creds=(("admin", "my2boys"),),
        services=((80, "http"),),
        hosts=H,
        paths=("wp-login.php", "/blog/"),
    )
    assert _rule_web_cred_reuse_admin(f, [], "wordpress") is None


def test_cred_reuse_abstains_if_already_run():
    f = ExtractedFacts(creds=(("admin", "x"),), services=((3000, "http"),), hosts=H)
    assert _rule_web_cred_reuse_admin(f, [": cred_reuse; curl ..."], "") is None


def test_cred_reuse_selected_by_plan_next_action_juice_shop():
    # end-to-end: after the crack lands the cred, the planner picks the
    # cred-reuse rule (registered right after _rule_crack_local_ntlm).
    f = ExtractedFacts(
        creds=(("admin@juice-sh.op", "admin123"),),
        services=((3000, "http"),),
        hosts=H,
    )
    # by the time a cred is cracked the recon scan has long since run, so
    # _rule_service_scan (recon-first) has already abstained.
    prior = [
        ": service_scan; nmap 127.0.0.1",
        "[CRACKED] 0192023a7bbd73250516f069df18b500:admin123",
    ]
    rec = plan_next_action(f, prior, "active sqli pentest")
    assert rec is not None and "cred_reuse" in rec.args
