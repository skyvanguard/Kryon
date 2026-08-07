"""CRITICAL: fact-derived values interpolated into shell commands must not allow
command injection. Facts come from target-controlled text (HTTP headers, tool
output, cracked passwords); the chain planner interpolates them into shell=True
one-liners. Structural fields are sanitized at the source; passwords are
shlex-quoted at the interpolation site (they legitimately contain metachars)."""

from __future__ import annotations

from kryon.intelligence.fact_extractor import ExtractedFacts


def test_structural_fields_strip_shell_metacharacters():
    f = ExtractedFacts(
        hosts=("x$(id).evil",),
        domains=("corp;rm -rf /",),
        users=("admin`whoami`",),
        paths=("/admin;cat /etc/passwd",),
    )
    assert "$" not in f.hosts[0] and "(" not in f.hosts[0]
    assert ";" not in f.domains[0] and " " not in f.domains[0]
    assert "`" not in f.users[0]
    assert ";" not in f.paths[0] and " " not in f.paths[0]
    assert f.paths[0].startswith("/admin")  # legit prefix preserved


def test_cred_user_sanitized_but_password_preserved():
    # The password must NOT be stripped (it legitimately contains metachars and
    # stripping would break the login) — it's shlex-quoted at the command site.
    f = ExtractedFacts(creds=(("ad`x`min", "p@$$w'or;d"),))
    user, pw = f.creds[0]
    assert "`" not in user  # user sanitized
    assert pw == "p@$$w'or;d"  # password intact


def test_planner_shlex_quotes_password_with_apostrophe():
    # A rockyou password with an apostrophe (don't, i'll) must not break out of
    # the sshpass -p '...' argument — no adversarial target needed.
    from kryon.intelligence import exploit_chain_planner as ep

    quoted = ep._shq("don't;rm -rf /")
    # shlex.quote makes it a single safe shell token — the ' and ; can't break out.
    assert quoted.startswith("'") or "\\" in quoted
    import shlex

    # Round-trips to exactly the original (no injection, value preserved).
    assert shlex.split(f"sshpass -p {quoted} ssh x")[2] == "don't;rm -rf /"
