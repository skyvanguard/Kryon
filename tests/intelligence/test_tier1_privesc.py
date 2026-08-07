"""Tier-1 privesc rules: linpeas_autoexploit (flag→exploit→root) + cred_harvest_reuse. Both fire on
creds+SSH and chain AFTER ssh_with_creds via their own markers (linpeas_auto / cred_harvest)."""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import (
    _rule_cred_harvest_reuse,
    _rule_linpeas_autoexploit,
    plan_next_action,
)
from kryon.intelligence.fact_extractor import ExtractedFacts

_CREDS = ExtractedFacts(services=((22, "ssh"),), hosts=("10.0.0.1",), creds=(("bob", "pw123"),))


def test_linpeas_autoexploits_root_vectors():
    rec = _rule_linpeas_autoexploit(_CREDS, [], "")
    assert rec is not None and rec.confidence >= 0.92
    assert "sshpass -p pw123" in rec.args and "linpeas_auto" in rec.args
    # auto-exploits docker/sudo, grabs user flag
    assert "docker-group" in rec.args and "sudo-nopasswd" in rec.args
    assert "cap_setuid" in rec.args and "USER-FLAG" in rec.args
    # /goal batch: SUID-GTFOBins, writable-passwd, lxd-group, LD_LIBRARY_PATH are now AUTO-EXPLOITED
    # (were enum/flag-only). Each lands [ROOT <vector>] reading /root/root.txt.
    assert "[ROOT suid-" in rec.args and "/root/root.txt -exec cat" in rec.args  # SUID find primitive
    assert "[ROOT writable-passwd]" in rec.args and "cp -f /tmp/.pwb /etc/passwd" in rec.args  # restored, no backdoor
    assert "[ROOT lxd-group]" in rec.args and "security.privileged=true" in rec.args
    assert "[ROOT LD_LIBRARY_PATH]" in rec.args and "readelf -d" in rec.args  # fakes a DT_NEEDED soname
    # /goal batch wave 3: VNC password (openssl DES-ECB, fixed key), writable-cron (bounded wait + restore),
    # PATH hijack (plant a relative command a SUID execs) — all newly covered.
    assert "[VNC-CRED]" in rec.args and "e84ad660c4721ae0" in rec.args  # VNC fixed DES key
    assert "[ROOT cron-writable]" in rec.args and "cp -f /tmp/.crb" in rec.args  # cron script restored
    assert "[ROOT path-hijack]" in rec.args
    # /goal batch wave 4: docker-socket + bind-mount container escapes, and PwnKit detection (NOT auto-run).
    assert "[ROOT docker-socket]" in rec.args and "docker.sock" in rec.args
    assert "[ROOT container-mount]" in rec.args and "/.dockerenv" in rec.args
    assert "[LIN-PRIVESC pwnkit]" in rec.args and "CVE-2021-4034" in rec.args  # detection only (crash risk)
    # 3-tier roadmap / Tier 1: sudo-with-PASSWORD + GTFOBins-specific + caps/groups + writable-shadow.
    assert "[ROOT sudo-password]" in rec.args and "sudo -S cat /root" in rec.args  # THM Light/Smol full-sudo
    assert "[ROOT sudo-$B]" in rec.args  # NOPASSWD:/usr/bin/find etc. via the per-binary GTFOBins loop
    assert "[ROOT cap_dac_read]" in rec.args  # read-bypass capability (no setuid needed)
    assert "[ROOT disk-group]" in rec.args and "debugfs -R" in rec.args
    assert "[ROOT-VECTOR shadow-group]" in rec.args  # shadow group -> read hash (crack is the next step)
    assert "[ROOT writable-shadow]" in rec.args and "/tmp/.shb" in rec.args  # restored, no backdoor
    # cap_setuid on python is now AUTO-EXPLOITED (was flag-only) — base64'd setuid(0) payload + [ROOT cap_setuid]
    # marker. Found validating THM Oh-My-WebServer: cap_setuid on python3.7 -> os.setuid(0) -> root + flag.
    assert "[ROOT cap_setuid]" in rec.args and "base64 -d" in rec.args
    assert 'grep -ioE "/[^ ]*python[0-9.]*"' in rec.args


def test_linpeas_autoexploits_ld_preload():
    """sudo env_keep+=LD_PRELOAD is now AUTO-EXPLOITED (was flag-only): parse sudo -l for the (root)
    command, compile a base64'd .so whose _init does setuid(0)+system, run sudo LD_PRELOAD=.so <cmd>.
    Found validating THM Creative: env_keep+=LD_PRELOAD + (root) /usr/bin/ping. Handles NOPASSWD and the
    reused SSH password (sudo -S)."""
    rec = _rule_linpeas_autoexploit(_CREDS, [], "")
    a = rec.args
    assert "[ROOT LD_PRELOAD]" in a and 'grep -qiE "env_keep[^=]*=.*LD_PRELOAD"' in a
    # compiles the .so (constructor, NOT _init/-nostartfiles) and parses the (root) command out of sudo -l
    assert "gcc -fPIC -shared -o /tmp/.lp.so" in a and "-nostartfiles" not in a and '\\(root\\)' in a
    # env_keep INVOCATION form (LD_PRELOAD before sudo), not the SETENV `sudo LD_PRELOAD=..` form; NOPASSWD
    # then the reused SSH password via sudo -S
    assert "LD_PRELOAD=/tmp/.lp.so sudo -n " in a
    assert 'echo "$PW" | LD_PRELOAD=/tmp/.lp.so sudo -S ' in a
    assert "sudo -n LD_PRELOAD=" not in a  # the broken SETENV form must be gone
    # AT_SECURE guard: a sudo binary with file caps/setuid (THM Creative ping) ignores LD_PRELOAD from /tmp
    assert "[LD_PRELOAD-BLOCKED]" in a and "getcap" in a
    # the SSH password is threaded into the remote shell base64-decoded (so "$"/backticks don't expand)
    import base64 as _b64

    assert f"PW=$(echo {_b64.b64encode(b'pw123').decode()} | base64 -d)" in a


def test_cred_harvest_sweeps_fs():
    rec = _rule_cred_harvest_reuse(_CREDS, [], "")
    assert rec is not None and "CRED-FOUND" in rec.args
    assert "bash_history" in rec.args and "id_rsa" in rec.args  # history + keys


def test_both_need_creds_and_ssh():
    assert _rule_linpeas_autoexploit(ExtractedFacts(services=((22, "ssh"),), hosts=("x",)), [], "") is None
    no_ssh = ExtractedFacts(services=((445, "smb"),), hosts=("x",), creds=(("a", "b"),))
    assert _rule_linpeas_autoexploit(no_ssh, [], "") is None
    assert _rule_cred_harvest_reuse(no_ssh, [], "") is None


def test_linpeas_fires_after_ssh_with_creds():
    # key chain link: with creds + SSH and ssh_with_creds already run (sshpass marker), the planner
    # advances to linpeas_autoexploit (no web/foothold service to preempt).
    after_ssh = plan_next_action(
        _CREDS, prior_tool_args=["nmap ... (service_scan)", "sshpass ... [PRIVESC-VECTOR]"], intent=""
    )
    assert after_ssh is not None and "linpeas_auto" in after_ssh.args
    # once linpeas has run too, it abstains (its marker) and cred_harvest is eligible
    assert _rule_linpeas_autoexploit(_CREDS, [": linpeas_auto; [ROOT docker-group] x"], "") is None
    assert _rule_cred_harvest_reuse(_CREDS, [], "") is not None


def test_abstain_once_run():
    assert _rule_linpeas_autoexploit(_CREDS, [": linpeas_auto; [ROOT ...]"], "") is None
    assert _rule_cred_harvest_reuse(_CREDS, [": cred_harvest; [CRED-FOUND ...]"], "") is None
