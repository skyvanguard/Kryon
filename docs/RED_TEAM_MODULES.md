# Red-team / offensive modules — disabled by default

Kryon ships with **blue-team by default**. Offensive modules are gated
behind an opt-in flag so that:

- A prospective banking customer reviewing the repo before procurement
  does not find `darknet_operations` or `log_cleaning` loaded at
  startup.
- An auto-pipeline that imports `kryon.tools` cannot accidentally
  activate anything offensive during a compliance scan.
- Audit teams can assert via static analysis that offensive code paths
  were not reachable in their configuration.

## Gated module list

| Path | Purpose |
|------|---------|
| `kryon.tools.anonymity` | Anonymisation routing (Tor / VPN / DNS-over-HTTPS) |
| `kryon.tools.command_and_control` | C2 server infrastructure |
| `kryon.tools.data_exfiltration` | DNS tunnelling, HTTPS covert channels, ICMP exfil |
| `kryon.tools.evasion` | Anti-forensic, log cleaning, artefact scrubbing |
| `kryon.tools.lateral_movement` | Pass-the-Hash, Pass-the-Ticket, pivoting |
| `kryon.tools.post_exploitation` | Credential dumping (mimikatz, LSASS), persistence |
| `kryon.tools.privilege_escalation` | LinPEAS / WinPEAS enumeration |

Each subpackage has a `require_red_team()` call at the top of its
`__init__.py`. Attempting to `import` any of them with the flag
disabled raises a clear `ImportError`.

## How to enable

### Environment variable (preferred for CI, docker-compose)

```bash
export KRYON_RED_TEAM=true
kryon engage ...
```

### CLI flag (user-facing)

```bash
kryon --red-team engage ...
```

## How to verify it is OFF in a given deployment

```bash
python -c "
from kryon.tools._offensive_gate import is_red_team_enabled
print('RED_TEAM =', is_red_team_enabled())
import kryon.tools.evasion  # expected to raise ImportError
" && echo UNEXPECTED || echo "✓ offensive modules disabled"
```

## Relationship to CLI subcommands

`kryon engage` (the default demo orchestrator) runs in blue-team mode
unconditionally. It will refuse to load any red-team module even if the
flag is on — engage only performs read-only recon + remediation of the
target's own misconfigurations.

Any workflow that needs offensive techniques must use the agent
runtime directly (`kryon` REPL with `--red-team`) and will hit the
explicit ImportError if misconfigured.
