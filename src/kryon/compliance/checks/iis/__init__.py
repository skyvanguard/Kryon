"""Microsoft IIS hardening check modules (CIS IIS Benchmark subset) — each
registers via `register_check` on import. Audited via WinRM/PowerShell
(WebAdministration module). Explicit submodule imports trigger registration."""

from kryon.compliance.checks.iis import (  # noqa: F401 — side-effect
    c_iis_1_1_directory_browse,
    c_iis_1_2_detailed_errors,
    c_iis_1_3_server_header,
    c_iis_2_1_logging,
)
