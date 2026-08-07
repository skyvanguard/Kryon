"""PostgreSQL hardening check modules (CIS PostgreSQL Benchmark subset) — each
registers via `register_check` on import. Queries run as the postgres OS user
via local peer auth over SSH. Explicit submodule imports trigger registration."""

from kryon.compliance.checks.postgres import (  # noqa: F401 — side-effect
    c_pg_1_1_ssl,
    c_pg_1_2_log_connections,
    c_pg_1_3_log_disconnections,
    c_pg_2_1_password_encryption,
    c_pg_2_2_no_network_trust,
)
