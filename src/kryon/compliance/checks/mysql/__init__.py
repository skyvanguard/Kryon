"""MySQL / MariaDB hardening check modules (CIS MySQL Benchmark subset) — each
registers via `register_check` on import. Run via the mysql client (local
socket auth) over SSH. Explicit submodule imports trigger registration."""

from kryon.compliance.checks.mysql import (  # noqa: F401 — side-effect
    c_mysql_1_1_require_tls,
    c_mysql_1_2_local_infile,
    c_mysql_2_1_anonymous_users,
    c_mysql_2_2_root_any_host,
    c_mysql_2_3_test_database,
)
