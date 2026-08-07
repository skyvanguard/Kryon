"""Apache HTTPD hardening check modules (CIS Apache Benchmark subset) — each
registers via `register_check` on import. Audited via config grep over SSH.
Explicit submodule imports trigger side-effect registration."""

from kryon.compliance.checks.apache import (  # noqa: F401 — side-effect
    c_apache_1_1_server_tokens,
    c_apache_1_2_server_signature,
    c_apache_2_1_indexes,
    c_apache_2_2_trace,
)
