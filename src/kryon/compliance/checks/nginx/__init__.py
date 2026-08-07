"""nginx hardening check modules (CIS nginx Benchmark subset) — each registers
via `register_check` on import. Audited via `nginx -T` over SSH. Explicit
submodule imports trigger side-effect registration."""

from kryon.compliance.checks.nginx import (  # noqa: F401 — side-effect
    c_ngx_1_1_server_tokens,
    c_ngx_1_2_ssl_protocols,
    c_ngx_1_3_autoindex,
    c_ngx_2_1_worker_user,
)
