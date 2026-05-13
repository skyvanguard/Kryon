"""F87 — API security tools.

Sub-package roadmap:
  openapi_importer.py  — F87.1: parse OpenAPI/Swagger spec, extract
                         endpoints + parameters + security schemes.
  bola_detector.py     — F87.2: Broken Object Level Authorization
                         (OWASP API #1) — probe IDOR via parameter
                         tampering.
  graphql_recon.py     — F87.3: GraphQL introspection + schema dump.
  fapi_validator.py    — F87.4: FAPI 1.0 Advanced conformance for
                         Open Banking endpoints (mTLS, PAR, JWT
                         response signing).

Importers and detectors are deliberately stdlib-only so they run
inside the banca air-gap container. Network I/O is gated behind tool
function boundaries — the underlying primitives accept text/dict so
unit tests don't need an HTTP server.
"""
