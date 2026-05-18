"""F200.A — Apache Tomcat compliance checks.

Surfaced by the Britimp POC pilot 2026-05-18 against .11 (Tomcat 7.0.34,
EOL March 2021). Each submodule registers a check on import.
"""

from kryon.compliance.checks.tomcat import (  # noqa: F401 — side-effect imports
    c_tomcat_1_1_version_eol,
    c_tomcat_1_2_ajp_ghostcat,
    c_tomcat_1_3_manager_exposed,
    c_tomcat_1_4_host_manager_exposed,
    c_tomcat_2_1_error_page_version_leak,
    c_tomcat_2_2_server_header_disclosure,
    c_tomcat_2_3_docs_accessible,
    c_tomcat_2_4_examples_accessible,
)
