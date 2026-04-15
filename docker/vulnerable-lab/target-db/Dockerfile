# Target DB — MySQL exposed without TLS + weak default credentials.
#
# Planted issues:
#   - No require_secure_transport           CWE-319
#   - bind-address 0.0.0.0 (public)         CWE-200
#   - weak password for 'app' user          CWE-521
FROM mysql:8.0

COPY my.cnf /etc/mysql/conf.d/zz_demo.cnf

EXPOSE 3306
