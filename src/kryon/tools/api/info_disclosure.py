"""F101 — Information Disclosure Scanner.

Universal pre-auth scanner for accidentally-exposed files / paths.
Every web application — banking or otherwise — has the same failure
modes: `.git/config` deployed to the document root, `.env` files
served by a misconfigured nginx, source maps in production, backup
files left by careless ops.

Pure static analysis: the operator probes the target with HEAD/GET
against the path list, captures status codes + body fingerprints,
hands them to the analyzer.

21 rules across 7 groups (stable INFO-NNN IDs):

  Group A — Version control + secrets exposure (CRITICAL / HIGH)
    INFO-001  .git/config / .svn/entries / .hg/store / .bzr exposed
    INFO-002  .env / .env.{local,production,dev,staging,test} exposed
    INFO-003  Database dump exposed (*.sql, dump.sql, backup.sql)
    INFO-004  SSL/TLS private key exposed (id_rsa, *.pem, *.key, *.pfx, *.p12)
    INFO-005  Cloud credentials exposed (.aws/credentials, .docker/config.json,
              .npmrc, .pypirc, .netrc)
    INFO-007  Terraform state file exposed (terraform.tfstate)
    INFO-008  Application secrets config (database.yml, master.key,
              credentials.yml.enc, appsettings.json)

  Group B — Build artifacts (MEDIUM / LOW)
    INFO-010  JavaScript source map exposed (*.js.map)
    INFO-011  CSS source map exposed (*.css.map)
    INFO-012  Backup files (~/.bak/.swp/.old/.orig/.save)
    INFO-013  IDE artifacts (.idea/, .vscode/settings.json, .DS_Store, *.iml)
    INFO-014  Build / config files (Dockerfile, package.json, Gemfile)
    INFO-015  CI/CD config exposed (.gitlab-ci.yml, .travis.yml,
              Jenkinsfile, bitbucket-pipelines.yml, .github/workflows)
    INFO-016  Java application config (web.xml, struts.xml, hibernate.cfg.xml)

  Group C — Server-info pages (HIGH)
    INFO-020  Apache server-status / server-info / nginx_status exposed
    INFO-021  phpinfo() page exposed

  Group D — Admin / management interfaces (MEDIUM)
    INFO-022  WordPress wp-config.php exposed (backup variant)
    INFO-023  Java app server admin (Tomcat manager, JMX console, WebSphere admin)
    INFO-024  Go pprof debug endpoint exposed
    INFO-025  Spring Boot actuator endpoints exposed (env, heapdump, mappings)
    INFO-030  CMS admin path responds (wp-admin, /administrator, /admin)
    INFO-031  Database management UI (phpmyadmin, adminer)

  Group E — Documentation leakage (LOW / INFO)
    INFO-040  API docs (swagger, /api-docs, /openapi.json)
    INFO-041  GraphQL endpoint exposed (introspection / graphiql / altair)
    INFO-050  Robots.txt with suspicious disallowed paths

Banca-safety: same finding shape as F97/F98/F100. PURE static.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "DisclosureProbe",
    "DisclosureFinding",
    "DisclosureAnalysis",
    "analyze_probes",
    "default_probe_paths",
    "ALL_DISCLOSURE_RULES",
]


ALL_DISCLOSURE_RULES: frozenset[str] = frozenset(
    {
        "INFO-001",
        "INFO-002",
        "INFO-003",
        "INFO-004",
        "INFO-005",
        "INFO-007",
        "INFO-008",
        "INFO-010",
        "INFO-011",
        "INFO-012",
        "INFO-013",
        "INFO-014",
        "INFO-015",
        "INFO-016",
        "INFO-020",
        "INFO-021",
        "INFO-022",
        "INFO-023",
        "INFO-024",
        "INFO-025",
        "INFO-030",
        "INFO-031",
        "INFO-040",
        "INFO-041",
        "INFO-050",
    }
)


# Map each probe path to (rule_id, severity, title, signature-regex).
# Signature regex inspects the body fingerprint (first 200 chars
# from response) to confirm the response is the real artifact,
# not a generic 200 OK from a SPA that serves the same shell for
# every path.
_PROBE_TABLE: dict[str, tuple[str, str, str, re.Pattern]] = {
    # INFO-001: version control
    "/.git/config": (
        "INFO-001",
        "CRITICAL",
        "Git config file exposed",
        re.compile(r"\[core\]|repositoryformatversion", re.IGNORECASE),
    ),
    "/.git/HEAD": (
        "INFO-001",
        "CRITICAL",
        "Git HEAD file exposed",
        re.compile(r"^ref:\s+refs/", re.IGNORECASE | re.MULTILINE),
    ),
    "/.git/index": ("INFO-001", "CRITICAL", "Git index file exposed", re.compile(r"DIRC", re.IGNORECASE)),
    "/.git/logs/HEAD": (
        "INFO-001",
        "CRITICAL",
        "Git HEAD reflog exposed",
        re.compile(r"^[0-9a-f]{40}\s+[0-9a-f]{40}", re.MULTILINE),
    ),
    "/.gitignore": ("INFO-001", "LOW", "Gitignore file exposed (info-tier)", re.compile(r"^[\w/.*-]", re.MULTILINE)),
    "/.svn/entries": ("INFO-001", "HIGH", "SVN entries file exposed", re.compile(r"^\d+\s*$", re.MULTILINE)),
    "/.svn/wc.db": ("INFO-001", "HIGH", "SVN working copy DB exposed", re.compile(r"SQLite format 3", re.IGNORECASE)),
    "/.hg/store": (
        "INFO-001",
        "HIGH",
        "Mercurial store directory exposed",
        re.compile(r"00manifest|index", re.IGNORECASE),
    ),
    "/.bzr/branch-format": ("INFO-001", "MEDIUM", "Bazaar branch-format exposed", re.compile(r"Bazaar", re.IGNORECASE)),
    # INFO-002: env files
    "/.env": ("INFO-002", "CRITICAL", ".env file exposed", re.compile(r"=|^[A-Z_]+=", re.MULTILINE)),
    "/.env.production": (
        "INFO-002",
        "CRITICAL",
        ".env.production file exposed",
        re.compile(r"=|^[A-Z_]+=", re.MULTILINE),
    ),
    "/.env.local": ("INFO-002", "CRITICAL", ".env.local file exposed", re.compile(r"=|^[A-Z_]+=", re.MULTILINE)),
    "/.env.development": (
        "INFO-002",
        "CRITICAL",
        ".env.development file exposed",
        re.compile(r"=|^[A-Z_]+=", re.MULTILINE),
    ),
    "/.env.dev": ("INFO-002", "CRITICAL", ".env.dev file exposed", re.compile(r"=|^[A-Z_]+=", re.MULTILINE)),
    "/.env.staging": ("INFO-002", "CRITICAL", ".env.staging file exposed", re.compile(r"=|^[A-Z_]+=", re.MULTILINE)),
    "/.env.test": ("INFO-002", "CRITICAL", ".env.test file exposed", re.compile(r"=|^[A-Z_]+=", re.MULTILINE)),
    "/.env.backup": ("INFO-002", "CRITICAL", ".env.backup file exposed", re.compile(r"=|^[A-Z_]+=", re.MULTILINE)),
    # INFO-003: db dumps
    "/dump.sql": (
        "INFO-003",
        "CRITICAL",
        "Database dump file exposed",
        re.compile(r"INSERT INTO|CREATE TABLE|DROP TABLE", re.IGNORECASE),
    ),
    "/backup.sql": (
        "INFO-003",
        "CRITICAL",
        "Database backup file exposed",
        re.compile(r"INSERT INTO|CREATE TABLE|DROP TABLE", re.IGNORECASE),
    ),
    "/database.sql": (
        "INFO-003",
        "CRITICAL",
        "Database SQL exposed",
        re.compile(r"INSERT INTO|CREATE TABLE|DROP TABLE", re.IGNORECASE),
    ),
    "/db.sql": ("INFO-003", "CRITICAL", "db.sql file exposed", re.compile(r"INSERT INTO|CREATE TABLE", re.IGNORECASE)),
    "/mysql.sql": (
        "INFO-003",
        "CRITICAL",
        "mysql.sql file exposed",
        re.compile(r"INSERT INTO|CREATE TABLE", re.IGNORECASE),
    ),
    "/db_backup.sql": (
        "INFO-003",
        "CRITICAL",
        "db_backup.sql exposed",
        re.compile(r"INSERT INTO|CREATE TABLE", re.IGNORECASE),
    ),
    # INFO-004: SSL/TLS private keys + SSH keys
    "/id_rsa": (
        "INFO-004",
        "CRITICAL",
        "SSH private key (id_rsa) exposed",
        re.compile(r"BEGIN (?:RSA |OPENSSH |DSA |EC )?PRIVATE KEY", re.IGNORECASE),
    ),
    "/id_dsa": (
        "INFO-004",
        "CRITICAL",
        "SSH DSA private key exposed",
        re.compile(r"BEGIN DSA PRIVATE KEY", re.IGNORECASE),
    ),
    "/id_ecdsa": (
        "INFO-004",
        "CRITICAL",
        "SSH ECDSA private key exposed",
        re.compile(r"BEGIN EC PRIVATE KEY", re.IGNORECASE),
    ),
    "/server.key": (
        "INFO-004",
        "CRITICAL",
        "TLS server private key exposed",
        re.compile(r"BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY", re.IGNORECASE),
    ),
    "/privkey.pem": (
        "INFO-004",
        "CRITICAL",
        "TLS private key (privkey.pem) exposed",
        re.compile(r"BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY", re.IGNORECASE),
    ),
    "/server.pem": (
        "INFO-004",
        "CRITICAL",
        "TLS server.pem exposed",
        re.compile(r"BEGIN (?:RSA |EC )?PRIVATE KEY", re.IGNORECASE),
    ),
    # INFO-005: cloud / package credentials
    "/.aws/credentials": (
        "INFO-005",
        "CRITICAL",
        "AWS credentials file exposed",
        re.compile(r"\[default\]|aws_access_key_id|aws_secret", re.IGNORECASE),
    ),
    "/.aws/config": (
        "INFO-005",
        "HIGH",
        "AWS config file exposed",
        re.compile(r"\[(default|profile)|region\s*=", re.IGNORECASE),
    ),
    "/.docker/config.json": (
        "INFO-005",
        "CRITICAL",
        "Docker auth config exposed",
        re.compile(r'"auths"|"credHelpers"|"credsStore"', re.IGNORECASE),
    ),
    "/.npmrc": (
        "INFO-005",
        "CRITICAL",
        ".npmrc with auth token exposed",
        re.compile(r"_authToken|//registry", re.IGNORECASE),
    ),
    "/.pypirc": (
        "INFO-005",
        "CRITICAL",
        ".pypirc with credentials exposed",
        re.compile(r"\[pypi|username\s*=|password\s*=", re.IGNORECASE),
    ),
    "/.netrc": (
        "INFO-005",
        "CRITICAL",
        ".netrc with credentials exposed",
        re.compile(r"machine\s+\S+|login\s+|password\s+", re.IGNORECASE),
    ),
    "/.boto": (
        "INFO-005",
        "HIGH",
        "Boto credentials file exposed",
        re.compile(r"\[Credentials\]|aws_access_key_id", re.IGNORECASE),
    ),
    # INFO-007: Terraform state (gold mine for secrets)
    "/terraform.tfstate": (
        "INFO-007",
        "CRITICAL",
        "Terraform state file exposed",
        re.compile(r'"terraform_version"|"resources"', re.IGNORECASE),
    ),
    "/terraform.tfstate.backup": (
        "INFO-007",
        "CRITICAL",
        "Terraform state backup exposed",
        re.compile(r'"terraform_version"|"resources"', re.IGNORECASE),
    ),
    "/.terraform/terraform.tfstate": (
        "INFO-007",
        "CRITICAL",
        "Terraform local state exposed",
        re.compile(r'"terraform_version"', re.IGNORECASE),
    ),
    # INFO-008: application secrets configs
    "/config/database.yml": (
        "INFO-008",
        "CRITICAL",
        "Rails database.yml exposed",
        re.compile(r"adapter:|username:|password:", re.IGNORECASE),
    ),
    "/config/secrets.yml": (
        "INFO-008",
        "CRITICAL",
        "Rails secrets.yml exposed",
        re.compile(r"secret_key_base|production:", re.IGNORECASE),
    ),
    "/config/master.key": (
        "INFO-008",
        "CRITICAL",
        "Rails master.key exposed",
        re.compile(r"^[0-9a-f]{32}", re.IGNORECASE),
    ),
    "/config/credentials.yml.enc": (
        "INFO-008",
        "HIGH",
        "Rails encrypted credentials file exposed",
        re.compile(r"^[A-Za-z0-9+/=]", re.MULTILINE),
    ),
    "/appsettings.json": (
        "INFO-008",
        "HIGH",
        ".NET appsettings.json exposed",
        re.compile(r'"ConnectionStrings"|"Logging"', re.IGNORECASE),
    ),
    "/appsettings.Development.json": (
        "INFO-008",
        "HIGH",
        ".NET dev appsettings exposed",
        re.compile(r'"ConnectionStrings"|"Logging"', re.IGNORECASE),
    ),
    "/application.properties": (
        "INFO-008",
        "HIGH",
        "Spring application.properties exposed",
        re.compile(r"spring\.|datasource\.url|server\.port", re.IGNORECASE),
    ),
    "/application.yml": (
        "INFO-008",
        "HIGH",
        "Spring application.yml exposed",
        re.compile(r"spring:|datasource:|server:", re.IGNORECASE),
    ),
    "/config.php": ("INFO-008", "HIGH", "config.php exposed", re.compile(r"<\?php|define\(", re.IGNORECASE)),
    "/wp-config.php.bak": (
        "INFO-022",
        "CRITICAL",
        "WordPress wp-config.php backup exposed",
        re.compile(r"DB_PASSWORD|DB_USER|AUTH_KEY", re.IGNORECASE),
    ),
    "/wp-config.php.old": (
        "INFO-022",
        "CRITICAL",
        "WordPress wp-config.php.old exposed",
        re.compile(r"DB_PASSWORD|DB_USER", re.IGNORECASE),
    ),
    "/wp-config.php.swp": (
        "INFO-022",
        "CRITICAL",
        "WordPress wp-config.php.swp exposed",
        re.compile(r"DB_PASSWORD|DB_USER", re.IGNORECASE),
    ),
    # INFO-013: IDE
    "/.idea/workspace.xml": (
        "INFO-013",
        "MEDIUM",
        "JetBrains IDE workspace exposed",
        re.compile(r"<project|<component", re.IGNORECASE),
    ),
    "/.vscode/settings.json": (
        "INFO-013",
        "LOW",
        "VS Code settings exposed",
        re.compile(r"\{|editor\.", re.IGNORECASE),
    ),
    "/.DS_Store": ("INFO-013", "LOW", "macOS Finder metadata exposed", re.compile(r"Bud1|DSDB", re.IGNORECASE)),
    "/.project": (
        "INFO-013",
        "LOW",
        "Eclipse project file exposed",
        re.compile(r"<projectDescription|<name>", re.IGNORECASE),
    ),
    "/.classpath": ("INFO-013", "LOW", "Eclipse classpath file exposed", re.compile(r"<classpath", re.IGNORECASE)),
    # INFO-014: build files
    "/Dockerfile": (
        "INFO-014",
        "MEDIUM",
        "Dockerfile exposed",
        re.compile(r"^(FROM|RUN|COPY|ENV)", re.IGNORECASE | re.MULTILINE),
    ),
    "/docker-compose.yml": (
        "INFO-014",
        "MEDIUM",
        "Docker Compose config exposed",
        re.compile(r"^services:|^version:", re.IGNORECASE | re.MULTILINE),
    ),
    "/docker-compose.override.yml": (
        "INFO-014",
        "MEDIUM",
        "docker-compose.override.yml exposed",
        re.compile(r"^services:|^version:", re.IGNORECASE | re.MULTILINE),
    ),
    "/package.json": (
        "INFO-014",
        "LOW",
        "Node.js package manifest exposed",
        re.compile(r'"name"|"version"|"dependencies"', re.IGNORECASE),
    ),
    "/package-lock.json": (
        "INFO-014",
        "LOW",
        "package-lock.json exposed",
        re.compile(r'"lockfileVersion"|"dependencies"', re.IGNORECASE),
    ),
    "/yarn.lock": (
        "INFO-014",
        "LOW",
        "yarn.lock exposed",
        re.compile(r"^# yarn lockfile|integrity sha", re.IGNORECASE | re.MULTILINE),
    ),
    "/pnpm-lock.yaml": (
        "INFO-014",
        "LOW",
        "pnpm-lock.yaml exposed",
        re.compile(r"^lockfileVersion:|^dependencies:", re.IGNORECASE | re.MULTILINE),
    ),
    "/composer.json": (
        "INFO-014",
        "LOW",
        "PHP Composer manifest exposed",
        re.compile(r'"name"|"require"', re.IGNORECASE),
    ),
    "/composer.lock": ("INFO-014", "LOW", "Composer lock file exposed", re.compile(r'"packages":', re.IGNORECASE)),
    "/requirements.txt": (
        "INFO-014",
        "LOW",
        "Python requirements exposed",
        re.compile(r"^[a-zA-Z0-9_-]+[=<>~!]+", re.MULTILINE),
    ),
    "/Pipfile": (
        "INFO-014",
        "LOW",
        "Python Pipfile exposed",
        re.compile(r"\[packages\]|\[\[source\]\]", re.IGNORECASE),
    ),
    "/Pipfile.lock": ("INFO-014", "LOW", "Pipfile.lock exposed", re.compile(r'"_meta"|"default"', re.IGNORECASE)),
    "/pyproject.toml": (
        "INFO-014",
        "LOW",
        "pyproject.toml exposed",
        re.compile(r"\[tool\.|\[project\]|\[build-system\]", re.IGNORECASE),
    ),
    "/Gemfile": (
        "INFO-014",
        "LOW",
        "Ruby Gemfile exposed",
        re.compile(r"^source\s+|^gem\s+", re.IGNORECASE | re.MULTILINE),
    ),
    "/Gemfile.lock": ("INFO-014", "LOW", "Gemfile.lock exposed", re.compile(r"GEM\b|PLATFORMS\b", re.IGNORECASE)),
    "/Cargo.toml": (
        "INFO-014",
        "LOW",
        "Rust Cargo.toml exposed",
        re.compile(r"\[package\]|\[dependencies\]", re.IGNORECASE),
    ),
    "/go.mod": (
        "INFO-014",
        "LOW",
        "Go modules file exposed",
        re.compile(r"^module\s+|^go\s+\d", re.IGNORECASE | re.MULTILINE),
    ),
    # INFO-015: CI/CD
    "/.gitlab-ci.yml": (
        "INFO-015",
        "MEDIUM",
        "GitLab CI config exposed",
        re.compile(r"^stages:|^image:|^script:", re.IGNORECASE | re.MULTILINE),
    ),
    "/.travis.yml": (
        "INFO-015",
        "MEDIUM",
        "Travis CI config exposed",
        re.compile(r"^language:|^script:", re.IGNORECASE | re.MULTILINE),
    ),
    "/.circleci/config.yml": (
        "INFO-015",
        "MEDIUM",
        "CircleCI config exposed",
        re.compile(r"^version:|^jobs:|^workflows:", re.IGNORECASE | re.MULTILINE),
    ),
    "/Jenkinsfile": (
        "INFO-015",
        "MEDIUM",
        "Jenkinsfile exposed",
        re.compile(r"pipeline\s*\{|node\s*\{|agent\s+", re.IGNORECASE),
    ),
    "/bitbucket-pipelines.yml": (
        "INFO-015",
        "MEDIUM",
        "Bitbucket Pipelines config exposed",
        re.compile(r"^pipelines:|^image:", re.IGNORECASE | re.MULTILINE),
    ),
    "/.github/workflows/main.yml": (
        "INFO-015",
        "MEDIUM",
        "GitHub Actions workflow exposed",
        re.compile(r"^on:|^jobs:|^name:", re.IGNORECASE | re.MULTILINE),
    ),
    "/azure-pipelines.yml": (
        "INFO-015",
        "MEDIUM",
        "Azure Pipelines config exposed",
        re.compile(r"^trigger:|^pool:|^stages:", re.IGNORECASE | re.MULTILINE),
    ),
    # INFO-016: Java app config
    "/WEB-INF/web.xml": (
        "INFO-016",
        "HIGH",
        "Java web.xml descriptor exposed",
        re.compile(r"<web-app|<servlet|<security", re.IGNORECASE),
    ),
    "/web.xml": ("INFO-016", "HIGH", "web.xml exposed at root", re.compile(r"<web-app|<servlet", re.IGNORECASE)),
    "/struts.xml": ("INFO-016", "HIGH", "Struts config exposed", re.compile(r"<struts|<package", re.IGNORECASE)),
    "/hibernate.cfg.xml": (
        "INFO-016",
        "HIGH",
        "Hibernate config exposed",
        re.compile(r"<hibernate-configuration", re.IGNORECASE),
    ),
    # INFO-020: server status
    "/server-status": (
        "INFO-020",
        "HIGH",
        "Apache server-status exposed",
        re.compile(r"Apache.*Status|Server uptime", re.IGNORECASE),
    ),
    "/server-info": (
        "INFO-020",
        "HIGH",
        "Apache server-info exposed",
        re.compile(r"Apache Server Information", re.IGNORECASE),
    ),
    "/nginx_status": (
        "INFO-020",
        "HIGH",
        "nginx stub_status exposed",
        re.compile(r"Active connections|server accepts handled", re.IGNORECASE),
    ),
    "/status": (
        "INFO-020",
        "MEDIUM",
        "Generic /status endpoint responds",
        re.compile(r"uptime|version|status\":", re.IGNORECASE),
    ),
    # INFO-021: phpinfo
    "/phpinfo.php": ("INFO-021", "HIGH", "phpinfo() exposed", re.compile(r"PHP Version|phpinfo", re.IGNORECASE)),
    "/info.php": ("INFO-021", "HIGH", "PHP info page exposed", re.compile(r"PHP Version|phpinfo", re.IGNORECASE)),
    "/test.php": (
        "INFO-021",
        "MEDIUM",
        "test.php exposed (often phpinfo)",
        re.compile(r"PHP Version|phpinfo", re.IGNORECASE),
    ),
    # INFO-023: Java app server admin
    "/manager/html": (
        "INFO-023",
        "HIGH",
        "Tomcat Manager UI exposed",
        re.compile(r"Tomcat|Manager App", re.IGNORECASE),
    ),
    "/manager/text": ("INFO-023", "HIGH", "Tomcat Manager text API exposed", re.compile(r"OK -|Tomcat", re.IGNORECASE)),
    "/host-manager/html": (
        "INFO-023",
        "HIGH",
        "Tomcat Host-Manager exposed",
        re.compile(r"Host Manager|Tomcat", re.IGNORECASE),
    ),
    "/jmx-console/": ("INFO-023", "HIGH", "JBoss JMX console exposed", re.compile(r"JMX|JBoss", re.IGNORECASE)),
    "/web-console/": ("INFO-023", "HIGH", "JBoss web-console exposed", re.compile(r"JBoss|Web Console", re.IGNORECASE)),
    "/admin/console": (
        "INFO-023",
        "HIGH",
        "WebSphere/Oracle admin console exposed",
        re.compile(r"WebSphere|WebLogic", re.IGNORECASE),
    ),
    # INFO-024: Go pprof
    "/debug/pprof/": (
        "INFO-024",
        "MEDIUM",
        "Go pprof debug endpoint exposed",
        re.compile(r"goroutine|heap|profile|cmdline", re.IGNORECASE),
    ),
    "/debug/pprof/heap": (
        "INFO-024",
        "MEDIUM",
        "Go pprof heap exposed",
        re.compile(r"goroutine|heap|profile", re.IGNORECASE),
    ),
    "/debug/pprof/goroutine": (
        "INFO-024",
        "MEDIUM",
        "Go pprof goroutine exposed",
        re.compile(r"goroutine|profile", re.IGNORECASE),
    ),
    # INFO-025: Spring Boot actuator
    "/actuator": (
        "INFO-025",
        "MEDIUM",
        "Spring Boot actuator root exposed",
        re.compile(r'"_links"|"href"|/actuator', re.IGNORECASE),
    ),
    "/actuator/env": (
        "INFO-025",
        "HIGH",
        "Spring Boot actuator /env exposed",
        re.compile(r'"activeProfiles"|"propertySources"', re.IGNORECASE),
    ),
    "/actuator/heapdump": (
        "INFO-025",
        "CRITICAL",
        "Spring Boot heapdump endpoint exposed",
        re.compile(r"HPROF|JAVA PROFILE", re.IGNORECASE),
    ),
    "/actuator/mappings": (
        "INFO-025",
        "MEDIUM",
        "Spring Boot actuator /mappings exposed",
        re.compile(r'"contexts"|"mappings"', re.IGNORECASE),
    ),
    "/actuator/configprops": (
        "INFO-025",
        "HIGH",
        "Spring Boot actuator /configprops exposed",
        re.compile(r'"contexts"|"beans"', re.IGNORECASE),
    ),
    "/actuator/beans": (
        "INFO-025",
        "MEDIUM",
        "Spring Boot actuator /beans exposed",
        re.compile(r'"contexts"|"beans"', re.IGNORECASE),
    ),
    "/actuator/threaddump": (
        "INFO-025",
        "MEDIUM",
        "Spring Boot actuator /threaddump exposed",
        re.compile(r'"threads"|"threadName"', re.IGNORECASE),
    ),
    "/actuator/loggers": (
        "INFO-025",
        "MEDIUM",
        "Spring Boot actuator /loggers exposed",
        re.compile(r'"levels"|"loggers"', re.IGNORECASE),
    ),
    "/actuator/health": (
        "INFO-025",
        "LOW",
        "Spring Boot actuator /health exposed",
        re.compile(r'"status"', re.IGNORECASE),
    ),
    # INFO-030: admin paths (status-based, no body match)
    "/wp-admin/": (
        "INFO-030",
        "MEDIUM",
        "WordPress admin path responds",
        re.compile(r"WordPress|wp-login", re.IGNORECASE),
    ),
    "/wp-login.php": (
        "INFO-030",
        "MEDIUM",
        "WordPress login page responds",
        re.compile(r"WordPress|wp-login|user_login", re.IGNORECASE),
    ),
    "/administrator/": (
        "INFO-030",
        "MEDIUM",
        "Joomla admin path responds",
        re.compile(r"Joomla|Administration", re.IGNORECASE),
    ),
    "/admin/": ("INFO-030", "MEDIUM", "Generic admin path responds", re.compile(r"admin|login", re.IGNORECASE)),
    "/admin.php": ("INFO-030", "MEDIUM", "admin.php responds", re.compile(r"admin|login", re.IGNORECASE)),
    "/admin/login": ("INFO-030", "MEDIUM", "/admin/login responds", re.compile(r"login|admin", re.IGNORECASE)),
    "/cpanel/": ("INFO-030", "MEDIUM", "cPanel responds", re.compile(r"cPanel", re.IGNORECASE)),
    "/webmail/": ("INFO-030", "MEDIUM", "webmail responds", re.compile(r"webmail|RoundCube|Horde", re.IGNORECASE)),
    # INFO-031: DB management
    "/phpmyadmin/": ("INFO-031", "MEDIUM", "phpMyAdmin exposed", re.compile(r"phpMyAdmin", re.IGNORECASE)),
    "/pma/": ("INFO-031", "MEDIUM", "phpMyAdmin (alt path /pma/) exposed", re.compile(r"phpMyAdmin", re.IGNORECASE)),
    "/myadmin/": ("INFO-031", "MEDIUM", "myadmin path exposed", re.compile(r"phpMyAdmin", re.IGNORECASE)),
    "/adminer.php": ("INFO-031", "MEDIUM", "Adminer DB tool exposed", re.compile(r"Adminer", re.IGNORECASE)),
    "/sql/": ("INFO-031", "MEDIUM", "/sql/ path exposed", re.compile(r"phpMyAdmin|Adminer|sql", re.IGNORECASE)),
    # INFO-040: API docs
    "/swagger-ui.html": ("INFO-040", "LOW", "Swagger UI exposed", re.compile(r"swagger|api-docs", re.IGNORECASE)),
    "/swagger/": ("INFO-040", "LOW", "Swagger path exposed", re.compile(r"swagger", re.IGNORECASE)),
    "/swagger.json": ("INFO-040", "LOW", "swagger.json exposed", re.compile(r'"swagger"|"openapi"', re.IGNORECASE)),
    "/api-docs": ("INFO-040", "LOW", "API documentation exposed", re.compile(r"swagger|openapi", re.IGNORECASE)),
    "/openapi.json": ("INFO-040", "LOW", "OpenAPI spec exposed", re.compile(r'"openapi"|"swagger"', re.IGNORECASE)),
    "/openapi.yaml": (
        "INFO-040",
        "LOW",
        "OpenAPI YAML spec exposed",
        re.compile(r"^openapi:|^swagger:|^info:", re.IGNORECASE | re.MULTILINE),
    ),
    "/v2/api-docs": ("INFO-040", "LOW", "Springfox API docs exposed", re.compile(r'"swagger"', re.IGNORECASE)),
    "/v3/api-docs": ("INFO-040", "LOW", "Springdoc API docs exposed", re.compile(r'"openapi"', re.IGNORECASE)),
    "/redoc": ("INFO-040", "LOW", "Redoc API docs exposed", re.compile(r"redoc|openapi", re.IGNORECASE)),
    # INFO-041: GraphQL
    "/graphql": (
        "INFO-041",
        "LOW",
        "GraphQL endpoint responds",
        re.compile(r'"data"|"errors"|"__schema"', re.IGNORECASE),
    ),
    "/graphiql": ("INFO-041", "MEDIUM", "GraphiQL UI exposed", re.compile(r"GraphiQL|graphql-ui", re.IGNORECASE)),
    "/altair": ("INFO-041", "MEDIUM", "Altair GraphQL UI exposed", re.compile(r"Altair|altair-graphql", re.IGNORECASE)),
    "/playground": (
        "INFO-041",
        "MEDIUM",
        "GraphQL Playground exposed",
        re.compile(r"GraphQL Playground", re.IGNORECASE),
    ),
    "/__graphql": (
        "INFO-041",
        "MEDIUM",
        "GraphQL alternate endpoint exposed",
        re.compile(r'"data"|"errors"|"__schema"', re.IGNORECASE),
    ),
    # INFO-050: robots.txt (always informational; we look for sensitive paths inside)
    "/robots.txt": (
        "INFO-050",
        "INFO",
        "Robots.txt present (review Disallow paths)",
        re.compile(r"^Disallow:|User-agent:", re.MULTILINE | re.IGNORECASE),
    ),
}


# Source map detection — different shape (operator probes the actual
# .map URL, which depends on bundle naming). The map magic comment
# at top of bundle is `//# sourceMappingURL=...`. We detect both:
# (a) operator probes a specific .map URL and gets it; (b) operator
# greps for the source mapping comment in the JS bundle (out of
# scope for v1).
_JS_MAP_RE = re.compile(r"\.js\.map$", re.IGNORECASE)
_CSS_MAP_RE = re.compile(r"\.css\.map$", re.IGNORECASE)
_BACKUP_RE = re.compile(r"\.(bak|swp|old|orig|backup|tmp|~)$", re.IGNORECASE)


@dataclass(frozen=True)
class DisclosureProbe:
    """One operator-issued probe."""

    path: str  # e.g. "/.git/config"
    http_status: int
    body_fingerprint: str = ""  # first 200-500 chars of response body
    content_length: int = 0


@dataclass(frozen=True)
class DisclosureFinding:
    """One disclosure verdict."""

    rule_id: str
    severity: str
    title: str
    detail: str
    remediation: str
    path: str = ""


@dataclass(frozen=True)
class DisclosureAnalysis:
    """Aggregated analysis."""

    total_probes: int
    findings: tuple[DisclosureFinding, ...] = field(default_factory=tuple)


def default_probe_paths() -> list[str]:
    """The canonical probe path list. Operators can extend / restrict
    per engagement context."""
    return list(_PROBE_TABLE.keys())


def _classify_probe(probe: DisclosureProbe) -> DisclosureFinding | None:
    """Run the static checks against one probe. Returns None when
    no finding fires."""
    path = probe.path
    status = probe.http_status
    fingerprint = probe.body_fingerprint or ""

    # 4xx/5xx is generally a non-finding (path doesn't exist or
    # access is blocked correctly).
    if status >= 400 and path not in ("/robots.txt",):
        return None

    # PRIORITY: if the path is a known specific entry in _PROBE_TABLE,
    # let it match BEFORE the generic .bak/.js.map catch-alls.
    # E.g. /wp-config.php.bak → INFO-022 (CRITICAL) wins over
    # INFO-012 (HIGH backup-extension catch-all).
    if path in _PROBE_TABLE:
        # fall through to the table-driven block below
        pass

    # JS/CSS source map: any 200 on a .js.map path is a finding.
    if _JS_MAP_RE.search(path) and status == 200:
        return DisclosureFinding(
            rule_id="INFO-010",
            severity="MEDIUM",
            title=f"JavaScript source map exposed ({path})",
            detail=(
                "Source maps reveal original (unminified) JavaScript "
                "source code + variable / function names. Speeds up "
                "reverse engineering + reveals internal patterns."
            ),
            remediation=(
                "Stop publishing .map files to production. Generate "
                "them locally for debugging, exclude from build artifact."
            ),
            path=path,
        )
    if _CSS_MAP_RE.search(path) and status == 200:
        return DisclosureFinding(
            rule_id="INFO-011",
            severity="LOW",
            title=f"CSS source map exposed ({path})",
            detail=(
                "CSS source maps reveal the original (pre-processor) "
                "CSS. Less impact than JS but still discloses internal "
                "file structure."
            ),
            remediation="Exclude .css.map from production builds.",
            path=path,
        )
    # Backup file by extension — only if NOT in the specific table
    # (specific entries like /wp-config.php.bak get higher-severity
    # treatment via INFO-022).
    if _BACKUP_RE.search(path) and status == 200 and path not in _PROBE_TABLE:
        return DisclosureFinding(
            rule_id="INFO-012",
            severity="HIGH",
            title=f"Backup file exposed ({path})",
            detail=(
                "Backup files (.bak / .swp / .old / .orig / ~) often "
                "contain the previous version of source code or "
                "configuration — sometimes with credentials still in "
                "them."
            ),
            remediation=(
                "Configure the web server to deny these extensions. "
                "nginx: `location ~ \\.(bak|swp|old|orig)$ { return 404; }`."
            ),
            path=path,
        )

    # Table-driven probes
    if path not in _PROBE_TABLE:
        return None
    rule_id, severity, title, body_re = _PROBE_TABLE[path]

    # Robots.txt is special: report when ANY Disallow line references
    # something sensitive (admin/api/auth/private)
    if rule_id == "INFO-050":
        if status != 200:
            return None
        sensitive = re.search(
            r"Disallow:\s*/(admin|api|backup|private|secret|auth|config)",
            fingerprint,
            re.IGNORECASE,
        )
        if sensitive:
            return DisclosureFinding(
                rule_id="INFO-050",
                severity="LOW",
                title="Robots.txt discloses sensitive paths",
                detail=(
                    f"robots.txt contains Disallow rules referencing "
                    f"sensitive paths (e.g. {sensitive.group(1)!r}). "
                    "Attackers read robots.txt FIRST to discover paths "
                    "the site wants to hide."
                ),
                remediation=(
                    "Don't enumerate sensitive paths in robots.txt. "
                    "Use proper access control instead — robots.txt is "
                    "public."
                ),
                path=path,
            )
        return None  # robots.txt exists but no sensitive disclosures

    # All other probes: 200 + body matches signature = finding.
    if status != 200:
        return None
    # If we have a body fingerprint, require it to match the
    # signature — avoids false positives from SPAs that 200 every
    # path with the same shell HTML.
    if fingerprint and not body_re.search(fingerprint):
        return None

    # If fingerprint is empty (caller did HEAD only), still flag —
    # but mention the caller should GET to confirm.
    detail_suffix = (
        "" if fingerprint and body_re.search(fingerprint) else " (probe used HEAD; recommend GET to confirm)"
    )

    return DisclosureFinding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        detail=_default_detail(rule_id, path) + detail_suffix,
        remediation=_default_remediation(rule_id, path),
        path=path,
    )


def _default_detail(rule_id: str, path: str) -> str:
    if rule_id == "INFO-001":
        return (
            f"Version control metadata exposed at {path}. Attackers "
            "extract repository contents via `wget --mirror` against "
            "the .git/.svn/.hg directory + reconstruct source code."
        )
    if rule_id == "INFO-002":
        return (
            f"Environment file exposed at {path}. Typically contains "
            "API keys, database credentials, JWT signing secrets, "
            "third-party tokens."
        )
    if rule_id == "INFO-003":
        return (
            f"Database dump exposed at {path}. Direct download = full "
            "dataset including PII, credentials, internal state."
        )
    if rule_id == "INFO-004":
        return (
            f"Private cryptographic key exposed at {path}. SSH keys "
            "grant remote shell. TLS server keys allow MITM + decrypt "
            "of captured traffic. Treat as full compromise."
        )
    if rule_id == "INFO-005":
        return (
            f"Cloud / package-manager credentials exposed at {path}. "
            "Direct access to cloud account, container registry, "
            "package publish + privilege depending on key scope."
        )
    if rule_id == "INFO-007":
        return (
            f"Terraform state file exposed at {path}. Terraform state "
            "stores resource IDs + provider credentials + secret "
            "values from `sensitive` outputs. Often the single most "
            "valuable file in a repo."
        )
    if rule_id == "INFO-008":
        return (
            f"Application config file exposed at {path}. Typically "
            "holds connection strings, master keys, secret-key-base. "
            "Credentialed access to back-end systems."
        )
    if rule_id == "INFO-015":
        return (
            f"CI/CD pipeline config exposed at {path}. Reveals build "
            "process, deploy targets, occasionally inlined secrets. "
            "Useful for supply-chain reconnaissance."
        )
    if rule_id == "INFO-016":
        return (
            f"Java application descriptor exposed at {path}. Reveals "
            "servlets, security constraints, datasource refs. Sometimes "
            "discloses dev DB credentials in <init-param>."
        )
    if rule_id == "INFO-020":
        return (
            f"Server status page at {path} reveals real-time request "
            "log + active connections + memory state. Information leak + "
            "potential timing-attack surface."
        )
    if rule_id == "INFO-021":
        return (
            f"phpinfo() page at {path} reveals PHP version, extensions, "
            "environment variables, server paths, OS details. "
            "Reconnaissance gold."
        )
    if rule_id == "INFO-022":
        return (
            f"WordPress wp-config.php backup exposed at {path}. Contains "
            "DB_PASSWORD, AUTH_KEY, SECURE_AUTH_KEY + every WP secret. "
            "Full site takeover."
        )
    if rule_id == "INFO-023":
        return (
            f"Java application-server admin interface exposed at {path}. "
            "Tomcat Manager, JBoss JMX console, WebSphere admin all "
            "accept WAR/EAR upload → RCE if creds are default/weak."
        )
    if rule_id == "INFO-024":
        return (
            f"Go pprof debugging endpoint exposed at {path}. Heap + "
            "goroutine + cmdline dumps reveal in-memory secrets, "
            "stack traces, command-line flags."
        )
    if rule_id == "INFO-025":
        return (
            f"Spring Boot actuator endpoint exposed at {path}. /env "
            "leaks environment variables. /heapdump produces a heap "
            "dump containing in-memory secrets. /mappings reveals "
            "all registered URLs."
        )
    if rule_id == "INFO-030":
        return (
            f"Admin path {path} responds. Default admin URLs are the "
            "first place credential-stuffing bots try. Even if 'protected', "
            "auth bypass / brute-force surface."
        )
    if rule_id == "INFO-031":
        return (
            f"Database management UI exposed at {path}. Direct attack path against the DB if creds are weak / default."
        )
    if rule_id == "INFO-040":
        return (
            f"API documentation exposed at {path}. Reveals every "
            "endpoint, parameter, auth method — full attack surface "
            "blueprint."
        )
    if rule_id == "INFO-041":
        return (
            f"GraphQL endpoint / UI exposed at {path}. If introspection "
            "is on, attackers extract the full schema → discover hidden "
            "queries, mutations, internal types."
        )
    return f"Resource exposed at {path}"


def _default_remediation(rule_id: str, path: str) -> str:
    if rule_id == "INFO-001":
        return (
            "Add web server rule to deny `.git/`, `.svn/`, `.hg/` "
            "directories. Move version control metadata OUT of the "
            "docroot."
        )
    if rule_id == "INFO-002":
        return (
            "Move .env files out of the document root. nginx: `location ~ /\\.env { deny all; }`. Audit deploy scripts."
        )
    if rule_id == "INFO-004":
        return (
            "Remove the key from web-accessible storage IMMEDIATELY + "
            "ROTATE it (assume compromised). Audit access logs for "
            "downloads. nginx: `location ~ \\.(pem|key|p12|pfx)$ "
            "{ deny all; }`."
        )
    if rule_id == "INFO-005":
        return (
            "Remove + rotate the credential. Move home-directory dotfiles "
            "(.aws/, .npmrc, .docker/) OUT of any served directory. "
            "Audit cloud-provider activity for the leaked key."
        )
    if rule_id == "INFO-007":
        return (
            "Move terraform.tfstate to an encrypted remote backend (S3 + "
            "DynamoDB lock, Terraform Cloud, GCS). Rotate every secret "
            "the state references."
        )
    if rule_id == "INFO-008":
        return (
            "Move config files outside docroot. Treat secrets like the rest of the codebase: never commit, never serve."
        )
    if rule_id == "INFO-015":
        return "Deny CI/CD config files at the web layer. Audit for inlined secrets + migrate them to a secret manager."
    if rule_id == "INFO-016":
        return (
            "Block /WEB-INF/ + /META-INF/ + standalone *.xml descriptors at the web tier. These should never be served."
        )
    if rule_id == "INFO-020":
        return (
            "Disable Apache mod_status / mod_info / nginx stub_status "
            "in production OR restrict access by IP allow-list."
        )
    if rule_id == "INFO-021":
        return (
            "Remove phpinfo() / info.php / test.php files from production. "
            "These are debugging shims that shouldn't ship."
        )
    if rule_id == "INFO-022":
        return (
            "Delete the .bak/.old/.swp variant of wp-config.php IMMEDIATELY "
            "+ ROTATE every WordPress secret (DB password, AUTH_KEY, "
            "SECURE_AUTH_KEY, NONCE_KEY, salts). Configure your deploy "
            "to exclude *.bak."
        )
    if rule_id == "INFO-023":
        return (
            "Restrict Tomcat Manager / JMX console / WebSphere admin to "
            "internal management network only. Enforce strong, "
            "non-default credentials + IP allow-list."
        )
    if rule_id == "INFO-024":
        return (
            "Bind net/http/pprof to a private interface, NOT the public "
            "listener. In Go: register pprof on a separate mux for "
            "127.0.0.1:6060."
        )
    if rule_id == "INFO-025":
        return (
            "Restrict Spring Boot actuator to /health only in production. "
            "Disable everything else: "
            "`management.endpoints.web.exposure.exclude=*` then "
            "`include=health`. Authenticate the rest."
        )
    if rule_id == "INFO-030":
        return (
            "Rename admin paths to non-default URLs + enforce strong auth "
            "+ IP allow-listing. Add rate limiting to defeat enumeration."
        )
    if rule_id == "INFO-031":
        return "Remove phpMyAdmin / Adminer from production. Use SSH tunneling for DB admin instead."
    if rule_id == "INFO-040":
        return "Gate API docs behind authentication, or remove from production entirely."
    if rule_id == "INFO-041":
        return (
            "Disable GraphQL introspection in production. Remove "
            "/graphiql /altair /playground UIs. Authenticate the "
            "GraphQL endpoint itself."
        )
    return "Remove from document root or restrict access by IP / auth."


def analyze_probes(probes: list[DisclosureProbe]) -> DisclosureAnalysis:
    """Run static classification over a list of probe results.

    Returns DisclosureAnalysis with findings sorted by severity
    (CRITICAL → INFO)."""
    findings: list[DisclosureFinding] = []
    for probe in probes:
        finding = _classify_probe(probe)
        if finding is not None:
            findings.append(finding)
    from kryon.util.severity import SEVERITY_RANK as severity_order
    findings.sort(key=lambda f: (severity_order.get(f.severity, 99), f.rule_id, f.path))
    return DisclosureAnalysis(total_probes=len(probes), findings=tuple(findings))
