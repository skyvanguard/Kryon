# Security Policy

## Reporting a Vulnerability

**DO NOT** open a public issue for security vulnerabilities.

Instead, please report vulnerabilities privately via [GitHub Security Advisories](https://github.com/skyvanguard/Kryon/security/advisories/new).

Include in your report:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgment within 48 hours. We aim to provide a fix or mitigation within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.1.x   | Yes       |
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Responsible Use

KRYON is designed for **authorized security testing only**. If you discover that a tool or feature can be misused in ways not covered by existing guardrails, please report it as a security issue.

## Security Features

KRYON includes several security controls:

- **JWT Authentication** with RBAC (admin/analyst/viewer roles)
- **API Key authentication** with timing-safe comparison
- **Rate limiting** (sliding window per IP, 60 rpm)
- **CORS hardening** (no wildcard with credentials)
- **Security headers** (CSP, X-Frame-Options, HSTS)
- **Input validation** on all API models
- **SQL injection prevention** via parameterized queries and column whitelisting
- **Prompt injection guardrails** for LLM agent interactions
- **Scope enforcement** to prevent out-of-scope scanning
- **Network egress policy** blocking RFC1918 ranges by default
- **Audit logging** for all mutating API operations
- **Client isolation** per analyst role
- **SIEM forwarding** for audit events

## Security Best Practices

When deploying KRYON:

- Use a strong, unique JWT secret (32+ characters)
- Enable HTTPS (TLS) in production
- Set restrictive CORS origins
- Use a reverse proxy (nginx) for SSL termination
- Keep dependencies up to date
- Review audit logs regularly
- Use the principle of least privilege for user roles

When contributing to KRYON:

- Never commit API keys, tokens, or credentials
- Validate and sanitize all user inputs
- Document authorization requirements for offensive tools
- Use environment variables for all sensitive configuration
