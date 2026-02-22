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
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Responsible Use

KRYON is designed for **authorized security testing only**. If you discover that a tool or feature can be misused in ways not covered by existing guardrails, please report it as a security issue.

## Security Best Practices

When contributing to KRYON:

- Never commit API keys, tokens, or credentials
- Validate and sanitize all user inputs
- Document authorization requirements for offensive tools
- Use environment variables for all sensitive configuration
