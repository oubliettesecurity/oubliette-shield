# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | Yes                |

## Reporting a Vulnerability

If you discover a security vulnerability in Oubliette Shield, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email us at: **security@oubliettesecurity.com**

Include the following in your report:

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours of receiving your report
- **Assessment**: Within 5 business days, we will assess the severity and impact
- **Fix**: Critical vulnerabilities will be patched within 7 days; others within 30 days
- **Disclosure**: We will coordinate disclosure timing with the reporter

## Scope

The following are in scope for security reports:

- Bypasses of the detection pipeline (false negatives on known attack patterns)
- Vulnerabilities in the Flask Blueprint (auth bypass, injection, etc.)
- Information disclosure through API endpoints
- Denial of service vectors in rate limiting or session management
- Dependencies with known CVEs

## Out of Scope

- Attacks that require physical access to the server
- Social engineering of Oubliette Security staff
- Issues in third-party LLM providers (report to the provider directly)

## Recognition

We appreciate responsible disclosure and will credit reporters in our CHANGELOG (with permission) and on our website.

Thank you for helping keep Oubliette Shield and its users secure.
