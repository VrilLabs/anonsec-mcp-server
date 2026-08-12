# Security Policy

## Supported Versions

Security updates are provided for the latest major version. Users running older versions are encouraged to upgrade to receive security fixes.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

To report a security vulnerability in Firefox Relay MCP Server:

1. **Email**: Send an email to `security@anonsec.dev` with the following information:
   - Type of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested mitigation (if any)

2. **Encrypted Reporting** (Recommended):
   - For sensitive information, use our PGP key to encrypt your report
   - PGP Key ID: `ANONSEC-SECURITY-2026`
   - Key available at: `https://anonsec.dev/security.asc`

3. **Response Time**: We aim to acknowledge all reports within 24 hours and provide a more detailed response within 72 hours.

## Vulnerability Disclosure Process

1. **Acknowledgment**: You will receive an acknowledgment of your report within 24 hours
2. **Assessment**: Our security team will assess the report and determine the severity
3. **Remediation**: We will work on a fix and test it thoroughly
4. **Disclosure**: We will coordinate with you on public disclosure timing
5. **Credit**: We will credit you in the release notes (unless you prefer to remain anonymous)

## Security Features

This project implements the following security measures:

- **AES-256-GCM Encryption** for all data at rest
- **Immutable Audit Logs** for all operations
- **Request ID Tracking** for traceability
- **Input Validation** for all tool parameters
- **OTP Code Masking** in responses (never exposed in plain text)
- **Sensitive Data Redaction** in audit logs
- **Type Safety** through TypeScript strict mode

## Security Best Practices

- Never commit encryption keys, API keys, or other secrets to version control
- Use environment variables for sensitive configuration
- Rotate encryption keys periodically
- Monitor audit logs for suspicious activity
- Keep dependencies updated

## Security References

- [OWASP Security Guidelines](https://owasp.org/www-project-cheat-sheets/)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [AES-256-GCM Specification](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

## Security Updates

Security advisories will be published in the [GitHub Security Advisories](https://github.com/your-org/anonsec-mcp-server/security/advisories) section and in the [CHANGELOG.md](CHANGELOG.md) file.
