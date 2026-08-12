# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-11

### Added

- Initial release of Firefox Relay MCP Server
- 6 production-ready MCP tools:
  - `new_emails` - Retrieve new/unread emails
  - `read_emails` - Read full email content
  - `all_emails` - List all emails with filtering
  - `latest_email` - Get the latest email
  - `latest_email_otp` - Extract OTP from latest email
  - `send_anon_email` - Send anonymous emails
- 6 MCP resources:
  - `urn:anonsec:relay/addresses` - Firefox Relay address management
  - `urn:anonsec:email/collection` - Email collection access
  - `urn:anonsec:otp/emails` - OTP emails collection
  - `urn:anonsec:server/info` - Server information
  - `urn:anonsec:audit/logs` - Audit logs
  - `urn:anonsec:email/{emailId}` - Individual email access

### Security

- AES-256-GCM encryption for data at rest
- Immutable audit logs for all operations
- Request ID tracking for traceability
- OTP code masking in responses
- Sensitive data redaction in audit logs

### Technical

- TypeScript with strict mode
- MCP Server 2.0 compliance
- SQLite database with better-sqlite3
- Firefox Relay API integration
- Comprehensive error handling

## [Unreleased]

### Added

- OpenSSF Best Practices badge preparation
- LICENSE file (MIT)
- README.md documentation
- CONTRIBUTING.md guidelines
- SECURITY.md vulnerability reporting process
- CHANGELOG.md for release tracking

### Changed

- Initial commit of project structure
