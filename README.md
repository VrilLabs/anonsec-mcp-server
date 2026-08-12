# Firefox Relay MCP Server - Anonymous Email Management

> **Production-Ready MCP Server for Firefox Relay Anonymous Email Operations**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/VrilLabs/anonsec-mcp-server/badge)](https://scorecard.dev/viewer/?uri=github.com/VrilLabs/anonsec-mcp-server)

**Firefox Relay MCP Server** (`anonsec-mcp-server`) is a production-grade Model Context Protocol server that provides comprehensive anonymous email management capabilities through Firefox Relay addresses. Built with privacy, security, and operational excellence as core principles, this server enables AI agents and applications to send, receive, and process emails while maintaining complete anonymity.

## Core Value Proposition

- **Privacy-First**: All email operations maintain sender anonymity through Firefox Relay infrastructure
- **PQC-Ready**: Post-Quantum Cryptography ready encryption architecture for data at rest
- **Production-Grade**: Built with golden-standard programming practices for reliability and security
- **MCP Native**: Full Model Context Protocol 2.0 compliance with tools and resources

## Quick Start

### Prerequisites

- Node.js >= 18.0.0
- npm or yarn
- Firefox Relay account and API access

### Installation

```bash
# Clone the repository
git clone https://github.com/VrilLabs/anonsec-mcp-server.git
cd anonsec-mcp-server

# Install dependencies
npm install

# Build the project
npm run build

# Start the server
npm run dev
```

### Configuration

Create a `.env` file with your Firefox Relay credentials:

```env
FIREFOX_RELAY_API_KEY=your_api_key_here
ENCRYPTION_KEY=your_32_byte_hex_key_here
DATABASE_PATH=./data/anonsec.sqlite
PORT=3000
```

The encryption key must be exactly 32 bytes (64 hex characters). Generate one with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Capabilities

### Email Management
- List new/unread emails from Firefox Relay addresses
- Read full email content with decryption
- Retrieve all emails with filtering
- Get latest email from any relay address

### OTP Handling
- Extract OTP codes from emails
- Validate OTP format and confidence
- Check OTP expiration
- Re-extract OTP from email body

### Email Sending
- Send anonymous emails through relay addresses
- Support for plain text and HTML content
- Custom headers and metadata
- OTP email simulation

## Project Structure

```
.
├── src/
│   ├── index.ts          # Server entry point and configuration
│   ├── api/
│   │   └── index.ts      # Firefox Relay API client
│   ├── config/
│   │   └── index.ts      # Configuration management
│   ├── db/
│   │   └── index.ts      # SQLite database service
│   ├── tools/
│   │   ├── all_emails.ts
│   │   ├── latest_email.ts
│   │   ├── latest_email_otp.ts
│   │   ├── new_emails.ts
│   │   ├── read_emails.ts
│   │   └── send_anon_email.ts
│   ├── types/
│   │   └── index.ts      # Type definitions
│   └── utils/
│       ├── crypto.ts     # Encryption utilities
│       └── otp.ts        # OTP extraction utilities
├── package.json
├── tsconfig.json
├── LICENSE
└── README.md
```

## Tools

The server provides 6 MCP tools:

1. **new_emails** - Retrieve new/unread emails
2. **read_emails** - Read full email content
3. **all_emails** - List all emails with filtering
4. **latest_email** - Get the latest email
5. **latest_email_otp** - Extract OTP from latest email
6. **send_anon_email** - Send anonymous emails

## Resources

- `urn:anonsec:relay/addresses` - Firefox Relay address management
- `urn:anonsec:email/collection` - Email collection access
- `urn:anonsec:otp/emails` - OTP emails collection
- `urn:anonsec:server/info` - Server information
- `urn:anonsec:audit/logs` - Audit logs
- `urn:anonsec:email/{emailId}` - Individual email access

## Security Features

- **AES-256-GCM Encryption** for data at rest
- **Immutable audit logs** for all operations
- **Request ID tracking** for traceability
- **Security validation** for sensitive operations
- **OTP code masking** in responses (never exposed)
- **Sensitive data redaction** in audit logs

## Architecture

The server follows a clean, production-ready architecture:

1. **MCP Server Layer** - Server initialization, tool registration, request handling
2. **Tools Layer** - Individual tool implementations
3. **Core Services Layer** - Database, API client, configuration, types, utilities
4. **Data Layer** - SQLite database with PQC-ready encryption

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and security practices.

## License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) for details.
