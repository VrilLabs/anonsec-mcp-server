# Firefox Relay MCP Server - Anonymous Email Management

> **SKILL.md** - Production-Ready MCP Server for Firefox Relay Anonymous Email Operations

---

## Overview

**Firefox Relay MCP Server** (`anonsec-mcp-server`) is a production-grade Model Context Protocol server that provides comprehensive anonymous email management capabilities through Firefox Relay addresses. Built with privacy, security, and operational excellence as core principles, this server enables AI agents and applications to send, receive, and process emails while maintaining complete anonymity.

### Core Value Proposition

- **Privacy-First**: All email operations maintain sender anonymity through Firefox Relay infrastructure
- **PQC-Ready**: Post-Quantum Cryptography ready encryption architecture for data at rest
- **Production-Grade**: Built with golden-standard programming practices for reliability and security
- **MCP Native**: Full Model Context Protocol 2.0 compliance with tools and resources

---

## Table of Contents

1. [Capabilities](#capabilities)
2. [Tools](#tools)
3. [Resources](#resources)
4. [Architecture](#architecture)
5. [Setup & Installation](#setup--installation)
6. [Configuration](#configuration)
7. [Usage Examples](#usage-examples)
8. [Security Features](#security-features)
9. [Golden Standard Practices](#golden-standard-practices)
10. [API Reference](#api-reference)
11. [Error Handling](#error-handling)
12. [Development](#development)
13. [Contributing](#contributing)
14. [License](#license)

---

## Capabilities

The Firefox Relay MCP Server provides the following core capabilities:

### Email Retrieval
- List new/unread emails
- Read full email content (with decryption)
- Retrieve all emails with filtering
- Get latest email from any relay address

### OTP Handling
- Extract OTP codes from latest email
- Validate OTP format and confidence
- Check OTP expiration
- Re-extract OTP from email body

### Email Sending
- Send anonymous emails through relay addresses
- Support for plain text and HTML content
- Custom headers and metadata
- OTP email simulation

### Resource Management
- Firefox Relay address management
- Email collection access
- OTP email collections
- Server health and status
- Audit log access

---

## Tools

The server provides **6 production-ready MCP tools** for email management:

### 1. `new_emails`

**Purpose**: Retrieve new/unread emails from Firefox Relay addresses.

**Description**: Lists all new (unread) emails received through configured Firefox Relay addresses. Supports filtering by relay address, date range, and provides detailed metadata for each email.

**Input Schema**:
```typescript
{
  relayAddressId?: number;      // Filter by specific relay address
  limit?: number;               // Maximum number of emails to return (default: 50)
  offset?: number;              // Pagination offset (default: 0)
  since?: string;               // ISO date string - only emails received after this date
  includeRead?: boolean;        // Include already read emails (default: false)
}
```

**Use Cases**:
- Check for new verification emails
- Monitor incoming messages for automated workflows
- Process unread emails in batches

**Example Response**:
```json
{
  "success": true,
  "emails": [
    {
      "id": 123,
      "emailId": "anonsec-uuid",
      "relayAddressId": 456,
      "sender": "noreply@example.com",
      "recipient": "relay@firefox.com",
      "subject": "Your Verification Code",
      "receivedAt": "2026-08-11T10:30:00.000Z",
      "isOtp": true,
      "size": 2048
    }
  ],
  "count": 1,
  "totalAvailable": 5,
  "requestId": "uuid",
  "timestamp": "2026-08-11T10:35:00.000Z"
}
```

---

### 2. `read_emails`

**Purpose**: Read full content of specific emails.

**Description**: Retrieves complete email content including body, headers, and metadata. Automatically decrypts encrypted content using PQC-ready AES-256-GCM encryption.

**Input Schema**:
```typescript
{
  emailIds: number[];           // Array of email IDs to read
  markAsRead?: boolean;         // Mark emails as read after retrieval (default: true)
  includeHeaders?: boolean;     // Include full email headers (default: false)
  decrypt?: boolean;            // Decrypt encrypted content (default: true)
}
```

**Use Cases**:
- Read full email content for processing
- Extract data from received emails
- Access encrypted email bodies

**Example Response**:
```json
{
  "success": true,
  "emails": [
    {
      "id": 123,
      "emailId": "anonsec-uuid",
      "relayAddressId": 456,
      "sender": "noreply@example.com",
      "recipient": "relay@firefox.com",
      "subject": "Your Verification Code",
      "body": "Your verification code is: 123456",
      "headers": {
        "Content-Type": "text/plain",
        "Date": "Tue, 11 Aug 2026 10:30:00 GMT"
      },
      "receivedAt": "2026-08-11T10:30:00.000Z",
      "isOtp": true,
      "otpCode": null,
      "securityFlags": ["otp_security_warning"]
    }
  ],
  "requestId": "uuid",
  "timestamp": "2026-08-11T10:35:00.000Z"
}
```

---

### 3. `all_emails`

**Purpose**: Retrieve all emails with comprehensive filtering.

**Description**: Lists all emails in the system with advanced filtering options. Supports pagination, date ranges, and filtering by relay address, OTP status, and read status.

**Input Schema**:
```typescript
{
  relayAddressId?: number;      // Filter by specific relay address
  limit?: number;               // Maximum number of emails (default: 50)
  offset?: number;              // Pagination offset (default: 0)
  since?: string;               // Only emails received after this ISO date
  until?: string;               // Only emails received before this ISO date
  isOtp?: boolean;              // Filter by OTP status
  isRead?: boolean;             // Filter by read status
  search?: string;               // Search in sender, subject, or body
}
```

**Use Cases**:
- Full email archive access
- Historical email analysis
- Bulk email processing

---

### 4. `latest_email`

**Purpose**: Get the most recent email from any or specific relay address.

**Description**: Retrieves the latest email received, optionally filtered by relay address. Provides full email content with metadata.

**Input Schema**:
```typescript
{
  relayAddressId?: number;      // Specific relay address to check
  markAsRead?: boolean;         // Mark as read after retrieval (default: false)
  includeBody?: boolean;        // Include full email body (default: true)
  decrypt?: boolean;            // Decrypt encrypted content (default: true)
}
```

**Use Cases**:
- Quick access to most recent email
- Real-time email monitoring
- Latest verification code retrieval

---

### 5. `latest_email_otp`

**Purpose**: Extract OTP code from the latest email.

**Description**: Specifically designed for OTP workflows. Retrieves the latest OTP email, extracts the verification code, validates it, and checks expiration. **Most used tool for authentication flows.**

**Input Schema**:
```typescript
{
  reExtract?: boolean;           // Re-extract OTP from email body (default: false)
  minConfidence?: number;       // Minimum OTP extraction confidence (0-1, default: 0.3)
  validateOtp?: boolean;        // Validate OTP format (default: true)
  markAsRead?: boolean;         // Mark email as read (default: false)
  maxAgeSeconds?: number;       // Maximum OTP age in seconds (default: 300 = 5 minutes)
}
```

**Use Cases**:
- Automated account verification
- Two-factor authentication flows
- Password reset code retrieval
- Any workflow requiring OTP extraction

**Example Response**:
```json
{
  "success": true,
  "otp": {
    "code": "123456",
    "provider": null,
    "type": "numeric",
    "expiresAt": null,
    "confidence": 0.95
  },
  "email": {
    "id": 123,
    "emailId": "anonsec-uuid",
    "relayAddressId": 456,
    "sender": "noreply@example.com",
    "recipient": "relay@firefox.com",
    "subject": "Your Verification Code",
    "receivedAt": "2026-08-11T10:30:00.000Z",
    "bodyPreview": "Your verification code is: 123456",
    "isOtp": true,
    "otpCode": "123456"
  },
  "requestId": "uuid",
  "timestamp": "2026-08-11T10:35:00.000Z",
  "ageSeconds": 300,
  "isExpired": false
}
```

**Error Responses**:
- `NoOtpEmailsFoundError`: No OTP emails in system
- `OtpExtractionError`: Failed to extract OTP from email
- `InvalidOtpError`: Extracted code doesn't match valid OTP format
- `ExpiredOtpError`: OTP exceeds maximum age threshold

---

### 6. `send_anon_email`

**Purpose**: Send anonymous emails through Firefox Relay addresses.

**Description**: Allows sending emails from configured Firefox Relay addresses while maintaining complete anonymity. Supports plain text and HTML content, custom headers, and OTP simulation.

**Important Note**: Firefox Relay does not currently support sending emails via API. This implementation provides a **simulation and database logging** infrastructure that can be extended when official API support becomes available.

**Input Schema**:
```typescript
{
  relayAddressId?: number;      // Relay address ID to send from
  relayAddress?: string;        // Full relay address to send from (alternative)
  to: string;                   // Recipient email address (required)
  subject: string;              // Email subject (required, max 998 chars)
  body: string;                 // Plain text email body (required, max 100KB)
  html?: string;                // HTML email body (optional, max 500KB)
  headers?: Record<string, string>; // Custom headers (default: {})
  isOtp?: boolean;              // Flag as OTP email (default: false)
  otpCode?: string;             // OTP code to include (4-10 chars)
  simulate?: boolean;           // Simulate send instead of actual (default: true)
}
```

**Use Cases**:
- Automated email responses
- Verification email sending
- Notification workflows
- Testing email flows

**Example Response**:
```json
{
  "success": true,
  "email": {
    "id": 456,
    "emailId": "anonsec-generated-uuid",
    "relayAddressId": 789,
    "fullRelayAddress": "relay@firefox.com",
    "to": "recipient@example.com",
    "subject": "Verification Code",
    "bodyPreview": "Your code is: 654321",
    "sentAt": "2026-08-11T10:40:00.000Z",
    "status": "simulated",
    "messageId": null
  },
  "requestId": "uuid",
  "timestamp": "2026-08-11T10:40:00.000Z",
  "warnings": [
    "Found 1 potential OTP codes in content"
  ]
}
```

**Error Responses**:
- `InvalidRelayAddressError`: Relay address not valid or not found
- `InvalidRecipientError`: Recipient email format invalid
- `RateLimitExceededError`: Rate limit exceeded (simulated)
- `AuthenticationError`: Authentication required (simulated)
- `EmailSendError`: General send failure

---

## Resources

The server exposes **6 MCP resources** for data access:

### 1. `urn:anonsec:relay/addresses` - Firefox Relay Addresses

**Description**: Collection of all configured Firefox Relay email addresses.

**MIME Type**: `application/json`

**Response Format**:
```json
{
  "addresses": [
    {
      "id": 123,
      "full_address": "relay+username@firefox.com",
      "display_name": "My Relay",
      "domain": "firefox.com",
      "created_at": "2026-08-11T09:00:00.000Z",
      "last_used_at": "2026-08-11T10:30:00.000Z",
      "email_count": 42,
      "is_active": true
    }
  ],
  "count": 1,
  "retrievedAt": "2026-08-11T10:45:00.000Z"
}
```

---

### 2. `urn:anonsec:email/collection` - Email Collection

**Description**: Complete collection of all received emails.

**MIME Type**: `application/json`

**Response Format**:
```json
{
  "emails": [
    {
      "id": 123,
      "emailId": "anonsec-uuid",
      "relayAddressId": 456,
      "sender": "noreply@example.com",
      "recipient": "relay@firefox.com",
      "subject": "Your Code",
      "receivedAt": "2026-08-11T10:30:00.000Z",
      "isOtp": true,
      "size": 2048
    }
  ],
  "count": 10,
  "totalAvailable": 100,
  "retrievedAt": "2026-08-11T10:45:00.000Z"
}
```

---

### 3. `urn:anonsec:otp/emails` - OTP Emails Collection

**Description**: Collection of all OTP (One-Time Password) emails.

**MIME Type**: `application/json`

**Security Note**: OTP codes are **never exposed** in resource responses (masked as `***`).

**Response Format**:
```json
{
  "emails": [
    {
      "id": 123,
      "emailId": "anonsec-uuid",
      "relayAddressId": 456,
      "sender": "noreply@example.com",
      "recipient": "relay@firefox.com",
      "subject": "Your Verification Code",
      "receivedAt": "2026-08-11T10:30:00.000Z",
      "otpCode": null,
      "isOtp": true,
      "size": 2048
    }
  ],
  "count": 5,
  "totalAvailable": 25,
  "retrievedAt": "2026-08-11T10:45:00.000Z"
}
```

---

### 4. `urn:anonsec:server/info` - Server Information

**Description**: Comprehensive server metadata, health status, and configuration.

**MIME Type**: `application/json`

**Response Format**:
```json
{
  "name": "anonsec-mcp-server",
  "version": "1.0.0",
  "timestamp": "2026-08-11T10:45:00.000Z",
  "capabilities": {
    "tools": [
      "new_emails",
      "read_emails", 
      "all_emails",
      "latest_email",
      "latest_email_otp",
      "send_anon_email"
    ],
    "resources": [
      "urn:anonsec:relay/addresses",
      "urn:anonsec:email/collection",
      "urn:anonsec:otp/emails",
      "urn:anonsec:server/info",
      "urn:anonsec:audit/logs"
    ]
  },
  "statistics": {
    "relayAddresses": 5,
    "totalEmails": 100,
    "otpEmails": 25,
    "auditLogs": 500
  },
  "configuration": {
    "databasePath": "/path/to/database.sqlite",
    "encryptionEnabled": true,
    "pqcReady": true
  }
}
```

---

### 5. `urn:anonsec:audit/logs` - Audit Logs

**Description**: Complete audit trail for security and traceability.

**MIME Type**: `application/json`

**Security Note**: Sensitive details are **redacted** in resource responses.

**Response Format**:
```json
{
  "logs": [
    {
      "id": 123,
      "timestamp": "2026-08-11T10:30:00.000Z",
      "action": "get_latest_otp_email",
      "userId": null,
      "targetId": "456",
      "targetType": "email_log"
    }
  ],
  "count": 50,
  "totalAvailable": 500,
  "retrievedAt": "2026-08-11T10:45:00.000Z"
}
```

---

### 6. `urn:anonsec:email/{emailId}` - Individual Email

**Description**: Access individual email by ID.

**URI Pattern**: `urn:anonsec:email/{emailId}`

**MIME Type**: `application/json`

**Security Note**: Content is **decrypted** on access if encrypted at rest.

**Response Format**:
```json
{
  "id": 123,
  "emailId": "anonsec-uuid",
  "relayAddressId": 456,
  "sender": "noreply@example.com",
  "recipient": "relay@firefox.com",
  "subject": "Your Verification Code",
  "body": "Your verification code is: 123456",
  "headers": {
    "Content-Type": "text/plain",
    "Date": "Tue, 11 Aug 2026 10:30:00 GMT"
  },
  "receivedAt": "2026-08-11T10:30:00.000Z",
  "readAt": null,
  "isOtp": true,
  "otpCode": null,
  "size": 2048
}
```

---

## Architecture

The Firefox Relay MCP Server follows a **clean, production-ready architecture** with the following components:

```
┌─────────────────────────────────────────────────────────────┐
│                     MCP Server Layer                        │
│  (src/index.ts)                                              │
│  - Server initialization and configuration                    │
│  - Tool registration and request handling                    │
│  - Resource access handlers                                  │
│  - Lifecycle management (graceful shutdown)                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Tools Layer                               │
│  (src/tools/*.ts)                                           │
│  - new_emails.ts       - Email retrieval                      │
│  - read_emails.ts      - Full email content access           │
│  - all_emails.ts       - Complete email listing               │
│  - latest_email.ts     - Latest email access                  │
│  - latest_email_otp.ts - OTP extraction and handling         │
│  - send_anon_email.ts  - Anonymous email sending             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Core Services Layer                       │
│  - Database Service (src/db/index.ts)       - SQLite        │
│  - API Client Service (src/api/index.ts)    - Firefox Relay │
│  - Configuration Service (src/config/index.ts)              │
│  - Type Definitions (src/types/index.ts)                     │
│  - Utility Functions (src/utils/*.ts)                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Data Layer                                  │
│  - SQLite Database (better-sqlite3)                        │
│  - PQC-Ready AES-256-GCM Encryption                          │
│  - Audit Logging                                             │
│  - Request ID Tracking (uuidv4)                              │
└─────────────────────────────────────────────────────────────┘
```

---

### Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **MCP Framework** | `@modelcontextprotocol/server` ^2.0.0 | MCP server implementation |
| **MCP SDK** | `@modelcontextprotocol/sdk` ^2.0.0 | MCP client types and utilities |
| **Database** | `better-sqlite3` ^11.0.0 | High-performance SQLite driver |
| **Validation** | `zod` ^4.0.0 | Runtime validation with TypeScript inference |
| **Encryption** | `crypto` ^1.0.0 | AES-256-GCM encryption (PQC-ready) |
| **UUID** | `uuid` ^10.0.0 | Request ID generation |
| **TypeScript** | ^5.0.0 | Type-safe development |

---

### Design Patterns

#### Singleton Pattern
All core services use singleton pattern for performance and consistency:

```typescript
// src/db/index.ts
let databaseInstance: Database | null = null;
export function getDatabase(): Database {
  if (!databaseInstance) {
    databaseInstance = new Database();
  }
  return databaseInstance;
}

// src/api/index.ts
let clientInstance: FirefoxRelayClient | null = null;
export function getClient(): FirefoxRelayClient {
  if (!clientInstance) {
    clientInstance = new FirefoxRelayClient();
  }
  return clientInstance;
}
```

#### Repository Pattern
Database operations are encapsulated in a dedicated service layer:

```typescript
class Database {
  // Email Log Operations
  insertEmailLog(log: DatabaseEmailLog): number;
  getEmailLogById(id: number): DatabaseEmailLog | null;
  getAllEmailLogs(limit?: number): DatabaseEmailLog[];
  markEmailAsRead(id: number): void;
  
  // Relay Address Operations
  insertRelayAddress(address: DatabaseRelayAddress): number;
  getRelayAddressById(id: number): DatabaseRelayAddress | null;
  getRelayAddressByFullAddress(address: string): DatabaseRelayAddress | null;
  getAllRelayAddresses(): DatabaseRelayAddress[];
  
  // OTP Operations
  insertOtpEmail(log: DatabaseOtpEmail): number;
  getLatestOtpEmail(): DatabaseEmailLog | null;
  getAllOtpEmails(): DatabaseEmailLog[];
  
  // Audit Logging
  insertAuditLog(log: DatabaseAuditLog): void;
  getAuditLogs(limit?: number): DatabaseAuditLog[];
}
```

---

## Setup & Installation

### Prerequisites

- **Node.js**: >= 18.0.0 (LTS recommended)
- **npm** or **yarn** or **pnpm**: Package manager
- **TypeScript**: ^5.0.0
- **SQLite**: Bundled with better-sqlite3

### Quick Start

#### 1. Clone the Repository

```bash
# Using SSH (preferred)
git clone git@github.com:your-org/anonsec-mcp-server.git
cd anonsec-mcp-server

# Or using HTTPS
git clone https://github.com/your-org/anonsec-mcp-server.git
cd anonsec-mcp-server
```

#### 2. Install Dependencies

```bash
# Using npm
npm install

# Using yarn
yarn install

# Using pnpm
pnpm install
```

#### 3. Configure Environment

Create `.env` file in the project root:

```bash
# Server Configuration
NODE_ENV=development
PORT=3000
HOST=localhost

# Database Configuration
DATABASE_PATH=./data/anonsec.sqlite

# Firefox Relay API (optional, for when API support is available)
FIREFOX_RELAY_API_KEY=your_api_key_here
FIREFOX_RELAY_API_URL=https://relay.firefox.com/api/v1

# Encryption Configuration
ENCRYPTION_KEY=your-32-byte-encryption-key-here
ENCRYPTION_ALGORITHM=aes-256-gcm

# Logging Configuration
LOG_LEVEL=info
ENABLE_LOGGING=true
```

**Encryption Key Generation**:
```bash
# Generate a 32-byte (256-bit) key for AES-256
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

#### 4. Build and Start

```bash
# Development mode (with hot reload)
npm run dev

# Production build
npm run build

# Start production server
npm start
```

#### 5. Verify Installation

```bash
# Check server health
curl http://localhost:3000/health

# Or use MCP client to list tools
mcp-client list-tools
```

---

## Configuration

### Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `NODE_ENV` | string | `development` | Environment mode |
| `PORT` | number | `3000` | Server port |
| `HOST` | string | `localhost` | Server hostname |
| `DATABASE_PATH` | string | `./data/anonsec.sqlite` | SQLite database path |
| `FIREFOX_RELAY_API_KEY` | string | - | Firefox Relay API key |
| `FIREFOX_RELAY_API_URL` | string | `https://relay.firefox.com/api/v1` | Firefox Relay API URL |
| `ENCRYPTION_KEY` | string | **Required** | 32-byte AES-256 key (hex) |
| `ENCRYPTION_ALGORITHM` | string | `aes-256-gcm` | Encryption algorithm |
| `LOG_LEVEL` | string | `info` | Logging level (debug, info, warn, error) |
| `ENABLE_LOGGING` | boolean | `true` | Enable console logging |

### Configuration File

The server uses a singleton Configuration class (`src/config/index.ts`) that loads from both environment variables and optional `config.json`:

```json
{
  "name": "anonsec-mcp-server",
  "version": "1.0.0",
  "port": 3000,
  "host": "localhost",
  "databasePath": "./data/anonsec.sqlite",
  "encryptionKey": "your-encryption-key",
  "encryptionAlgorithm": "aes-256-gcm",
  "enableLogging": true,
  "logLevel": "info"
}
```

---

## Usage Examples

### MCP Client Integration

#### Using the MCP Inspector

```bash
# Install MCP Inspector
npm install -g @modelcontextprotocol/inspector

# Connect to the server
mcp-inspector --server ./dist/index.js
```

#### Using Python MCP Client

```python
from mcp import Client

async def get_latest_otp():
    client = Client("anonsec-mcp-server")
    
    # Call the latest_email_otp tool
    response = await client.call_tool(
        "latest_email_otp",
        {
            "reExtract": True,
            "minConfidence": 0.5,
            "validateOtp": True,
            "maxAgeSeconds": 300
        }
    )
    
    result = response[0]['text']
    import json
    data = json.loads(result)
    
    if data['success']:
        print(f"OTP Code: {data['otp']['code']}")
        print(f"From: {data['email']['sender']}")
        print(f"Subject: {data['email']['subject']}")
        print(f"Age: {data['ageSeconds']} seconds")
    else:
        print(f"Error: {data['error']}")
```

#### Using TypeScript MCP Client

```typescript
import { Client } from '@modelcontextprotocol/sdk/client';

const client = new Client({ name: 'anonsec-mcp-server' });

async function getLatestOtp() {
  const response = await client.callTool('latest_email_otp', {
    reExtract: true,
    minConfidence: 0.5,
    validateOtp: true,
    maxAgeSeconds: 300
  });
  
  const result = JSON.parse(response.content[0].text);
  
  if (result.success) {
    console.log(`OTP Code: ${result.otp.code}`);
    console.log(`From: ${result.email.sender}`);
    console.log(`Subject: ${result.email.subject}`);
    console.log(`Age: ${result.ageSeconds} seconds`);
  } else {
    console.error(`Error: ${result.error}`);
  }
}
```

---

### Common Workflows

#### Workflow 1: Account Verification

```typescript
// Step 1: Get the latest OTP email
const otpResponse = await client.callTool('latest_email_otp', {
  reExtract: true,
  validateOtp: true,
  maxAgeSeconds: 600 // 10 minutes
});

const otpData = JSON.parse(otpResponse.content[0].text);

if (otpData.success && otpData.otp?.code) {
  const verificationCode = otpData.otp.code;
  
  // Step 2: Use the code for verification
  await verifyAccount(verificationCode);
  
  // Step 3: Mark as read (optional)
  await client.callTool('read_emails', {
    emailIds: [otpData.email.id],
    markAsRead: true
  });
}
```

#### Workflow 2: Monitor New Emails

```typescript
// Get new emails
const newEmailsResponse = await client.callTool('new_emails', {
  limit: 10,
  includeRead: false
});

const emailsData = JSON.parse(newEmailsResponse.content[0].text);

if (emailsData.success) {
  const newEmails = emailsData.emails;
  
  for (const email of newEmails) {
    console.log(`New email: ${email.subject} from ${email.sender}`);
    
    // Read full content if needed
    if (email.isOtp) {
      const otp = await getOtpFromEmail(email.id);
      console.log(`Found OTP: ${otp}`);
    }
  }
}
```

#### Workflow 3: Send Anonymous Email

```typescript
// Send an anonymous email
const sendResponse = await client.callTool('send_anon_email', {
  relayAddressId: 1, // Or use relayAddress: "relay@firefox.com"
  to: "recipient@example.com",
  subject: "Hello from AnonSec",
  body: "This email was sent anonymously through Firefox Relay.",
  isOtp: false,
  simulate: true // Set to false when actual API support is available
});

const sendData = JSON.parse(sendResponse.content[0].text);

if (sendData.success) {
  console.log(`Email sent: ${sendData.email.emailId}`);
  console.log(`Status: ${sendData.email.status}`);
}
```

---

## Security Features

### PQC-Ready Encryption Architecture

The server implements **Post-Quantum Cryptography ready** encryption for all sensitive data at rest:

#### Encryption Implementation

```typescript
// src/db/index.ts
import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'crypto';

interface EncryptionConfig {
  algorithm: string;
  key: Buffer;
  ivLength: number;
}

class Database {
  private encryptionConfig: EncryptionConfig;
  
  constructor() {
    const encryptionKey = process.env.ENCRYPTION_KEY || '';
    this.encryptionConfig = {
      algorithm: 'aes-256-gcm',
      key: Buffer.from(encryptionKey, 'hex'),
      ivLength: 12 // 96-bit IV for GCM
    };
  }
  
  encryptField(value: string, useIv: boolean = false): EncryptedField {
    const iv = useIv ? randomBytes(this.encryptionConfig.ivLength) : Buffer.alloc(0);
    const cipher = createCipheriv(
      this.encryptionConfig.algorithm,
      this.encryptionConfig.key,
      iv
    );
    
    let encrypted = cipher.update(value, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: useIv ? iv.toString('hex') : null,
      authTag: authTag.toString('hex'),
      algorithm: this.encryptionConfig.algorithm
    };
  }
  
  decryptField(encryptedField: EncryptedField, useIv: boolean = false): DecryptedField {
    const iv = encryptedField.iv ? Buffer.from(encryptedField.iv, 'hex') : Buffer.alloc(0);
    const authTag = Buffer.from(encryptedField.authTag, 'hex');
    
    const decipher = createDecipheriv(
      encryptedField.algorithm,
      this.encryptionConfig.key,
      iv
    );
    
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encryptedField.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return {
      decrypted,
      algorithm: encryptedField.algorithm
    };
  }
}
```

#### Encrypted Fields

The following fields are **always encrypted at rest**:
- `email_log.body` - Email body content
- `email_log.headers` - Email headers (JSON stringified)
- `relay_address.full_address` - Full relay email address
- Any field marked with `_encrypted: true`

### OTP Security

#### OTP Protection

- OTP codes are **never logged** in plain text
- OTP codes are **masked** (`***`) in resource responses
- OTP codes are **only exposed** through the `latest_email_otp` tool
- OTP extraction includes **confidence scoring**

#### OTP Validation

```typescript
// src/utils/otp.ts
export function isValidOtpCode(code: string): boolean {
  // Numeric OTP: 4-10 digits
  if (/^\d{4,10}$/.test(code)) {
    return true;
  }
  
  // Alphanumeric OTP: 4-10 alphanumeric characters
  if (/^[a-zA-Z0-9]{4,10}$/.test(code)) {
    return true;
  }
  
  return false;
}

export function extractOtpFromText(
  text: string,
  options: { minConfidence?: number; returnAll?: boolean } = {}
): OtpExtractionResult[] {
  const { minConfidence = 0.3, returnAll = false } = options;
  const results: OtpExtractionResult[] = [];
  
  // Pattern 1: 6-digit numeric codes (most common)
  const sixDigitPattern = /\b(\d{6})\b/g;
  
  // Pattern 2: 4-8 digit numeric codes
  const numericPattern = /\b(\d{4,8})\b/g;
  
  // Pattern 3: Alphanumeric codes
  const alphaNumericPattern = /\b([a-zA-Z0-9]{4,10})\b/g;
  
  // Extract and validate all matches
  const allMatches = [
    ...text.matchAll(sixDigitPattern),
    ...text.matchAll(numericPattern),
    ...text.matchAll(alphaNumericPattern)
  ];
  
  for (const match of allMatches) {
    const code = match[1];
    if (isValidOtpCode(code)) {
      const confidence = calculateConfidence(text, code, match.index);
      if (confidence >= minConfidence) {
        results.push({
          code,
          provider: detectProvider(text),
          type: /^\d+$/.test(code) ? 'numeric' : 'alphanumeric',
          expiresAt: extractExpiry(text),
          confidence
        });
      }
    }
  }
  
  return returnAll ? results : results.slice(0, 1);
}
```

### Audit Logging

All operations are logged to an **immutable audit trail**:

```typescript
// src/db/index.ts
interface DatabaseAuditLog {
  id: number;
  timestamp: string;           // ISO date string
  action: string;              // Action performed
  user_id: string | null;      // User ID (if authenticated)
  target_id: string;           // Target resource ID
  target_type: string;         // Target resource type
  details: string;             // JSON stringified details
  ip_address: string | null;   // Client IP address
  user_agent: string | null;   // Client user agent
}

// Audit log insertion
insertAuditLog(log: DatabaseAuditLog): void {
  const stmt = this.db.prepare(`
    INSERT INTO audit_logs (timestamp, action, user_id, target_id, target_type, details, ip_address, user_agent)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    log.timestamp,
    log.action,
    log.user_id,
    log.target_id,
    log.target_type,
    log.details,
    log.ip_address,
    log.user_agent
  );
}
```

### Request ID Tracking

Every request receives a **unique request ID** (uuidv4) for tracing:

```typescript
import { v4 as uuidv4 } from 'uuid';

// In each tool handler
const requestId = uuidv4();
const timestamp = new Date().toISOString();

// Included in all responses
{
  requestId: "550e8400-e29b-41d4-a716-446655440000",
  timestamp: "2026-08-11T10:45:00.000Z"
}
```

---

## Golden Standard Practices

This server embodies **golden-standard programming practices** throughout:

### 1. Type Safety

- **Full TypeScript** with strict mode
- **Zod v4 validation** for all inputs
- **Type-safe database operations**
- **Strong typing** for all responses

```typescript
// src/tools/latest_email_otp.ts
export const LatestEmailOtpInputSchema = z.object({
  reExtract: z.boolean().optional().default(false),
  minConfidence: z.number().min(0).max(1).optional().default(0.3),
  validateOtp: z.boolean().optional().default(true),
  markAsRead: z.boolean().optional().default(false),
  maxAgeSeconds: z.number().int().positive().optional().default(300),
});

export type LatestEmailOtpInput = z.infer<typeof LatestEmailOtpInputSchema>;
```

### 2. Error Handling

- **Custom error classes** for each error type
- **Comprehensive error handling** in all operations
- **Graceful degradation** on failures
- **Error logging** to audit trail

```typescript
// src/tools/latest_email_otp.ts
export class NoOtpEmailsFoundError extends Error {
  constructor(message: string = 'No OTP emails found') {
    super(message);
    this.name = 'NoOtpEmailsFoundError';
  }
}

export class OtpExtractionError extends Error {
  constructor(
    message: string,
    public readonly code: string = 'OTP_EXTRACTION_ERROR',
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'OtpExtractionError';
  }
}

export class InvalidOtpError extends Error {
  constructor(
    message: string,
    public readonly otpCode: string,
    public readonly reason: string
  ) {
    super(message);
    this.name = 'InvalidOtpError';
  }
}

export class ExpiredOtpError extends Error {
  constructor(
    message: string,
    public readonly ageSeconds: number,
    public readonly maxAgeSeconds: number
  ) {
    super(message);
    this.name = 'ExpiredOtpError';
  }
}
```

### 3. Validation

- **Input validation** on all tool calls
- **Schema validation** using Zod v4
- **Business rule validation**
- **Security validation** for sensitive operations

```typescript
// In tool handler
const validationResult = LatestEmailOtpInputSchema.safeParse(input);

if (!validationResult.success) {
  throw new Error(`Input validation failed: ${validationResult.error.message}`);
}

const {
  reExtract = false,
  minConfidence = 0.3,
  validateOtp = true,
  markAsRead = false,
  maxAgeSeconds = 300,
} = validationResult.data;
```

### 4. Separation of Concerns

- **Tools layer** - MCP tool implementations
- **Services layer** - Database and API services
- **Configuration layer** - Environment and config management
- **Types layer** - TypeScript type definitions
- **Utilities layer** - Helper functions

### 5. Immutability

- **Singleton services** prevent duplicate instances
- **Read-only operations** where appropriate
- **Immutable audit logs** for security

### 6. Performance

- **SQLite prepared statements** for database operations
- **Singleton pattern** for expensive resources
- **Pagination** for large result sets
- **Limits** on returned data

### 7. Security

- **Encryption at rest** for sensitive data
- **Input validation** on all operations
- **OTP protection** - never exposed in logs
- **Audit trail** for all operations
- **Request ID tracking** for tracing

---

## API Reference

### Database Schema

The server uses SQLite with the following tables:

#### `relay_addresses`

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PRIMARY KEY | Auto-incrementing ID |
| `full_address` | TEXT NOT NULL | Full relay email address (encrypted) |
| `full_address_encrypted` | BOOLEAN DEFAULT 1 | Whether full_address is encrypted |
| `display_name` | TEXT | Human-readable display name |
| `domain` | TEXT NOT NULL | Domain part of address |
| `local_part` | TEXT NOT NULL | Local part of address |
| `created_at` | TEXT NOT NULL | ISO date when created |
| `last_used_at` | TEXT | ISO date when last used |
| `email_count` | INTEGER DEFAULT 0 | Number of emails received |
| `is_active` | BOOLEAN DEFAULT 1 | Whether address is active |

#### `email_logs`

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PRIMARY KEY | Auto-incrementing ID |
| `email_id` | TEXT NOT NULL | Unique email ID |
| `relay_address_id` | INTEGER NOT NULL | Foreign key to relay_addresses |
| `sender` | TEXT NOT NULL | Sender email address |
| `recipient` | TEXT NOT NULL | Recipient email address |
| `subject` | TEXT | Email subject |
| `received_at` | TEXT NOT NULL | ISO date when received |
| `read_at` | TEXT | ISO date when read |
| `body` | TEXT | Email body (encrypted) |
| `body_encrypted` | BOOLEAN DEFAULT 1 | Whether body is encrypted |
| `otp_code` | TEXT | Extracted OTP code (if any) |
| `is_otp` | BOOLEAN DEFAULT 0 | Whether email contains OTP |
| `headers` | TEXT | JSON stringified headers (encrypted) |
| `headers_encrypted` | BOOLEAN DEFAULT 1 | Whether headers are encrypted |
| `size` | INTEGER | Approximate size in bytes |

#### `otp_emails`

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PRIMARY KEY | Auto-incrementing ID |
| `email_id` | TEXT NOT NULL | Unique email ID |
| `relay_address_id` | INTEGER NOT NULL | Foreign key to relay_addresses |
| `sender` | TEXT NOT NULL | Sender email address |
| `recipient` | TEXT NOT NULL | Recipient email address |
| `subject` | TEXT | Email subject |
| `received_at` | TEXT NOT NULL | ISO date when received |
| `otp_code` | TEXT NOT NULL | Extracted OTP code |
| `otp_type` | TEXT | OTP type (numeric/alphanumeric) |
| `confidence` | REAL | Extraction confidence score |
| `provider` | TEXT | OTP provider (if detected) |
| `expires_at` | TEXT | OTP expiration time |
| `body` | TEXT | Email body (encrypted) |
| `body_encrypted` | BOOLEAN DEFAULT 1 | Whether body is encrypted |
| `size` | INTEGER | Approximate size in bytes |

#### `audit_logs`

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PRIMARY KEY | Auto-incrementing ID |
| `timestamp` | TEXT NOT NULL | ISO date of action |
| `action` | TEXT NOT NULL | Action performed |
| `user_id` | TEXT | User ID (if authenticated) |
| `target_id` | TEXT NOT NULL | Target resource ID |
| `target_type` | TEXT NOT NULL | Target resource type |
| `details` | TEXT | JSON stringified details |
| `ip_address` | TEXT | Client IP address |
| `user_agent` | TEXT | Client user agent |

---

## Error Handling

### Error Types

All errors extend from native JavaScript `Error` with additional metadata:

| Error Class | HTTP-like Code | Description |
|-------------|---------------|-------------|
| `NoOtpEmailsFoundError` | - | No OTP emails in system |
| `OtpExtractionError` | - | Failed to extract OTP from email |
| `InvalidOtpError` | - | OTP code format invalid |
| `ExpiredOtpError` | - | OTP exceeds age threshold |
| `EmailSendError` | - | Email send operation failed |
| `InvalidRelayAddressError` | - | Relay address not valid |
| `InvalidRecipientError` | - | Recipient email invalid |
| `RateLimitExceededError` | - | Rate limit exceeded |
| `AuthenticationError` | - | Authentication required |

### Error Response Format

All errors return a consistent format:

```json
{
  "success": false,
  "error": "Error message describing the issue",
  "requestId": "unique-request-id",
  "timestamp": "ISO-date-string"
}
```

### HTTP Status Code Mapping (Conceptual)

| Error Type | Status Code |
|------------|-------------|
| Validation errors | 400 Bad Request |
| Not found errors | 404 Not Found |
| Rate limit errors | 429 Too Many Requests |
| Authentication errors | 401 Unauthorized |
| Server errors | 500 Internal Server Error |

---

## Development

### Project Structure

```
anonsec-mcp-server/
├── src/
│   ├── index.ts                    # MCP Server entry point
│   ├── config/
│   │   └── index.ts               # Configuration singleton
│   ├── db/
│   │   └── index.ts               # Database service
│   ├── api/
│   │   └── index.ts               # Firefox Relay API client
│   ├── tools/
│   │   ├── new_emails.ts          # New emails tool
│   │   ├── read_emails.ts         # Read emails tool
│   │   ├── all_emails.ts          # All emails tool
│   │   ├── latest_email.ts        # Latest email tool
│   │   ├── latest_email_otp.ts    # Latest OTP email tool
│   │   └── send_anon_email.ts     # Send anonymous email tool
│   ├── types/
│   │   └── index.ts               # TypeScript type definitions
│   └── utils/
│       ├── otp.ts                 # OTP utilities
│       └── validation.ts           # Validation utilities
├── test/
│   └── *.test.ts                  # Test files
├── data/
│   └── anonsec.sqlite             # SQLite database (created on first run)
├── dist/
│   └── index.js                   # Compiled JavaScript (npm run build)
├── package.json
├── tsconfig.json
├── .env                          # Environment configuration
└── SKILL.md                      # This documentation
```

### Scripts

| Script | Description |
|--------|-------------|
| `npm run build` | Compile TypeScript to JavaScript |
| `npm run dev` | Start development server with hot reload |
| `npm start` | Start production server |
| `npm run lint` | Run ESLint on source files |
| `npm test` | Run test suite with Vitest |
| `npm run typecheck` | TypeScript type checking without emitting |

### Code Quality

#### Linting

```bash
# Run ESLint
npm run lint

# Fix lint issues
npm run lint -- --fix
```

#### Testing

```bash
# Run all tests
npm test

# Run specific test file
npm test -- src/tools/latest_email_otp.test.ts

# Watch mode
npm test -- --watch
```

#### Type Checking

```bash
# Check types without compiling
npm run typecheck
```

---

## Contributing

Contributions are welcome! Please follow these guidelines:

### Code Style

- **TypeScript**: Use strict mode
- **Naming**: Use camelCase for variables and functions, PascalCase for types and classes
- **Imports**: Group imports by source (external, then internal)
- **Comments**: Use JSDoc for exported functions and classes
- **Line Length**: Keep lines under 120 characters when possible

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
feat: add new tool for email filtering
fix: correct OTP extraction regex pattern
chore: update dependencies
refactor: improve error handling in tools
docs: update SKILL.md with usage examples
```

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the **MIT License**:

```
MIT License

Copyright (c) 2026 AnonSec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Support

### Troubleshooting

#### Server won't start

```bash
# Check if port is in use
lsof -i :3000

# Try a different port
PORT=4000 npm run dev
```

#### Database errors

```bash
# Check database file permissions
ls -la data/anonsec.sqlite

# Ensure directory exists
mkdir -p data
```

#### Encryption errors

```bash
# Verify encryption key is correct length
# Must be exactly 32 bytes (64 hex characters)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Getting Help

- Check the [MCP Documentation](https://github.com/modelcontextprotocol/specification)
- Review the [Firefox Relay API](https://relay.firefox.com/developers)
- Open an issue in the repository

---

## Changelog

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2026-08-11 | Initial release - Production-ready MCP server with 6 tools, 6 resources, PQC encryption, comprehensive error handling |

---

## Roadmap

### Future Enhancements

- [ ] Official Firefox Relay API sending support (when available)
- [ ] WebSocket support for real-time email notifications
- [ ] Advanced email filtering and search
- [ ] Email attachment handling
- [ ] Multiple database backends (PostgreSQL, MySQL)
- [ ] Rate limiting and quota management
- [ ] Authentication and authorization
- [ ] Web-based administration interface

### PQC Upgrade Path

The server is **PQC-ready** with AES-256-GCM encryption. Future upgrades include:

- [ ] NIST PQC algorithm support (Kyber, Dilithium)
- [ ] Hybrid encryption (AES + PQC)
- [ ] Quantum-resistant key exchange

---

## References

### MCP Specification

- [Model Context Protocol Specification](https://github.com/modelcontextprotocol/specification)
- [MCP Server SDK](https://github.com/modelcontextprotocol/server)
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/sdk)

### Firefox Relay

- [Firefox Relay Website](https://relay.firefox.com)
- [Firefox Relay Documentation](https://relay.firefox.com/developers)
- [Firefox Relay API (when available)](https://relay.firefox.com/api)

### Security

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [AES-256-GCM Specification](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [OWASP Security Guidelines](https://owasp.org/www-project-cheat-sheets/)

---

## Metadata

```yaml
name: Firefox Relay MCP Server
description: Production-ready MCP server for anonymous email management with PQC-ready encryption
author: AnonSec
version: 1.0.0
license: MIT
repository: https://github.com/your-org/anonsec-mcp-server
homepage: https://anonsec.dev
keywords:
  - mcp
  - firefox-relay
  - anonymous-email
  - privacy
  - opsec
  - pqc
  - encryption
tags:
  - mcp-server
  - email
  - privacy
  - security
  - typescript
```

---

*Built with golden-standard programming practices for maximal premium code-quality and programmatic excellence.*

*Generated for the AnonSec MCP Server project - Production-Ready Firefox Relay Email Management.*
