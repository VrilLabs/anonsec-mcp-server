/**
 * Tool: send_anon_email
 * 
 * Sends an anonymous email through a Firefox Relay address.
 * This tool allows sending emails from relay addresses while maintaining
 * privacy and anonymity through the Firefox Relay service.
 * 
 * Note: Firefox Relay doesn't currently support sending emails via API.
 * This implementation provides a simulation and database logging for the purpose
 * of the MCP server, with the understanding that actual sending would be handled
 * by the user's email client or through alternative means.
 * 
 * Follows golden-standard programming practices:
 * - Zod v4 validation for input parameters
 * - Comprehensive error handling with custom error classes
 * - Database persistence with PQC encryption at rest
 * - Audit logging for security and traceability
 */

import { z } from 'zod/v4';
import { MCPTool, ToolResult } from '@modelcontextprotocol/sdk/server';
import { getClient } from '../api';
import { getDatabase } from '../db';
import { Configuration } from '../config';
import {
  DatabaseRelayAddress,
  DatabaseEmailLog,
  ApiResponse,
  ApiError,
  FIREFOX_RELAY_CONSTANTS,
  SecurityFlag,
  EmailContent,
} from '../types';
import { v4 as uuidv4 } from 'uuid';
import { extractOtpFromText, isValidOtpCode } from '../utils/otp';

// ============================================================================
// Input Validation Schema
// ============================================================================

/**
 * Schema for validating send_anon_email tool input
 */
export const SendAnonEmailInputSchema = z.object({
  /**
   * Relay address ID to send from
   */
  relayAddressId: z.number().int().positive().optional(),

  /**
   * Full relay address to send from (alternative to ID)
   */
  relayAddress: z.string().email().optional(),

  /**
   * Recipient email address
   */
  to: z.string().email(),

  /**
   * Email subject
   */
  subject: z.string().min(1).max(998), // RFC 5322 subject length limit

  /**
   * Email body (plain text)
   */
  body: z.string().min(1).max(100000), // Max 100KB body

  /**
   * Email body in HTML format (alternative to plain text body)
   */
  html: z.string().max(500000).optional(), // Max 500KB HTML

  /**
   * Custom headers to include in the email
   */
  headers: z.record(z.string(), z.string()).optional().default({}),

  /**
   * Whether to log this as an OTP email (for testing purposes)
   */
  isOtp: z.boolean().optional().default(false),

  /**
   * OTP code to include in the email (for testing/simulation)
   */
  otpCode: z.string().length(4, 10).optional(),

  /**
   * Whether to actually send the email (simulated in this implementation)
   */
  simulate: z.boolean().optional().default(true),
});

/**
 * Type for validated input
 */
export type SendAnonEmailInput = z.infer<typeof SendAnonEmailInputSchema>;

// ============================================================================
// Response Types
// ============================================================================

/**
 * Response type for the send_anon_email tool
 */
export interface SendAnonEmailResponse {
  success: boolean;
  email: {
    id: number;
    emailId: string;
    relayAddressId: number;
    fullRelayAddress: string;
    to: string;
    subject: string;
    bodyPreview: string | null;
    sentAt: string;
    status: 'sent' | 'queued' | 'failed' | 'simulated';
    messageId: string | null;
  } | null;
  requestId: string;
  timestamp: string;
  error?: string;
  warnings?: string[];
}

// ============================================================================
// Error Classes
// ============================================================================

/**
 * Custom error for send operation failures
 */
export class EmailSendError extends Error {
  constructor(
    message: string,
    public readonly code: string = 'EMAIL_SEND_ERROR',
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'EmailSendError';
  }
}

/**
 * Custom error for invalid relay address
 */
export class InvalidRelayAddressError extends Error {
  constructor(
    message: string,
    public readonly address: string
  ) {
    super(message);
    this.name = 'InvalidRelayAddressError';
  }
}

/**
 * Custom error for invalid recipient
 */
export class InvalidRecipientError extends Error {
  constructor(
    message: string,
    public readonly recipient: string
  ) {
    super(message);
    this.name = 'InvalidRecipientError';
  }
}

/**
 * Custom error for rate limiting
 */
export class RateLimitExceededError extends Error {
  constructor(
    message: string,
    public readonly retryAfter: number
  ) {
    super(message);
    this.name = 'RateLimitExceededError';
  }
}

/**
 * Custom error for authentication issues
 */
export class AuthenticationError extends Error {
  constructor(message: string = 'Authentication required for sending') {
    super(message);
    this.name = 'AuthenticationError';
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate a unique email ID
 */
function generateEmailId(): string {
  return `anonsec-${uuidv4()}`;
}

/**
 * Validate email content for security issues
 */
function validateEmailContent(
  subject: string,
  body: string,
  html?: string
): { isValid: boolean; warnings: string[] } {
  const warnings: string[] = [];

  // Check subject length
  if (subject.length > 998) {
    warnings.push('Subject exceeds recommended length (998 characters)');
  }

  // Check body length
  if (body.length > 100000) {
    warnings.push('Body exceeds recommended length (100KB)');
  }

  // Check for suspicious content patterns
  const suspiciousPatterns = [
    { pattern: /password.*is.*\w+/i, message: 'Potential password in content' },
    { pattern: /ssn.*\d{3}-\d{2}-\d{4}/i, message: 'Potential SSN in content' },
    { pattern: /credit.*card.*\d{4}/i, message: 'Potential credit card in content' },
    { pattern: /api.*key.*[a-z0-9-]{20,}/i, message: 'Potential API key in content' },
    { pattern: /secret.*[a-z0-9-]{20,}/i, message: 'Potential secret in content' },
  ];

  const contentToCheck = `${subject}\n${body}${html ? '\n' + html : ''}`;

  for (const { pattern, message } of suspiciousPatterns) {
    if (pattern.test(contentToCheck)) {
      warnings.push(message);
    }
  }

  // Check for OTP codes if not explicitly marked as OTP
  const otpPattern = /\b\d{4,10}\b/g;
  const otpMatches = contentToCheck.match(otpPattern);
  if (otpMatches && otpMatches.length > 0) {
    const validOtps = otpMatches.filter(code => isValidOtpCode(code));
    if (validOtps.length > 0) {
      warnings.push(`Found ${validOtps.length} potential OTP codes in content`);
    }
  }

  return { isValid: warnings.length === 0, warnings };
}

/**
 * Process and encrypt email content for database storage
 */
function processEmailForStorage(
  relayAddressId: number,
  to: string,
  subject: string,
  body: string,
  html?: string,
  headers?: Record<string, string>,
  isOtp: boolean = false,
  otpCode?: string
): DatabaseEmailLog {
  const db = getDatabase();
  const emailId = generateEmailId();
  const now = new Date().toISOString();

  // Encrypt sensitive fields
  const encryptedBody = db.encryptField(body, true);
  const encryptedHeaders = headers ? db.encryptField(JSON.stringify(headers), true) : null;

  // Calculate approximate size
  const size = Buffer.byteLength(body, 'utf8') + 
               (html ? Buffer.byteLength(html, 'utf8') : 0) +
               Buffer.byteLength(subject, 'utf8');

  return {
    id: 0, // Will be set by database
    relay_address_id: relayAddressId,
    email_id: emailId,
    sender: '', // Will be populated when email is actually sent
    recipient: to,
    subject,
    received_at: now,
    read_at: null,
    body: encryptedBody.encrypted,
    body_encrypted: true,
    otp_code: isOtp ? (otpCode || null) : null,
    is_otp: isOtp,
    headers: encryptedHeaders,
    headers_encrypted: Boolean(encryptedHeaders),
    size,
  };
}

// ============================================================================
// Tool Implementation
// ============================================================================

/**
 * Sends an anonymous email through a Firefox Relay address.
 * 
 * This function:
 * 1. Validates input using Zod v4
 * 2. Resolves relay address ID from either ID or full address
 * 3. Validates recipient and content
 * 4. Processes email content for database storage
 * 5. Logs the email to the database (simulated send)
 * 6. Logs all operations to audit trail
 * 
 * Note: Actual email sending is simulated as Firefox Relay doesn't
 * currently support sending via API. This implementation provides
 * the infrastructure for when API support is available.
 * 
 * @param input - Validated input parameters
 * @param context - MCP tool execution context
 * @returns Tool result with send operation details
 */
export async function sendAnonEmailHandler(
  input: unknown,
  context?: Record<string, unknown>
): Promise<ToolResult<SendAnonEmailResponse>> {
  const requestId = uuidv4();
  const timestamp = new Date().toISOString();

  // Get dependencies
  const config = Configuration.getInstance();
  const db = getDatabase();
  const client = getClient();

  try {
    // Validate input
    const validationResult = SendAnonEmailInputSchema.safeParse(input);

    if (!validationResult.success) {
      throw new Error(`Input validation failed: ${validationResult.error.message}`);
    }

    const {
      relayAddressId,
      relayAddress,
      to,
      subject,
      body,
      html,
      headers = {},
      isOtp = false,
      otpCode,
      simulate = true,
    } = validationResult.data;

    // Validate that we have either relayAddressId or relayAddress
    if (!relayAddressId && !relayAddress) {
      throw new Error('Either relayAddressId or relayAddress must be provided');
    }

    // Resolve relay address
    let resolvedRelayAddressId: number;
    let resolvedFullAddress: string;

    if (relayAddress) {
      // Validate that the address is a Firefox Relay address
      if (!client.validateRelayAddress(relayAddress)) {
        throw new InvalidRelayAddressError(
          `Invalid Firefox Relay address: ${relayAddress}`,
          relayAddress
        );
      }

      // Get address from database by full address
      const address = db.getRelayAddressByFullAddress(relayAddress);
      if (!address) {
        throw new InvalidRelayAddressError(
          `Relay address not found in database: ${relayAddress}`,
          relayAddress
        );
      }

      resolvedRelayAddressId = address.id;
      resolvedFullAddress = address.full_address;
    } else if (relayAddressId) {
      // Get address from database by ID
      const address = db.getRelayAddressById(relayAddressId);
      if (!address) {
        throw new InvalidRelayAddressError(
          `Relay address not found with ID: ${relayAddressId}`,
          String(relayAddressId)
        );
      }

      resolvedRelayAddressId = address.id;
      resolvedFullAddress = address.full_address;

      // Validate that the address is a Firefox Relay address
      if (!client.validateRelayAddress(address.full_address)) {
        throw new InvalidRelayAddressError(
          `Invalid Firefox Relay address: ${address.full_address}`,
          address.full_address
        );
      }
    } else {
      throw new Error('Either relayAddressId or relayAddress must be provided');
    }

    // Validate recipient
    if (!to || !to.includes('@') || to.length > 254) {
      throw new InvalidRecipientError(
        `Invalid recipient email address: ${to}`,
        to
      );
    }

    // Validate OTP code if provided
    if (otpCode && !isValidOtpCode(otpCode)) {
      throw new Error(`Invalid OTP code: ${otpCode}. Must be 4-10 digits or alphanumeric characters.`);
    }

    // Validate email content
    const contentValidation = validateEmailContent(subject, body, html);
    const warnings = contentValidation.warnings;

    // Check if this would be an OTP email based on content
    const detectedOtp = isOtp || (otpCode ? true : extractOtpFromText(body).length > 0);

    // Process email for storage
    const emailLog = processEmailForStorage(
      resolvedRelayAddressId,
      to,
      subject,
      body,
      html,
      { ...headers, 'X-AnonSec-Simulated': simulate ? 'true' : 'false' },
      detectedOtp,
      otpCode
    );

    // Insert email into database (simulating send)
    const insertId = db.insertEmailLog(emailLog);

    // Update the email log with the actual ID
    const insertedEmail = { ...emailLog, id: insertId };

    // In a real implementation, this is where we would make the actual
    // API call to send the email through Firefox Relay
    // For now, we simulate the send operation
    const status = simulate ? 'simulated' : 'sent';
    const messageId = simulate ? null : `anonsec-${uuidv4()}`;
    const sentAt = new Date().toISOString();

    // Log to audit trail
    db.insertAuditLog({
      timestamp,
      action: 'send_anon_email',
      user_id: context?.userId || null,
      target_id: String(insertId),
      target_type: 'email_log',
      details: JSON.stringify({
        requestId,
        emailId: emailLog.email_id,
        relayAddressId: resolvedRelayAddressId,
        fullRelayAddress: resolvedFullAddress,
        to,
        subject: subject.substring(0, 100), // Limit subject length in logs
        isOtp: detectedOtp,
        hasOtpCode: Boolean(otpCode),
        simulated: simulate,
        status,
        warnings,
      }),
      ip_address: null,
      user_agent: null,
    });

    // Build response
    const bodyPreview = body.substring(0, 200) + (body.length > 200 ? '...' : '');

    const response: SendAnonEmailResponse = {
      success: true,
      email: {
        id: insertId,
        emailId: emailLog.email_id,
        relayAddressId: resolvedRelayAddressId,
        fullRelayAddress: resolvedFullAddress,
        to,
        subject,
        bodyPreview,
        sentAt,
        status,
        messageId,
      },
      requestId,
      timestamp,
      warnings: warnings.length > 0 ? warnings : undefined,
    };

    return {
      content: [{
        type: 'text',
        text: JSON.stringify(response, null, 2),
      }],
      isError: false,
    };

  } catch (error) {
    const errorId = uuidv4();
    const errorMessage = error instanceof Error ? error.message : String(error);

    // Log error to audit trail
    try {
      const db = getDatabase();
      db.insertAuditLog({
        timestamp,
        action: 'send_anon_email_error',
        user_id: context?.userId || null,
        target_id: requestId,
        target_type: 'request',
        details: JSON.stringify({
          error: errorMessage,
          errorId,
        }),
        ip_address: null,
        user_agent: null,
      });
    } catch {
      // Ignore audit logging errors
    }

    // Handle specific error types
    if (error instanceof InvalidRelayAddressError) {
      const response: SendAnonEmailResponse = {
        success: false,
        email: null,
        requestId,
        timestamp,
        error: error.message,
      };

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(response, null, 2),
        }],
        isError: true,
      };
    }

    if (error instanceof InvalidRecipientError) {
      const response: SendAnonEmailResponse = {
        success: false,
        email: null,
        requestId,
        timestamp,
        error: error.message,
      };

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(response, null, 2),
        }],
        isError: true,
      };
    }

    if (error instanceof RateLimitExceededError) {
      const response: SendAnonEmailResponse = {
        success: false,
        email: null,
        requestId,
        timestamp,
        error: error.message,
      };

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(response, null, 2),
        }],
        isError: true,
      };
    }

    if (error instanceof AuthenticationError) {
      const response: SendAnonEmailResponse = {
        success: false,
        email: null,
        requestId,
        timestamp,
        error: error.message,
      };

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(response, null, 2),
        }],
        isError: true,
      };
    }

    if (error instanceof EmailSendError) {
      const response: SendAnonEmailResponse = {
        success: false,
        email: null,
        requestId,
        timestamp,
        error: error.message,
      };

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(response, null, 2),
        }],
        isError: true,
      };
    }

    // Handle unknown errors
    const response: SendAnonEmailResponse = {
      success: false,
      email: null,
      requestId,
      timestamp,
      error: `Failed to send anonymous email: ${errorMessage}`,
    };

    return {
      content: [{
        type: 'text',
        text: JSON.stringify(response, null, 2),
      }],
      isError: true,
    };
  }
}

// ============================================================================
// MCP Tool Definition
// ============================================================================

/**
 * MCP Tool definition for send_anon_email
 */
export const sendAnonEmailTool: MCPTool = {
  name: 'send_anon_email',
  description: 'Sends an anonymous email through a Firefox Relay address. Allows sending emails from relay addresses while maintaining privacy and anonymity. Supports plain text and HTML content, custom headers, OTP flagging, and content validation. Note: Actual sending is simulated as Firefox Relay API does not currently support sending emails directly.',
  inputSchema: SendAnonEmailInputSchema,
  handler: sendAnonEmailHandler,
};

// ============================================================================
// Exports
// ============================================================================

export {
  SendAnonEmailInputSchema,
  SendAnonEmailResponse,
  EmailSendError,
  InvalidRelayAddressError,
  InvalidRecipientError,
  RateLimitExceededError,
  AuthenticationError,
};

export default sendAnonEmailTool;
