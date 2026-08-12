/**
 * Tool: latest_email_otp
 * 
 * Retrieves the latest OTP (One-Time Password) email from the system.
 * This tool is specifically designed to extract the most recent OTP code
 * from received emails, making it easy for automated workflows to access
 * verification codes.
 * 
 * Follows golden-standard programming practices:
 * - Zod v4 validation for input parameters
 * - Comprehensive error handling with custom error classes
 * - Database persistence with PQC encryption at rest
 * - OTP extraction and security analysis
 * - Audit logging for security and traceability
 */

import { z } from 'zod/v4';
import { MCPTool, ToolResult } from '@modelcontextprotocol/sdk/server';
import { getDatabase } from '../db';
import { Configuration } from '../config';
import {
  DatabaseEmailLog,
  OtpExtractionResult,
  SecurityFlag,
  EmailContent,
} from '../types';
import { v4 as uuidv4 } from 'uuid';
import { extractOtpFromText, extractOtpFromEmail, isValidOtpCode } from '../utils/otp';

// ============================================================================
// Input Validation Schema
// ============================================================================

/**
 * Schema for validating latest_email_otp tool input
 */
export const LatestEmailOtpInputSchema = z.object({
  /**
   * Whether to re-extract OTP from email body (if not already extracted)
   */
  reExtract: z.boolean().optional().default(false),

  /**
   * Minimum confidence score for OTP extraction (0-1)
   */
  minConfidence: z.number().min(0).max(1).optional().default(0.3),

  /**
   * Whether to validate that the extracted code looks like a real OTP
   */
  validateOtp: z.boolean().optional().default(true),

  /**
   * Whether to mark the OTP email as read after retrieval
   */
  markAsRead: z.boolean().optional().default(false),

  /**
   * Maximum age of OTP in seconds (to filter out expired OTPs)
   */
  maxAgeSeconds: z.number().int().positive().optional().default(300), // 5 minutes default
});

/**
 * Type for validated input
 */
export type LatestEmailOtpInput = z.infer<typeof LatestEmailOtpInputSchema>;

// ============================================================================
// Response Types
// ============================================================================

/**
 * Response type for the latest_email_otp tool
 */
export interface LatestEmailOtpResponse {
  success: boolean;
  otp: OtpExtractionResult | null;
  email: {
    id: number;
    emailId: string;
    relayAddressId: number;
    sender: string;
    recipient: string;
    subject: string;
    receivedAt: string;
    bodyPreview: string | null;
    isOtp: boolean;
    otpCode: string | null;
  } | null;
  requestId: string;
  timestamp: string;
  error?: string;
  ageSeconds?: number;
  isExpired?: boolean;
}

// ============================================================================
// Error Classes
// ============================================================================

/**
 * Custom error for no OTP emails found
 */
export class NoOtpEmailsFoundError extends Error {
  constructor(message: string = 'No OTP emails found') {
    super(message);
    this.name = 'NoOtpEmailsFoundError';
  }
}

/**
 * Custom error for OTP extraction failures
 */
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

/**
 * Custom error for invalid OTP codes
 */
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

/**
 * Custom error for expired OTP
 */
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

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Analyze email content for security flags specific to OTP
 */
function analyzeOtpSecurity(email: EmailContent): SecurityFlag[] {
  const flags: SecurityFlag[] = [];

  // OTP-specific security checks
  const bodyText = (email.body || '').toLowerCase();

  // Check for suspicious OTP patterns
  const suspiciousPatterns = [
    /do not share.*code/i,
    /keep.*code.*secret/i,
    /code.*will expire/i,
    /one time.*use/i,
    /valid for.*minutes?/i,
  ];

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(bodyText)) {
      flags.push('otp_security_warning');
      break;
    }
  }

  // Check if OTP is in the subject (less secure)
  if (email.subject && /\d{4,8}/.test(email.subject)) {
    flags.push('otp_in_subject');
  }

  return [...new Set(flags)];
}

/**
 * Process OTP email into structured format
 */
function processOtpEmail(
  dbEmail: DatabaseEmailLog,
  reExtract: boolean = false,
  minConfidence: number = 0.3,
  validateOtp: boolean = true
): LatestEmailOtpResponse['email'] & { 
  otpInfo: OtpExtractionResult | null;
  securityFlags: SecurityFlag[];
} {
  let otpInfo: OtpExtractionResult | null = null;
  let otpCode = dbEmail.otp_code;
  let isOtp = dbEmail.is_otp;

  // Re-extract OTP if requested or if not already extracted
  if (reExtract || !otpCode) {
    if (dbEmail.body) {
      const extracted = extractOtpFromText(dbEmail.body, { 
        minConfidence,
        returnAll: false
      });
      
      if (extracted && extracted.length > 0) {
        const result = extracted[0];
        
        // Validate the extracted OTP
        if (validateOtp && result.code && !isValidOtpCode(result.code)) {
          throw new InvalidOtpError(
            `Extracted OTP code is invalid: ${result.code}`,
            result.code,
            'Code does not match valid OTP format'
          );
        }
        
        otpInfo = result;
        otpCode = result.code;
        isOtp = true;
      }
    }
  } else if (dbEmail.otp_code) {
    // Use existing OTP but validate it
    if (validateOtp && !isValidOtpCode(dbEmail.otp_code)) {
      throw new InvalidOtpError(
        `Stored OTP code is invalid: ${dbEmail.otp_code}`,
        dbEmail.otp_code,
        'Stored OTP does not match valid format'
      );
    }
    
    // Create OTP info from stored code
    otpInfo = {
      code: dbEmail.otp_code,
      provider: null,
      type: /^\d+$/.test(dbEmail.otp_code) ? 'numeric' : 'alphanumeric',
      expiresAt: null,
      confidence: 0.9, // High confidence for stored OTP
    };
    otpCode = dbEmail.otp_code;
  }

  // Create email content for security analysis
  const emailContent: EmailContent = {
    id: dbEmail.email_id,
    from: dbEmail.sender,
    to: [dbEmail.recipient],
    subject: dbEmail.subject,
    body: dbEmail.body || '',
    html: null,
    headers: {},
    receivedAt: dbEmail.received_at,
    attachments: [],
  };

  const securityFlags = analyzeOtpSecurity(emailContent);

  // Add body preview (first 200 characters)
  const bodyPreview = dbEmail.body 
    ? dbEmail.body.substring(0, 200) + (dbEmail.body.length > 200 ? '...' : '')
    : null;

  return {
    id: dbEmail.id,
    emailId: dbEmail.email_id,
    relayAddressId: dbEmail.relay_address_id,
    sender: dbEmail.sender,
    recipient: dbEmail.recipient,
    subject: dbEmail.subject,
    receivedAt: dbEmail.received_at,
    bodyPreview,
    isOtp: Boolean(isOtp),
    otpCode,
    otpInfo,
    securityFlags,
  };
}

// ============================================================================
// Tool Implementation
// ============================================================================

/**
 * Retrieves the latest OTP email from the system.
 * 
 * This function:
 * 1. Validates input using Zod v4
 * 2. Retrieves the latest OTP email from the database
 * 3. Optionally re-extracts OTP codes from email body
 * 4. Validates extracted OTP codes
 * 5. Checks OTP age and expiration
 * 6. Performs security analysis
 * 7. Logs all operations to audit trail
 * 
 * @param input - Validated input parameters
 * @param context - MCP tool execution context
 * @returns Tool result with the latest OTP information
 */
export async function latestEmailOtpHandler(
  input: unknown,
  context?: Record<string, unknown>
): Promise<ToolResult<LatestEmailOtpResponse>> {
  const requestId = uuidv4();
  const timestamp = new Date().toISOString();

  // Get dependencies
  const config = Configuration.getInstance();
  const db = getDatabase();

  try {
    // Validate input
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

    // Get the latest OTP email from database
    const otpEmail = db.getLatestOtpEmail();

    if (!otpEmail) {
      throw new NoOtpEmailsFoundError('No OTP emails found in the system');
    }

    // Process the OTP email
    const processed = processOtpEmail(otpEmail, reExtract, minConfidence, validateOtp);

    // Calculate OTP age
    const receivedAt = new Date(otpEmail.received_at);
    const ageSeconds = Math.floor((Date.now() - receivedAt.getTime()) / 1000);
    const isExpired = ageSeconds > maxAgeSeconds;

    // Check if OTP is expired
    if (isExpired && maxAgeSeconds > 0) {
      throw new ExpiredOtpError(
        `OTP is expired. Age: ${ageSeconds}s, Max: ${maxAgeSeconds}s`,
        ageSeconds,
        maxAgeSeconds
      );
    }

    // Mark as read if requested
    if (markAsRead && !otpEmail.read_at) {
      db.markEmailAsRead(otpEmail.id);
    }

    // Log to audit trail
    db.insertAuditLog({
      timestamp,
      action: 'get_latest_otp_email',
      user_id: context?.userId || null,
      target_id: String(otpEmail.id),
      target_type: 'email_log',
      details: JSON.stringify({
        requestId,
        emailId: otpEmail.email_id,
        relayAddressId: otpEmail.relay_address_id,
        sender: otpEmail.sender,
        subject: otpEmail.subject,
        otpCode: otpEmail.otp_code ? '***' : null, // Don't log actual OTP
        hasOtp: Boolean(otpEmail.otp_code),
        ageSeconds,
        isExpired,
        reExtracted: reExtract,
      }),
      ip_address: null,
      user_agent: null,
    });

    // Build response
    const response: LatestEmailOtpResponse = {
      success: true,
      otp: processed.otpInfo,
      email: {
        id: processed.id,
        emailId: processed.emailId,
        relayAddressId: processed.relayAddressId,
        sender: processed.sender,
        recipient: processed.recipient,
        subject: processed.subject,
        receivedAt: processed.receivedAt,
        bodyPreview: processed.bodyPreview,
        isOtp: processed.isOtp,
        otpCode: processed.otpCode,
      },
      requestId,
      timestamp,
      ageSeconds,
      isExpired,
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
        action: 'latest_email_otp_error',
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
    if (error instanceof NoOtpEmailsFoundError) {
      const response: LatestEmailOtpResponse = {
        success: false,
        otp: null,
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

    if (error instanceof InvalidOtpError) {
      const response: LatestEmailOtpResponse = {
        success: false,
        otp: null,
        email: null,
        requestId,
        timestamp,
        error: `Invalid OTP: ${error.message} (Reason: ${error.reason})`,
      };

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(response, null, 2),
        }],
        isError: true,
      };
    }

    if (error instanceof ExpiredOtpError) {
      const response: LatestEmailOtpResponse = {
        success: false,
        otp: null,
        email: null,
        requestId,
        timestamp,
        error: error.message,
        ageSeconds: error.ageSeconds,
        isExpired: true,
      };

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(response, null, 2),
        }],
        isError: true,
      };
    }

    if (error instanceof OtpExtractionError) {
      const response: LatestEmailOtpResponse = {
        success: false,
        otp: null,
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
    const response: LatestEmailOtpResponse = {
      success: false,
      otp: null,
      email: null,
      requestId,
      timestamp,
      error: `Failed to get latest OTP email: ${errorMessage}`,
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
 * MCP Tool definition for latest_email_otp
 */
export const latestEmailOtpTool: MCPTool = {
  name: 'latest_email_otp',
  description: 'Retrieves the latest OTP (One-Time Password) email from the system. Returns the most recent OTP code with metadata including sender, subject, age, and extraction confidence. Supports re-extraction, validation, age filtering, and automatic marking as read. Perfect for automated verification workflows.',
  inputSchema: LatestEmailOtpInputSchema,
  handler: latestEmailOtpHandler,
};

// ============================================================================
// Exports
// ============================================================================

export {
  LatestEmailOtpInputSchema,
  LatestEmailOtpResponse,
  NoOtpEmailsFoundError,
  OtpExtractionError,
  InvalidOtpError,
  ExpiredOtpError,
};

export default latestEmailOtpTool;
