/**
 * Tool: read_emails
 * 
 * Retrieves and reads emails from Firefox Relay addresses with OTP extraction
 * and security analysis capabilities.
 * 
 * Follows golden-standard programming practices:
 * - Zod v4 validation for input parameters
 * - Comprehensive error handling with custom error classes
 * - Database persistence with PQC encryption at rest
 * - OTP extraction and security analysis
 * - Audit logging for security and traceability
 */

import { z } from 'zod/v4';
import { CallToolRequestSchema, MCPTool, ToolResult } from '@modelcontextprotocol/sdk/server';
import { getClient } from '../api';
import { getDatabase } from '../db';
import { Configuration } from '../config';
import {
  DatabaseEmailLog,
  DatabaseRelayAddress,
  ApiResponse,
  ApiError,
  FIREFOX_RELAY_CONSTANTS,
  EmailContent,
  OtpExtractionResult,
  ProcessedEmail,
  SecurityFlag,
} from '../types';
import { v4 as uuidv4 } from 'uuid';
import { extractOtpFromText, extractOtpFromEmail } from '../utils/otp';

// ============================================================================
// Input Validation Schema
// ============================================================================

/**
 * Schema for validating read_emails tool input
 */
export const ReadEmailsInputSchema = z.object({
  /**
   * Relay address ID to read emails from
   */
  relayAddressId: z.number().int().positive().optional(),
  
  /**
   * Full relay address to read emails from (alternative to ID)
   */
  relayAddress: z.string().email().optional(),
  
  /**
   * Specific email ID to read
   */
  emailId: z.string().optional(),
  
  /**
   * Maximum number of emails to return
   */
  limit: z.number().int().positive().max(100).optional().default(20),
  
  /**
   * Whether to extract OTP codes from emails
   */
  extractOtp: z.boolean().optional().default(true),
  
  /**
   * Whether to mark emails as read after retrieving
   */
  markAsRead: z.boolean().optional().default(false),
  
  /**
   * Filter by OTP emails only
   */
  otpOnly: z.boolean().optional().default(false),
  
  /**
   * Filter by unread emails only
   */
  unreadOnly: z.boolean().optional().default(false),
  
  /**
   * Search query for filtering emails
   */
  searchQuery: z.string().max(500).optional(),
});

/**
 * Type for validated input
 */
export type ReadEmailsInput = z.infer<typeof ReadEmailsInputSchema>;

// ============================================================================
// Response Types
// ============================================================================

/**
 * Response type for a retrieved email
 */
export interface RetrievedEmail {
  id: number;
  emailId: string;
  relayAddressId: number;
  fullRelayAddress: string;
  sender: string;
  recipient: string;
  subject: string;
  body: string | null;
  html: string | null;
  receivedAt: string;
  readAt: string | null;
  isRead: boolean;
  size: number;
  otpCode: string | null;
  isOtp: boolean;
  otpInfo: OtpExtractionResult | null;
  securityFlags: SecurityFlag[];
  headers: Record<string, string> | null;
}

/**
 * Response type for the read_emails tool
 */
export interface ReadEmailsResponse {
  success: boolean;
  emails: RetrievedEmail[];
  count: number;
  totalAvailable: number;
  hasMore: boolean;
  requestId: string;
  timestamp: string;
  error?: string;
}

// ============================================================================
// Error Classes
// ============================================================================

/**
 * Custom error for email retrieval failures
 */
export class EmailRetrievalError extends Error {
  constructor(
    message: string,
    public readonly code: string = 'EMAIL_RETRIEVAL_ERROR',
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'EmailRetrievalError';
  }
}

/**
 * Custom error for not found resources
 */
export class ResourceNotFoundError extends Error {
  constructor(
    message: string,
    public readonly resourceType: string,
    public readonly identifier: string | number
  ) {
    super(message);
    this.name = 'ResourceNotFoundError';
  }
}

// ============================================================================
// Security Analysis Functions
// ============================================================================

/**
 * Analyze email content for security flags
 */
function analyzeSecurity(email: EmailContent): SecurityFlag[] {
  const flags: SecurityFlag[] = [];
  
  // Check for suspicious patterns in subject
  const suspiciousSubjectPatterns = [
    /urgent/i,
    /action required/i,
    /account suspended/i,
    /verify your account/i,
    /security alert/i,
    /password reset/i,
    /login attempt/i,
    /unauthorized/i,
  ];
  
  for (const pattern of suspiciousSubjectPatterns) {
    if (pattern.test(email.subject)) {
      flags.push('phishing_suspected');
      break;
    }
  }
  
  // Check for suspicious links in body
  const suspiciousDomains = [
    'bit.ly',
    'tinyurl.com',
    'goo.gl',
    't.co',
    'is.gd',
    'buff.ly',
  ];
  
  const bodyText = (email.body || '').toLowerCase();
  for (const domain of suspiciousDomains) {
    if (bodyText.includes(domain)) {
      flags.push('suspicious_links');
      break;
    }
  }
  
  // Check for unencrypted sensitive data patterns
  const sensitivePatterns = [
    /password:\s*\w+/i,
    /ssn:\s*\d{3}-\d{2}-\d{4}/i,
    /credit card:\s*\d{4}/i,
    /bank account:\s*\d+/i,
    /api key:\s*[a-z0-9-]+/i,
    /secret:\s*[a-z0-9-]+/i,
    /token:\s*[a-z0-9-]+/i,
  ];
  
  for (const pattern of sensitivePatterns) {
    if (pattern.test(bodyText)) {
      flags.push('unencrypted_sensitive_data');
      break;
    }
  }
  
  // Remove duplicates
  return [...new Set(flags)];
}

/**
 * Process raw email content into structured format
 */
function processEmailContent(
  dbEmail: DatabaseEmailLog & { full_address: string },
  extractOtp: boolean = true
): RetrievedEmail {
  // Parse headers if present
  let headers: Record<string, string> | null = null;
  if (dbEmail.headers) {
    try {
      headers = JSON.parse(dbEmail.headers);
    } catch {
      headers = { raw: dbEmail.headers };
    }
  }
  
  // Extract OTP information
  let otpInfo: OtpExtractionResult | null = null;
  let isOtp = dbEmail.is_otp;
  let otpCode = dbEmail.otp_code;
  
  if (extractOtp && dbEmail.body) {
    otpInfo = extractOtpFromText(dbEmail.body);
    if (otpInfo) {
      isOtp = true;
      otpCode = otpInfo.code;
    }
  }
  
  // Analyze security
  const emailContent: EmailContent = {
    id: dbEmail.email_id,
    from: dbEmail.sender,
    to: [dbEmail.recipient],
    subject: dbEmail.subject,
    body: dbEmail.body || '',
    html: null,
    headers: headers || {},
    receivedAt: dbEmail.received_at,
    attachments: [],
  };
  
  const securityFlags = analyzeSecurity(emailContent);
  
  // If OTP was detected, add to security flags if not already present
  if (isOtp && !securityFlags.includes('unencrypted_sensitive_data')) {
    // OTP codes are sensitive data
    securityFlags.push('unencrypted_sensitive_data');
  }
  
  return {
    id: dbEmail.id,
    emailId: dbEmail.email_id,
    relayAddressId: dbEmail.relay_address_id,
    fullRelayAddress: dbEmail.full_address,
    sender: dbEmail.sender,
    recipient: dbEmail.recipient,
    subject: dbEmail.subject,
    body: dbEmail.body,
    html: null,
    receivedAt: dbEmail.received_at,
    readAt: dbEmail.read_at,
    isRead: Boolean(dbEmail.read_at),
    size: dbEmail.size,
    otpCode,
    isOtp: Boolean(isOtp),
    otpInfo,
    securityFlags,
    headers,
  };
}

// ============================================================================
// Tool Implementation
// ============================================================================

/**
 * Retrieves and reads emails from Firefox Relay addresses
 * 
 * This function:
 * 1. Validates input using Zod v4
 * 2. Retrieves emails from the database based on criteria
 * 3. Extracts OTP codes if requested
 * 4. Performs security analysis on email content
 * 5. Marks emails as read if requested
 * 6. Logs all operations to audit trail
 * 
 * @param input - Validated input parameters
 * @param context - MCP tool execution context
 * @returns Tool result with retrieved emails
 */
export async function readEmailsHandler(
  input: unknown,
  context?: Record<string, unknown>
): Promise<ToolResult<ReadEmailsResponse>> {
  const requestId = uuidv4();
  const timestamp = new Date().toISOString();
  
  // Get dependencies
  const config = Configuration.getInstance();
  const db = getDatabase();
  const client = getClient();
  
  try {
    // Validate input
    const validationResult = ReadEmailsInputSchema.safeParse(input);
    
    if (!validationResult.success) {
      throw new Error(`Input validation failed: ${validationResult.error.message}`);
    }
    
    const {
      relayAddressId,
      relayAddress,
      emailId,
      limit = 20,
      extractOtp = true,
      markAsRead = false,
      otpOnly = false,
      unreadOnly = false,
      searchQuery,
    } = validationResult.data;
    
    // Validate that we have either relayAddressId, relayAddress, or emailId
    if (!relayAddressId && !relayAddress && !emailId) {
      throw new Error('Either relayAddressId, relayAddress, or emailId must be provided');
    }
    
    // Resolve relay address ID if address is provided
    let resolvedRelayAddressId: number | null = relayAddressId || null;
    let resolvedFullAddress: string | null = null;
    
    if (relayAddress) {
      const address = db.getRelayAddressByFullAddress(relayAddress);
      if (!address) {
        throw new ResourceNotFoundError(
          `Relay address not found: ${relayAddress}`,
          'relay_address',
          relayAddress
        );
      }
      resolvedRelayAddressId = address.id;
      resolvedFullAddress = address.full_address;
    } else if (resolvedRelayAddressId) {
      const address = db.getRelayAddressById(resolvedRelayAddressId);
      if (!address) {
        throw new ResourceNotFoundError(
          `Relay address not found with ID: ${resolvedRelayAddressId}`,
          'relay_address',
          resolvedRelayAddressId
        );
      }
      resolvedFullAddress = address.full_address;
    }
    
    // Build query based on parameters
    let emails: DatabaseEmailLog[];
    let totalAvailable = 0;
    
    if (emailId) {
      // Get specific email by ID
      const email = db.getEmailLogById(Number(emailId));
      if (!email) {
        throw new ResourceNotFoundError(
          `Email not found: ${emailId}`,
          'email',
          emailId
        );
      }
      
      // If relay address filter is specified, verify the email belongs to it
      if (resolvedRelayAddressId && email.relay_address_id !== resolvedRelayAddressId) {
        throw new ResourceNotFoundError(
          `Email ${emailId} does not belong to relay address ${resolvedRelayAddressId}`,
          'email',
          emailId
        );
      }
      
      emails = [email];
      totalAvailable = 1;
    } else {
      // Get emails by relay address
      if (!resolvedRelayAddressId) {
        throw new Error('relayAddressId or relayAddress is required when emailId is not provided');
      }
      
      // Get all email logs for the relay address
      const allEmails = db.getEmailLogsByRelayAddressId(resolvedRelayAddressId, 1000);
      totalAvailable = allEmails.length;
      
      // Apply filters
      let filtered = allEmails;
      
      // Filter by OTP only
      if (otpOnly) {
        filtered = filtered.filter(e => e.is_otp && e.otp_code);
      }
      
      // Filter by unread only
      if (unreadOnly) {
        filtered = filtered.filter(e => !e.read_at);
      }
      
      // Filter by search query
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        filtered = filtered.filter(e => 
          e.subject.toLowerCase().includes(query) ||
          e.sender.toLowerCase().includes(query) ||
          (e.body?.toLowerCase().includes(query) ?? false)
        );
      }
      
      // Sort by received_at descending (newest first)
      filtered.sort((a, b) => new Date(b.received_at).getTime() - new Date(a.received_at).getTime());
      
      // Apply limit
      emails = filtered.slice(0, limit);
    }
    
    // Process emails
    const processedEmails: RetrievedEmail[] = [];
    
    for (const email of emails) {
      // Add full_address to email object for processing
      const emailWithAddress = { ...email, full_address: resolvedFullAddress || '' };
      const processed = processEmailContent(emailWithAddress, extractOtp);
      processedEmails.push(processed);
      
      // Mark as read if requested
      if (markAsRead && !email.read_at) {
        db.markEmailAsRead(email.id);
        
        // Update the processed email
        processed.isRead = true;
        processed.readAt = new Date().toISOString();
      }
      
      // Log to audit trail
      db.insertAuditLog({
        timestamp,
        action: 'read_email',
        user_id: context?.userId || null,
        target_id: String(email.id),
        target_type: 'email_log',
        details: JSON.stringify({
          requestId,
          emailId: email.email_id,
          relayAddressId: email.relay_address_id,
          sender: email.sender,
          subject: email.subject,
          isOtp: email.is_otp,
        }),
        ip_address: null,
        user_agent: null,
      });
    }
    
    // Build response
    const response: ReadEmailsResponse = {
      success: true,
      emails: processedEmails,
      count: processedEmails.length,
      totalAvailable,
      hasMore: (emails.length < totalAvailable) && (emails.length === limit),
      requestId,
      timestamp,
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
        action: 'read_emails_error',
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
    
    const response: ReadEmailsResponse = {
      success: false,
      emails: [],
      count: 0,
      totalAvailable: 0,
      hasMore: false,
      requestId,
      timestamp,
      error: `Failed to read emails: ${errorMessage}`,
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
 * MCP Tool definition for read_emails
 */
export const readEmailsTool: MCPTool = {
  name: 'read_emails',
  description: 'Retrieves and reads emails from Firefox Relay addresses with OTP extraction and security analysis. Supports filtering by relay address, email ID, OTP status, read status, and search queries. Returns structured email data including OTP codes, security flags, and metadata.',
  inputSchema: ReadEmailsInputSchema,
  handler: readEmailsHandler,
};

// ============================================================================
// Exports
// ============================================================================

export {
  ReadEmailsInputSchema,
  EmailRetrievalError,
  ResourceNotFoundError,
};

export default readEmailsTool;
