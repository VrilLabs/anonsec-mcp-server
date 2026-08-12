/**
 * Tool: all_emails
 * 
 * Retrieves all emails across all Firefox Relay addresses with comprehensive
 * filtering, pagination, and search capabilities.
 * 
 * Follows golden-standard programming practices:
 * - Zod v4 validation for input parameters
 * - Comprehensive error handling with custom error classes
 * - Database persistence with PQC encryption at rest
 * - Pagination support for large datasets
 * - Audit logging for security and traceability
 */

import { z } from 'zod/v4';
import { CallToolRequestSchema, MCPTool, ToolResult } from '@modelcontextprotocol/sdk/server';
import { getClient } from '../api';
import { getDatabase } from '../db';
import { Configuration } from '../config';
import {
  DatabaseEmailLog,
  ApiResponse,
  ApiError,
  FIREFOX_RELAY_CONSTANTS,
  OtpExtractionResult,
} from '../types';
import { v4 as uuidv4 } from 'uuid';
import { extractOtpFromText } from '../utils/otp';
import { analyzeSecurity, processEmailContent, RetrievedEmail } from './read_emails';

// ============================================================================
// Input Validation Schema
// ============================================================================

/**
 * Schema for validating all_emails tool input
 */
export const AllEmailsInputSchema = z.object({
  /**
   * Maximum number of emails to return per page
   */
  limit: z.number().int().positive().max(100).optional().default(20),
  
  /**
   * Pagination cursor (email ID to start from)
   */
  cursor: z.string().optional(),
  
  /**
   * Whether to extract OTP codes from emails
   */
  extractOtp: z.boolean().optional().default(false),
  
  /**
   * Filter by OTP emails only
   */
  otpOnly: z.boolean().optional().default(false),
  
  /**
   * Filter by unread emails only
   */
  unreadOnly: z.boolean().optional().default(false),
  
  /**
   * Filter by relay address ID
   */
  relayAddressId: z.number().int().positive().optional(),
  
  /**
   * Search query for filtering emails
   */
  searchQuery: z.string().max(500).optional(),
  
  /**
   * Sort order: 'newest' or 'oldest'
   */
  sortOrder: z.enum(['newest', 'oldest']).optional().default('newest'),
});

/**
 * Type for validated input
 */
export type AllEmailsInput = z.infer<typeof AllEmailsInputSchema>;

// ============================================================================
// Response Types
// ============================================================================

/**
 * Response type for the all_emails tool
 */
export interface AllEmailsResponse {
  success: boolean;
  emails: RetrievedEmail[];
  count: number;
  total: number;
  page: number;
  pageSize: number;
  hasMore: boolean;
  nextCursor: string | null;
  previousCursor: string | null;
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
export class AllEmailsRetrievalError extends Error {
  constructor(
    message: string,
    public readonly code: string = 'ALL_EMAILS_RETRIEVAL_ERROR',
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'AllEmailsRetrievalError';
  }
}

// ============================================================================
// Tool Implementation
// ============================================================================

/**
 * Retrieves all emails across all relay addresses
 * 
 * This function:
 * 1. Validates input using Zod v4
 * 2. Retrieves emails from the database with pagination
 * 3. Applies filters (OTP only, unread only, relay address, search)
 * 4. Extracts OTP codes if requested
 * 5. Performs security analysis on email content
 * 6. Logs all operations to audit trail
 * 
 * @param input - Validated input parameters
 * @param context - MCP tool execution context
 * @returns Tool result with paginated email results
 */
export async function allEmailsHandler(
  input: unknown,
  context?: Record<string, unknown>
): Promise<ToolResult<AllEmailsResponse>> {
  const requestId = uuidv4();
  const timestamp = new Date().toISOString();
  
  // Get dependencies
  const config = Configuration.getInstance();
  const db = getDatabase();
  
  try {
    // Validate input
    const validationResult = AllEmailsInputSchema.safeParse(input);
    
    if (!validationResult.success) {
      throw new Error(`Input validation failed: ${validationResult.error.message}`);
    }
    
    const {
      limit = 20,
      cursor,
      extractOtp = false,
      otpOnly = false,
      unreadOnly = false,
      relayAddressId,
      searchQuery,
      sortOrder = 'newest',
    } = validationResult.data;
    
    // Get relay addresses for reference
    const relayAddresses = db.listRelayAddresses();
    const addressMap = new Map<number, string>();
    for (const addr of relayAddresses) {
      addressMap.set(addr.id, addr.full_address);
    }
    
    // Get all email logs
    let allEmails: DatabaseEmailLog[] = [];
    
    if (relayAddressId) {
      // Get emails for specific relay address
      allEmails = db.getEmailLogsByRelayAddressId(relayAddressId, 10000);
    } else {
      // Get all emails across all relay addresses
      // We need to query all email logs
      const stmt = db.getDatabase().prepare(`
        SELECT 
          id, relay_address_id, email_id, sender, recipient, subject,
          received_at, read_at, body, body_encrypted,
          otp_code, is_otp, headers, headers_encrypted, size
        FROM email_logs
        ORDER BY received_at ${sortOrder === 'newest' ? 'DESC' : 'ASC'}
      `);
      allEmails = stmt.all() as DatabaseEmailLog[];
    }
    
    // Decrypt sensitive fields
    const processedAllEmails = allEmails.map(email => {
      if (email.body && email.body_encrypted) {
        try {
          const db = getDatabase();
          // @ts-expect-error - accessing private method for decryption
          email.body = db.decryptField(email.body, true);
        } catch {
          // Keep encrypted if decryption fails
        }
      }
      if (email.headers && email.headers_encrypted) {
        try {
          const db = getDatabase();
          // @ts-expect-error - accessing private method for decryption
          email.headers = db.decryptField(email.headers, true);
        } catch {
          // Keep encrypted if decryption fails
        }
      }
      return {
        ...email,
        is_otp: Boolean(email.is_otp),
        body_encrypted: Boolean(email.body_encrypted),
        headers_encrypted: Boolean(email.headers_encrypted),
      };
    });
    
    const total = processedAllEmails.length;
    
    // Apply filters
    let filtered = processedAllEmails;
    
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
        (e.body?.toLowerCase().includes(query) ?? false) ||
        (e.recipient?.toLowerCase().includes(query) ?? false)
      );
    }
    
    // Sort
    filtered.sort((a, b) => {
      const aTime = new Date(a.received_at).getTime();
      const bTime = new Date(b.received_at).getTime();
      return sortOrder === 'newest' ? bTime - aTime : aTime - bTime;
    });
    
    // Handle cursor pagination
    let startIndex = 0;
    if (cursor) {
      // Find the cursor position
      const cursorIndex = filtered.findIndex(e => e.email_id === cursor);
      if (cursorIndex !== -1) {
        startIndex = cursorIndex + 1;
      }
    }
    
    // Apply pagination
    const pageSize = limit;
    const paginatedEmails = filtered.slice(startIndex, startIndex + pageSize);
    const page = Math.floor(startIndex / pageSize) + 1;
    const hasMore = (startIndex + pageSize) < filtered.length;
    
    // Process emails
    const processedEmails: RetrievedEmail[] = [];
    
    for (const email of paginatedEmails) {
      const fullAddress = addressMap.get(email.relay_address_id) || '';
      const emailWithAddress = { ...email, full_address: fullAddress };
      const processed = processEmailContent(emailWithAddress, extractOtp);
      processedEmails.push(processed);
      
      // Log to audit trail
      db.insertAuditLog({
        timestamp,
        action: 'list_all_emails',
        user_id: context?.userId || null,
        target_id: String(email.id),
        target_type: 'email_log',
        details: JSON.stringify({
          requestId,
          emailId: email.email_id,
          relayAddressId: email.relay_address_id,
        }),
        ip_address: null,
        user_agent: null,
      });
    }
    
    // Determine next cursor
    const nextCursor = hasMore && paginatedEmails.length > 0 
      ? paginatedEmails[paginatedEmails.length - 1].email_id 
      : null;
    
    // Determine previous cursor
    const previousCursor = startIndex > 0 && filtered.length > 0
      ? filtered[Math.max(0, startIndex - 1)].email_id
      : null;
    
    // Build response
    const response: AllEmailsResponse = {
      success: true,
      emails: processedEmails,
      count: processedEmails.length,
      total: filtered.length,
      page,
      pageSize,
      hasMore,
      nextCursor,
      previousCursor,
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
        action: 'all_emails_error',
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
    
    const response: AllEmailsResponse = {
      success: false,
      emails: [],
      count: 0,
      total: 0,
      page: 0,
      pageSize: 0,
      hasMore: false,
      nextCursor: null,
      previousCursor: null,
      requestId,
      timestamp,
      error: `Failed to retrieve all emails: ${errorMessage}`,
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
 * MCP Tool definition for all_emails
 */
export const allEmailsTool: MCPTool = {
  name: 'all_emails',
  description: 'Retrieves all emails across all Firefox Relay addresses with comprehensive filtering, pagination, and search capabilities. Returns paginated results with OTP extraction, security analysis, and metadata.',
  inputSchema: AllEmailsInputSchema,
  handler: allEmailsHandler,
};

// ============================================================================
// Exports
// ============================================================================

export {
  AllEmailsInputSchema,
  AllEmailsResponse,
  AllEmailsRetrievalError,
};

export default allEmailsTool;
