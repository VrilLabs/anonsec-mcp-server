/**
 * Tool: latest_email
 * 
 * Retrieves the latest email for a specific Firefox Relay address.
 * This is a specialized tool for quickly accessing the most recent email
 * without needing to fetch all emails.
 * 
 * Follows golden-standard programming practices:
 * - Zod v4 validation for input parameters
 * - Comprehensive error handling with custom error classes
 * - Database persistence with PQC encryption at rest
 * - OTP extraction and security analysis
 * - Audit logging for security and traceability
 */

import { z } from 'zod/v4';
import { getClient } from '../api';
import { getDatabase } from '../db';
import {
  MCPTool,
  ToolResult,
} from '../types';
import { v4 as uuidv4 } from 'uuid';
import { processEmailContent, RetrievedEmail } from './read_emails';

// ============================================================================
// Input Validation Schema
// ============================================================================

/**
 * Schema for validating latest_email tool input
 */
export const LatestEmailInputSchema = z.object({
  /**
   * Relay address ID to get the latest email from
   */
  relayAddressId: z.number().int().positive().optional(),
  
  /**
   * Full relay address to get the latest email from (alternative to ID)
   */
  relayAddress: z.string().email().optional(),
  
  /**
   * Whether to extract OTP codes from the email
   */
  extractOtp: z.boolean().optional().default(true),
  
  /**
   * Whether to include security analysis
   */
  includeSecurityAnalysis: z.boolean().optional().default(true),
});

/**
 * Type for validated input
 */
export type LatestEmailInput = z.infer<typeof LatestEmailInputSchema>;

// ============================================================================
// Response Types
// ============================================================================

/**
 * Response type for the latest_email tool
 */
export interface LatestEmailResponse {
  success: boolean;
  email: RetrievedEmail | null;
  requestId: string;
  timestamp: string;
  error?: string;
  relayAddressId?: number;
  fullRelayAddress?: string;
}

// ============================================================================
// Error Classes
// ============================================================================

/**
 * Custom error for no emails found
 */
export class NoEmailsFoundError extends Error {
  constructor(
    message: string = 'No emails found for the specified relay address',
    public readonly relayAddressId?: number,
    public readonly fullAddress?: string
  ) {
    super(message);
    this.name = 'NoEmailsFoundError';
  }
}

/**
 * Custom error for email retrieval failures
 */
export class LatestEmailRetrievalError extends Error {
  constructor(
    message: string,
    public readonly code: string = 'LATEST_EMAIL_RETRIEVAL_ERROR',
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'LatestEmailRetrievalError';
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

// ============================================================================
// Tool Implementation
// ============================================================================

/**
 * Retrieves the latest email for a specific Firefox Relay address
 * 
 * This function:
 * 1. Validates input using Zod v4
 * 2. Resolves relay address ID from either ID or full address
 * 3. Retrieves the latest email from the database
 * 4. Extracts OTP codes if requested
 * 5. Performs security analysis if requested
 * 6. Logs all operations to audit trail
 * 
 * @param input - Validated input parameters
 * @param context - MCP tool execution context
 * @returns Tool result with the latest email
 */
// eslint-disable-next-line @typescript-eslint/require-await -- async to satisfy the MCPTool handler contract; this tool has no async work
export async function latestEmailHandler(
  input: unknown,
  context?: Record<string, unknown>
): Promise<ToolResult> {
  const requestId = uuidv4();
  const timestamp = new Date().toISOString();

  // Get dependencies
  const db = getDatabase();
  const client = getClient();
  
  try {
    // Validate input
    const validationResult = LatestEmailInputSchema.safeParse(input);
    
    if (!validationResult.success) {
      throw new Error(`Input validation failed: ${validationResult.error.message}`);
    }
    
    const {
      relayAddressId,
      relayAddress,
      extractOtp = true,
      includeSecurityAnalysis = true,
    } = validationResult.data;
    
    // Validate that we have either relayAddressId or relayAddress
    if (!relayAddressId && !relayAddress) {
      throw new Error('Either relayAddressId or relayAddress must be provided');
    }
    
    // Resolve relay address ID and full address
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
    
    // Get the latest email for the relay address
    const latestEmail = db.getLatestEmailLogByRelayAddressId(resolvedRelayAddressId);
    
    if (!latestEmail) {
      throw new NoEmailsFoundError(
        `No emails found for relay address ${resolvedFullAddress}`,
        resolvedRelayAddressId,
        resolvedFullAddress
      );
    }
    
    // Add full_address to email object for processing
    const emailWithAddress = { ...latestEmail, full_address: resolvedFullAddress };
    
    // Process email content
    const processedEmail = processEmailContent(emailWithAddress, extractOtp && includeSecurityAnalysis);
    
    // Update email with address information
    processedEmail.relayAddressId = resolvedRelayAddressId;
    processedEmail.fullRelayAddress = resolvedFullAddress;
    
    // Log to audit trail
    db.insertAuditLog({
      timestamp,
      action: 'get_latest_email',
      user_id: typeof context?.userId === 'string' ? context.userId : null,
      target_id: String(latestEmail.id),
      target_type: 'email_log',
      details: JSON.stringify({
        requestId,
        emailId: latestEmail.email_id,
        relayAddressId: resolvedRelayAddressId,
        fullRelayAddress: resolvedFullAddress,
        sender: latestEmail.sender,
        subject: latestEmail.subject,
        isOtp: latestEmail.is_otp,
        hasOtpCode: Boolean(latestEmail.otp_code),
      }),
      ip_address: null,
      user_agent: null,
    });
    
    // Build response
    const response: LatestEmailResponse = {
      success: true,
      email: processedEmail,
      requestId,
      timestamp,
      relayAddressId: resolvedRelayAddressId,
      fullRelayAddress: resolvedFullAddress,
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
        action: 'latest_email_error',
        user_id: typeof context?.userId === 'string' ? context.userId : null,
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
    if (error instanceof NoEmailsFoundError) {
      const response: LatestEmailResponse = {
        success: false,
        email: null,
        requestId,
        timestamp,
        error: error.message,
        relayAddressId: error.relayAddressId,
        fullRelayAddress: error.fullAddress,
      };
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(response, null, 2),
        }],
        isError: true,
      };
    }
    
    if (error instanceof InvalidRelayAddressError) {
      const response: LatestEmailResponse = {
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
    
    if (error instanceof LatestEmailRetrievalError) {
      const response: LatestEmailResponse = {
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
    const response: LatestEmailResponse = {
      success: false,
      email: null,
      requestId,
      timestamp,
      error: `Failed to get latest email: ${errorMessage}`,
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
 * MCP Tool definition for latest_email
 */
export const latestEmailTool: MCPTool = {
  name: 'latest_email',
  description: 'Retrieves the latest email for a specific Firefox Relay address. Returns the most recent email with full details including OTP extraction, security analysis, and metadata. Requires either relayAddressId or relayAddress parameter.',
  inputSchema: LatestEmailInputSchema,
  handler: latestEmailHandler,
};

// ============================================================================
// Exports
// ============================================================================

export default latestEmailTool;
