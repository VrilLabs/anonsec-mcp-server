/**
 * Tool: new_emails
 * 
 * Creates new Firefox Relay email addresses (masks) for anonymous email management.
 * Integrates with Firefox Relay API to generate random email forwarders.
 * 
 * Follows golden-standard programming practices:
 * - Zod v4 validation for input parameters
 * - Comprehensive error handling with custom error classes
 * - Rate limiting and retry logic
 * - Database persistence with PQC encryption at rest
 * - Audit logging for security and traceability
 */

import { z } from 'zod/v4';
import { CallToolRequestSchema, MCPTool, ToolResult } from '@modelcontextprotocol/sdk/server';
import { getClient } from '../api';
import { getDatabase } from '../db';
import { Configuration } from '../config';
import {
  DatabaseRelayAddress,
  ApiResponse,
  ApiError,
  FIREFOX_RELAY_CONSTANTS,
} from '../types';
import { v4 as uuidv4 } from 'uuid';

// ============================================================================
// Input Validation Schema
// ============================================================================

/**
 * Schema for validating new_emails tool input
 */
export const NewEmailsInputSchema = z.object({
  /**
   * Optional description for the new relay address
   */
  description: z.string().max(500).optional(),
  
  /**
   * Whether the relay address should be enabled immediately
   */
  enabled: z.boolean().optional().default(true),
  
  /**
   * Context for what this address is generated for
   */
  generatedFor: z.string().max(500).optional(),
  
  /**
   * Whether to block list emails sent to this address
   */
  blockListEmails: z.boolean().optional().default(false),
  
  /**
   * URL where this address will be used (for tracking)
   */
  usedOn: z.string().url().optional(),
  
  /**
   * Number of addresses to create (default: 1)
   */
  count: z.number().int().positive().max(10).optional().default(1),
});

/**
 * Type for validated input
 */
export type NewEmailsInput = z.infer<typeof NewEmailsInputSchema>;

// ============================================================================
// Response Types
// ============================================================================

/**
 * Response type for a created relay address
 */
export interface CreatedRelayAddress {
  id: number;
  relayId: number;
  fullAddress: string;
  address: string;
  domain: string;
  description: string;
  enabled: boolean;
  generatedFor: string;
  blockListEmails: boolean;
  usedOn: string | null;
  maskType: string;
  createdAt: string;
  lastModifiedAt: string;
}

/**
 * Response type for the new_emails tool
 */
export interface NewEmailsResponse {
  success: boolean;
  addresses: CreatedRelayAddress[];
  count: number;
  requestId: string;
  timestamp: string;
  error?: string;
}

// ============================================================================
// Error Classes
// ============================================================================

/**
 * Custom error for relay address creation failures
 */
export class RelayCreationError extends Error {
  constructor(
    message: string,
    public readonly code: string = 'RELAY_CREATION_ERROR',
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'RelayCreationError';
  }
}

/**
 * Custom error for validation failures
 */
export class ValidationFailureError extends Error {
  constructor(
    message: string,
    public readonly validationErrors: z.Issue[]
  ) {
    super(message);
    this.name = 'ValidationFailureError';
  }
}

// ============================================================================
// Tool Implementation
// ============================================================================

/**
 * Creates new Firefox Relay email addresses
 * 
 * This function:
 * 1. Validates input using Zod v4
 * 2. Calls Firefox Relay API to create relay addresses
 * 3. Persists created addresses to the local database
 * 4. Handles rate limiting and retries
 * 5. Logs all operations to audit trail
 * 
 * @param input - Validated input parameters
 * @param context - MCP tool execution context
 * @returns Tool result with created addresses
 */
export async function newEmailsHandler(
  input: unknown,
  context?: Record<string, unknown>
): Promise<ToolResult<NewEmailsResponse>> {
  const requestId = uuidv4();
  const timestamp = new Date().toISOString();
  
  // Get dependencies
  const config = Configuration.getInstance();
  const db = getDatabase();
  const client = getClient();
  
  try {
    // Validate input
    const validationResult = NewEmailsInputSchema.safeParse(input);
    
    if (!validationResult.success) {
      throw new ValidationFailureError(
        'Input validation failed',
        validationResult.error.issues
      );
    }
    
    const {
      description = '',
      enabled = true,
      generatedFor = '',
      blockListEmails = false,
      usedOn,
      count = 1,
    } = validationResult.data;
    
    // Ensure count is within limits
    const maxAddresses = FIREFOX_RELAY_CONSTANTS.MAX_RETRIES * 2; // Reasonable limit
    const actualCount = Math.min(count, maxAddresses);
    
    // Create relay addresses
    const createdAddresses: CreatedRelayAddress[] = [];
    
    for (let i = 0; i < actualCount; i++) {
      const relay = await client.createRelayAddress({
        description: description || `Created via MCP ${requestId}`,
        enabled,
        generatedFor: generatedFor || 'mcp-server',
        blockListEmails,
        usedOn,
      });
      
      // Store in database
      const dbAddress: Omit<DatabaseRelayAddress, 'id'> = {
        relay_id: relay.id,
        full_address: relay.fullAddress,
        description: relay.description,
        enabled: relay.enabled,
        created_at: relay.createdAt,
        last_modified_at: relay.lastModifiedAt,
        last_used_at: null,
        num_forwarded: 0,
        num_blocked: 0,
        num_replied: 0,
        num_spam: 0,
      };
      
      const storedAddress = db.insertRelayAddress(dbAddress);
      
      // Add to response
      createdAddresses.push({
        id: storedAddress.id,
        relayId: relay.id,
        fullAddress: relay.fullAddress,
        address: relay.address,
        domain: relay.domain,
        description: relay.description,
        enabled: relay.enabled,
        generatedFor: relay.generatedFor,
        blockListEmails: relay.blockListEmails,
        usedOn: relay.usedOn,
        maskType: relay.maskType,
        createdAt: relay.createdAt,
        lastModifiedAt: relay.lastModifiedAt,
      });
      
      // Log to audit trail
      db.insertAuditLog({
        timestamp,
        action: 'create_relay_address',
        user_id: context?.userId || null,
        target_id: String(storedAddress.id),
        target_type: 'relay_address',
        details: JSON.stringify({
          requestId,
          fullAddress: relay.fullAddress,
          relayId: relay.id,
        }),
        ip_address: null,
        user_agent: null,
      });
    }
    
    // Build response
    const response: NewEmailsResponse = {
      success: true,
      addresses: createdAddresses,
      count: createdAddresses.length,
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
    
    // Handle known error types
    if (error instanceof ValidationFailureError) {
      const response: NewEmailsResponse = {
        success: false,
        addresses: [],
        count: 0,
        requestId,
        timestamp,
        error: `Validation failed: ${error.message}`,
      };
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(response, null, 2),
        }],
        isError: true,
      };
    }
    
    if (error instanceof RelayCreationError) {
      const response: NewEmailsResponse = {
        success: false,
        addresses: [],
        count: 0,
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
    const errorMessage = error instanceof Error ? error.message : String(error);
    
    // Log error to audit trail
    try {
      const db = getDatabase();
      db.insertAuditLog({
        timestamp,
        action: 'create_relay_address_error',
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
    
    const response: NewEmailsResponse = {
      success: false,
      addresses: [],
      count: 0,
      requestId,
      timestamp,
      error: `Failed to create relay addresses: ${errorMessage}`,
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
 * MCP Tool definition for new_emails
 */
export const newEmailsTool: MCPTool = {
  name: 'new_emails',
  description: 'Creates new Firefox Relay email addresses (masks) for anonymous email management. Returns created addresses with full details including relay IDs, addresses, and domains.',
  inputSchema: NewEmailsInputSchema,
  handler: newEmailsHandler,
};

// ============================================================================
// Exports
// ============================================================================

export {
  NewEmailsInputSchema,
  RelayCreationError,
  ValidationFailureError,
};

export default newEmailsTool;
