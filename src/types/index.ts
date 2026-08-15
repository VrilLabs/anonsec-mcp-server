/**
 * Type definitions for Firefox Relay MCP Server
 *
 * This module contains all type definitions used throughout the application,
 * following golden-standard programming practices for maximal type safety
 * and programmatic excellence.
 */

import type { z } from 'zod/v4';

// ============================================================================
// Firefox Relay API Types
// ============================================================================

/**
 * Firefox Relay API response for a relay address (email mask)
 */
export interface FirefoxRelayAddress {
  id: number;
  address: string; // local part, e.g. "abc123"
  domain: string; // e.g. "mozmail.com"
  full_address: string; // e.g. "abc123@mozmail.com"
  enabled: boolean;
  description: string;
  generated_for: string;
  block_list_emails: boolean;
  used_on: string | null;
  mask_type: string; // "random" or "domain"
  created_at: string; // ISO 8601
  last_modified_at: string; // ISO 8601
  last_used_at: string | null;
  num_forwarded: number;
  num_blocked: number;
  num_level_one_trackers_blocked: number;
  num_replied: number;
  num_spam: number;
}

/**
 * Request payload for creating a new Firefox Relay address
 */
export interface CreateRelayAddressRequest {
  description?: string;
  enabled?: boolean;
  generated_for?: string;
  block_list_emails?: boolean;
  used_on?: string;
}

/**
 * Response from Firefox Relay API for creating a new address
 */
export interface CreateRelayAddressResponse {
  id: number;
  address: string;
  domain: string;
  full_address: string;
  enabled: boolean;
  description: string;
  generated_for: string;
  block_list_emails: boolean;
  used_on: string | null;
  mask_type: string;
  created_at: string;
  last_modified_at: string;
  last_used_at: string | null;
}

/**
 * Update request for a Firefox Relay address
 */
export interface UpdateRelayAddressRequest {
  description?: string;
  enabled?: boolean;
  block_list_emails?: boolean;
  used_on?: string;
}

// ============================================================================
// Database Types
// ============================================================================

/**
 * Database schema for storing Firefox Relay email addresses
 */
export interface DatabaseRelayAddress {
  id: number;
  relay_id: number; // Firefox Relay's ID
  full_address: string;
  description: string;
  enabled: boolean;
  created_at: string;
  last_modified_at: string;
  last_used_at: string | null;
  num_forwarded: number;
  num_blocked: number;
  num_replied: number;
  num_spam: number;
}

/**
 * Database schema for email logs
 */
export interface DatabaseEmailLog {
  id: number;
  relay_address_id: number; // Foreign key to relay addresses
  email_id: string; // Unique email identifier
  sender: string;
  recipient: string;
  subject: string;
  received_at: string;
  read_at: string | null;
  body: string | null; // Encrypted at rest
  body_encrypted: boolean; // Whether `body` is currently ciphertext
  otp_code: string | null; // Extracted OTP code
  is_otp: boolean;
  headers: string | null; // Encrypted at rest
  headers_encrypted: boolean; // Whether `headers` is currently ciphertext
  size: number;
}

/**
 * Database schema for API key management
 */
export interface DatabaseApiKey {
  id: number;
  key_hash: string; // PQC hashed API key
  description: string;
  created_at: string;
  last_used_at: string | null;
  is_active: boolean;
  permissions: string[]; // Array of permission strings
}

/**
 * Database schema for audit logs
 */
export interface DatabaseAuditLog {
  id: number;
  timestamp: string;
  action: string; // e.g., "create_alias", "read_email", "delete_alias"
  user_id: string | null; // User identifier if applicable
  target_id: string | null; // ID of the target resource
  target_type: string | null; // Type of the target resource
  details: string | null; // Additional details (encrypted)
  details_encrypted: boolean; // Whether `details` is currently ciphertext
  ip_address: string | null;
  user_agent: string | null;
}

// ============================================================================
// MCP Server Types
// ============================================================================

/**
 * Configuration for the MCP Server
 */
export interface McpServerConfig {
  name: string;
  version: string;
  apiKey: string; // Firefox Relay API key
  databasePath: string;
  encryptionKey: string; // Key for PQC encryption
  port: number;
  host: string;
  enableLogging: boolean;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

/**
 * Context for MCP tool execution
 */
export interface ToolExecutionContext {
  toolName: string;
  requestId: string;
  timestamp: string;
  userId: string | null;
  sessionId: string | null;
}

/**
 * Result returned by an MCP tool handler
 */
export interface ToolResult {
  content: Array<{ type: 'text'; text: string }>;
  isError: boolean;
}

/**
 * Internal definition of an MCP tool, used to register tools with the server
 */
export interface MCPTool {
  name: string;
  description: string;
  inputSchema: z.ZodTypeAny;
  handler: (input: unknown, context?: Record<string, unknown>) => Promise<ToolResult>;
}

// ============================================================================
// Email Processing Types
// ============================================================================

/**
 * Extracted OTP information from an email
 */
export interface OtpExtractionResult {
  code: string | null;
  provider: string | null; // e.g., "Google", "GitHub", "AWS"
  type: string | null; // e.g., "numeric", "alphanumeric"
  expiresAt: string | null; // ISO 8601 if expiration is mentioned
  confidence: number; // 0-1 confidence score
}

/**
 * Email content for processing
 */
export interface EmailContent {
  id: string;
  from: string;
  to: string[];
  subject: string;
  body: string;
  html: string | null;
  headers: Record<string, string>;
  receivedAt: string;
  attachments: EmailAttachment[];
}

/**
 * Email attachment information
 */
export interface EmailAttachment {
  id: string;
  filename: string;
  contentType: string;
  size: number;
  // Note: Attachments are forbidden for security in this implementation
}

/**
 * Result of processing an email
 */
export interface ProcessedEmail {
  email: EmailContent;
  otpInfo: OtpExtractionResult | null;
  isOtpEmail: boolean;
  extractedLinks: string[];
  securityFlags: SecurityFlag[];
}

/**
 * Security flags for email content
 */
export type SecurityFlag =
  | 'phishing_suspected'
  | 'malware_detected'
  | 'spam_patterns'
  | 'unencrypted_sensitive_data'
  | 'suspicious_links'
  | 'mismatched_sender'
  | 'otp_security_warning'
  | 'otp_in_subject';

// ============================================================================
// Response Types
// ============================================================================

/**
 * Standard response wrapper for API operations
 */
export interface ApiResponse<T> {
  success: boolean;
  data: T | null;
  error: ApiError | null;
  timestamp: string;
  requestId: string;
}

/**
 * Error type for API operations
 */
export interface ApiError {
  code: string;
  message: string;
  details: Record<string, unknown> | null;
  timestamp: string;
}

/**
 * Paginated response wrapper
 */
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  hasMore: boolean;
  nextCursor: string | null;
  previousCursor: string | null;
}

// ============================================================================
// Validation Schemas
// ============================================================================

/**
 * Schema for validating email addresses
 */
export interface EmailValidationResult {
  isValid: boolean;
  email: string;
  domain: string;
  localPart: string;
  errors: string[];
}

/**
 * Schema for rate limiting
 */
export interface RateLimitStatus {
  requestsMade: number;
  requestsAllowed: number;
  resetAt: string;
  isLimited: boolean;
}

// ============================================================================
// Utility Types
// ============================================================================

/**
 * Result of a database operation
 */
export type DatabaseResult<T> = Promise<{
  success: boolean;
  data?: T;
  error?: Error;
}>;

/**
 * Callback for logging operations
 */
export type Logger = {
  debug: (message: string, context?: Record<string, unknown>) => void;
  info: (message: string, context?: Record<string, unknown>) => void;
  warn: (message: string, context?: Record<string, unknown>) => void;
  error: (message: string, context?: Record<string, unknown>) => void;
};

/**
 * Empty object type
 */
export type EmptyObject = Record<string, never>;

/**
 * Make all properties optional
 */
export type PartialBy<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

/**
 * Remove undefined from type
 */
export type WithoutUndefined<T> = {
  [P in keyof T]: Exclude<T[P], undefined>;
};

// ============================================================================
// Constants
// ============================================================================

/**
 * Default configuration values
 */
export const DEFAULT_CONFIG: Partial<McpServerConfig> = {
  name: 'anonsec-mcp-server',
  version: '1.0.0',
  port: 3000,
  host: 'localhost',
  enableLogging: true,
  logLevel: 'info',
  databasePath: 'data/anonsec.db',
};

/**
 * Firefox Relay API constants
 */
export const FIREFOX_RELAY_CONSTANTS = {
  BASE_URL: 'https://relay.firefox.com/api/v1/',
  AUTH_HEADER: 'Authorization',
  AUTH_PREFIX: 'Token',
  USER_AGENT: 'anonsec-mcp-server/1.0.0',
  TIMEOUT_MS: 30000,
  RATE_LIMIT_DELAY: 1000, // 1 second between requests
  MAX_RETRIES: 3,
};

/**
 * Database constants
 */
export const DATABASE_CONSTANTS = {
  PRAGMA_JOURNAL_MODE: 'WAL',
  PRAGMA_SYNCHRONOUS: 'NORMAL',
  PRAGMA_FOREIGN_KEYS: 'ON',
  ENCRYPTION_ALGORITHM: 'AES-256-GCM',
  KEY_DERIVATION_ITERATIONS: 100000,
};

/**
 * Security constants
 */
export const SECURITY_CONSTANTS = {
  MAX_EMAIL_BODY_SIZE: 10 * 1024 * 1024, // 10MB
  MAX_ATTACHMENT_SIZE: 0, // Attachments forbidden for security
  MAX_SUBJECT_LENGTH: 1000,
  MAX_SENDER_LENGTH: 500,
  MAX_RECIPIENTS: 10,
  OTP_PATTERN: /\b[A-Z0-9]{4,10}\b|\b\d{4,8}\b/g,
  SUSPICIOUS_DOMAINS: [
    'example.com',
    'test.com',
    'localhost',
    '127.0.0.1',
  ],
};
