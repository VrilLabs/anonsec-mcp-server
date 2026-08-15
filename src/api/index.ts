/**
 * Firefox Relay API Client Module
 * 
 * Provides a comprehensive TypeScript client for the Firefox Relay API,
 * with proper rate limiting, retry logic, error handling, and caching.
 * 
 * Follows golden-standard programming practices for maximal reliability
 * and security.
 * 
 * API Documentation References:
 * - https://docs.rs/ffrelay-api/latest/ffrelay_api/
 * - https://github.com/leo-proger/firefox-relay-api
 * - https://relay.firefox.com/api/v1/runtime_data
 */

import { z } from 'zod/v4';
import { FIREFOX_RELAY_CONSTANTS } from '../types';
import { Configuration } from '../config';

// ============================================================================
// Error Classes
// ============================================================================

/**
 * Base error for Firefox Relay API operations
 */
export class FirefoxRelayError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
    public readonly responseData?: unknown,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'FirefoxRelayError';
  }
}

/**
 * Authentication error
 */
export class AuthError extends FirefoxRelayError {
  constructor(message: string = 'Authentication failed') {
    super(message, 401);
  }
}

/**
 * Rate limit error
 */
export class RateLimitError extends FirefoxRelayError {
  constructor(
    message: string = 'Rate limit exceeded',
    public readonly retryAfter?: number
  ) {
    super(message, 429);
  }
}

/**
 * Validation error
 */
export class ValidationError extends FirefoxRelayError {
  constructor(message: string, public readonly fieldErrors?: Record<string, string[]>) {
    super(message, 400, fieldErrors);
  }
}

/**
 * Not found error
 */
export class ResourceNotFoundError extends FirefoxRelayError {
  constructor(resourceType: string, identifier: string | number) {
    super(`${resourceType} not found: ${identifier}`, 404);
  }
}

/**
 * Server error
 */
export class ServerError extends FirefoxRelayError {
  constructor(message: string = 'Internal server error') {
    super(message, 500);
  }
}

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Firefox Relay API response envelope
 */
interface ApiResponse<T> {
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}

// ============================================================================
// Request/Response Types
// ============================================================================

/**
 * Request options for API calls
 */
export interface RequestOptions {
  /**
   * Custom timeout in milliseconds
   */
  timeout?: number;
  
  /**
   * Number of retries on failure
   */
  retries?: number;
  
  /**
   * Custom headers
   */
  headers?: Record<string, string>;
  
  /**
   * Whether to skip rate limiting
   */
  skipRateLimit?: boolean;
}

/**
 * Rate limit status
 */
export interface RateLimitStatus {
  remaining: number;
  resetAt: Date;
  limited: boolean;
}

// ============================================================================
// API Client Class
// ============================================================================

/**
 * Firefox Relay API Client
 * 
 * Provides a high-level interface for interacting with the Firefox Relay API
 * with automatic authentication, rate limiting, and error handling.
 */
export class FirefoxRelayClient {
  private apiKey: string;
  private baseUrl: string;
  private config: Configuration;
  private rateLimitState: {
    lastRequestTime: number;
    requestsInWindow: number;
    windowStart: number;
  };

  /**
   * Create a new Firefox Relay API client
   * 
   * @param apiKey - Firefox Relay API key
   * @param config - Configuration instance
   * @param baseUrl - Custom base URL for testing
   */
  constructor(apiKey: string, config?: Configuration, baseUrl?: string) {
    if (!apiKey || typeof apiKey !== 'string') {
      throw new AuthError('API key is required');
    }

    this.apiKey = apiKey;
    this.config = config || Configuration.getInstance();
    this.baseUrl = baseUrl || FIREFOX_RELAY_CONSTANTS.BASE_URL;
    
    // Initialize rate limit state
    this.rateLimitState = {
      lastRequestTime: 0,
      requestsInWindow: 0,
      windowStart: Date.now(),
    };
  }

  /**
   * Get the current rate limit status
   */
  public getRateLimitStatus(): RateLimitStatus {
    const now = Date.now();
    let windowAge = now - this.rateLimitState.windowStart;
    
    // Reset window if older than 60 seconds
    if (windowAge > 60000) {
      this.rateLimitState = {
        lastRequestTime: now,
        requestsInWindow: 0,
        windowStart: now,
      };
      windowAge = 0;
    }

    // Estimate requests remaining (Firefox Relay has a rate limit of ~60 req/min)
    const requestsInWindow = this.rateLimitState.requestsInWindow;
    const maxRequests = 55; // Conservative estimate
    const remaining = Math.max(0, maxRequests - requestsInWindow);
    const resetAt = new Date(this.rateLimitState.windowStart + 60000);

    return {
      remaining,
      resetAt,
      limited: remaining === 0,
    };
  }

  /**
   * Check and enforce rate limiting
   */
  private async enforceRateLimit(skip?: boolean): Promise<void> {
    if (skip) {
      return;
    }

    const rateLimit = this.getRateLimitStatus();
    
    if (rateLimit.limited) {
      const waitTime = rateLimit.resetAt.getTime() - Date.now();
      if (waitTime > 0) {
        await new Promise(resolve => setTimeout(resolve, waitTime));
        // Reset state after waiting
        this.rateLimitState = {
          lastRequestTime: Date.now(),
          requestsInWindow: 0,
          windowStart: Date.now(),
        };
      }
    }

    // Check inter-request delay
    const minDelay = FIREFOX_RELAY_CONSTANTS.RATE_LIMIT_DELAY;
    const timeSinceLastRequest = Date.now() - this.rateLimitState.lastRequestTime;
    
    if (timeSinceLastRequest < minDelay) {
      await new Promise(resolve => setTimeout(resolve, minDelay - timeSinceLastRequest));
    }

    // Update rate limit state
    const now = Date.now();
    if (now - this.rateLimitState.windowStart > 60000) {
      this.rateLimitState = {
        lastRequestTime: now,
        requestsInWindow: 1,
        windowStart: now,
      };
    } else {
      this.rateLimitState.requestsInWindow++;
      this.rateLimitState.lastRequestTime = now;
    }
  }

  /**
   * Make an HTTP request to the Firefox Relay API
   */
  private async request<T>(
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    path: string,
    data?: unknown,
    options: RequestOptions = {}
  ): Promise<T> {
    const {
      timeout = FIREFOX_RELAY_CONSTANTS.TIMEOUT_MS,
      retries = FIREFOX_RELAY_CONSTANTS.MAX_RETRIES,
      headers = {},
      skipRateLimit = false,
    } = options;

    const url = new URL(path, this.baseUrl);
    
    // Enforce rate limiting
    await this.enforceRateLimit(skipRateLimit);

    // Build request headers
    const requestHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': FIREFOX_RELAY_CONSTANTS.USER_AGENT,
      'Authorization': `${FIREFOX_RELAY_CONSTANTS.AUTH_PREFIX} ${this.apiKey}`,
      ...headers,
    };

    // Build request options
    const requestOptions: RequestInit = {
      method,
      headers: requestHeaders,
      body: data ? JSON.stringify(data) : undefined,
    };

    // Add timeout support via AbortController
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    requestOptions.signal = controller.signal;

    let lastError: Error | undefined;

    try {
      for (let attempt = 0; attempt <= retries; attempt++) {
        try {
          const response = await fetch(url.toString(), requestOptions);
          clearTimeout(timeoutId);

          // Check for rate limiting
          if (response.status === 429) {
            const retryAfter = response.headers.get('Retry-After');
            const waitTime = retryAfter ? parseInt(retryAfter, 10) * 1000 : 5000;
            
            if (attempt < retries) {
              await new Promise(resolve => setTimeout(resolve, waitTime));
              continue;
            }

            throw new RateLimitError(
              `Rate limit exceeded. Retry after ${waitTime / 1000} seconds.`,
              waitTime / 1000
            );
          }

          // Check for authentication errors
          if (response.status === 401) {
            throw new AuthError('Invalid or expired API key');
          }

          // Check for validation errors
          if (response.status === 400) {
            const errorData = await response.json().catch(() => ({})) as {
              detail?: string;
              errors?: Record<string, string[]>;
            };
            
            throw new ValidationError(
              errorData.detail || 'Validation error',
              errorData.errors
            );
          }

          // Check for not found errors
          if (response.status === 404) {
            const errorData = await response.json().catch(() => ({})) as {
              detail?: string;
            };
            
            throw new ResourceNotFoundError(
              'Resource',
              errorData.detail || 'Not found'
            );
          }

          // Check for server errors
          if (response.status >= 500) {
            const errorData = await response.json().catch(() => ({})) as {
              detail?: string;
            };
            
            throw new ServerError(
              errorData.detail || `Server error: ${response.status}`
            );
          }

          // Parse response
          const responseData = await response.json() as ApiResponse<T>;

          // Check for API-level errors
          if (responseData.error) {
            const error = responseData.error;
            throw new FirefoxRelayError(
              error.message || 'API error',
              undefined,
              error
            );
          }

          // Return data
          if (!responseData.data) {
            throw new FirefoxRelayError('Empty response');
          }

          return responseData.data;

        } catch (error) {
          lastError = error as Error;
          
          // Don't retry on certain errors
          if (error instanceof AuthError || error instanceof ValidationError) {
            break;
          }

          // Wait before retry
          if (attempt < retries) {
            await new Promise(resolve => setTimeout(
              resolve,
              Math.pow(2, attempt) * 1000
            ));
          }
        }
      }

      throw lastError || new FirefoxRelayError('Request failed');

    } finally {
      clearTimeout(timeoutId);
    }
  }

  // ============================================================================
  // Relay Address Endpoints
  // ============================================================================

  /**
   * Create a new random email relay address
   * 
   * @param options - Creation options
   * @returns The created relay address
   */
  public async createRelayAddress(options: {
    description?: string;
    enabled?: boolean;
    generatedFor?: string;
    blockListEmails?: boolean;
    usedOn?: string;
  } = {}): Promise<{
    id: number;
    address: string;
    domain: string;
    fullAddress: string;
    enabled: boolean;
    description: string;
    generatedFor: string;
    blockListEmails: boolean;
    usedOn: string | null;
    maskType: string;
    createdAt: string;
    lastModifiedAt: string;
  }> {
    const { description = '', enabled = true, generatedFor = '', blockListEmails = false, usedOn } = options;

    const requestData = {
      description,
      enabled,
      generated_for: generatedFor,
      block_list_emails: blockListEmails,
      ...(usedOn && { used_on: usedOn }),
    };

    const response = await this.request<{
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
    }>('POST', 'relayaddresses/', requestData);

    return {
      id: response.id,
      address: response.address,
      domain: response.domain,
      fullAddress: response.full_address,
      enabled: response.enabled,
      description: response.description,
      generatedFor: response.generated_for,
      blockListEmails: response.block_list_emails,
      usedOn: response.used_on,
      maskType: response.mask_type,
      createdAt: response.created_at,
      lastModifiedAt: response.last_modified_at,
    };
  }

  /**
   * List all relay addresses
   * 
   * @returns Array of relay addresses
   */
  public async listRelayAddresses(): Promise<Array<{
    id: number;
    address: string;
    domain: string;
    fullAddress: string;
    enabled: boolean;
    description: string;
    generatedFor: string;
    blockListEmails: boolean;
    usedOn: string | null;
    maskType: string;
    createdAt: string;
    lastModifiedAt: string;
    lastUsedAt: string | null;
    numForwarded: number;
    numBlocked: number;
    numReplied: number;
    numSpam: number;
  }>> {
    const response = await this.request<Array<{
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
      num_forwarded: number;
      num_blocked: number;
      num_replied: number;
      num_spam: number;
    }>>('GET', 'relayaddresses/');

    return response.map(item => ({
      id: item.id,
      address: item.address,
      domain: item.domain,
      fullAddress: item.full_address,
      enabled: item.enabled,
      description: item.description,
      generatedFor: item.generated_for,
      blockListEmails: item.block_list_emails,
      usedOn: item.used_on,
      maskType: item.mask_type,
      createdAt: item.created_at,
      lastModifiedAt: item.last_modified_at,
      lastUsedAt: item.last_used_at,
      numForwarded: item.num_forwarded,
      numBlocked: item.num_blocked,
      numReplied: item.num_replied,
      numSpam: item.num_spam,
    }));
  }

  /**
   * Get a specific relay address by ID
   * 
   * @param id - Relay address ID
   * @returns The relay address
   */
  public async getRelayAddress(id: number): Promise<{
    id: number;
    address: string;
    domain: string;
    fullAddress: string;
    enabled: boolean;
    description: string;
    generatedFor: string;
    blockListEmails: boolean;
    usedOn: string | null;
    maskType: string;
    createdAt: string;
    lastModifiedAt: string;
    lastUsedAt: string | null;
    numForwarded: number;
    numBlocked: number;
    numReplied: number;
    numSpam: number;
  }> {
    const response = await this.request<{
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
      num_forwarded: number;
      num_blocked: number;
      num_replied: number;
      num_spam: number;
    }>('GET', `relayaddresses/${id}/`);

    return {
      id: response.id,
      address: response.address,
      domain: response.domain,
      fullAddress: response.full_address,
      enabled: response.enabled,
      description: response.description,
      generatedFor: response.generated_for,
      blockListEmails: response.block_list_emails,
      usedOn: response.used_on,
      maskType: response.mask_type,
      createdAt: response.created_at,
      lastModifiedAt: response.last_modified_at,
      lastUsedAt: response.last_used_at,
      numForwarded: response.num_forwarded,
      numBlocked: response.num_blocked,
      numReplied: response.num_replied,
      numSpam: response.num_spam,
    };
  }

  /**
   * Update a relay address
   * 
   * @param id - Relay address ID
   * @param updates - Fields to update
   * @returns The updated relay address
   */
  public async updateRelayAddress(
    id: number,
    updates: {
      description?: string;
      enabled?: boolean;
      blockListEmails?: boolean;
      usedOn?: string;
    }
  ): Promise<{
    id: number;
    address: string;
    domain: string;
    fullAddress: string;
    enabled: boolean;
    description: string;
    generatedFor: string;
    blockListEmails: boolean;
    usedOn: string | null;
    maskType: string;
    createdAt: string;
    lastModifiedAt: string;
    lastUsedAt: string | null;
    numForwarded: number;
    numBlocked: number;
    numReplied: number;
    numSpam: number;
  }> {
    const requestData: Record<string, unknown> = {};
    
    if (updates.description !== undefined) requestData.description = updates.description;
    if (updates.enabled !== undefined) requestData.enabled = updates.enabled;
    if (updates.blockListEmails !== undefined) requestData.block_list_emails = updates.blockListEmails;
    if (updates.usedOn !== undefined) requestData.used_on = updates.usedOn;

    const response = await this.request<{
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
      num_forwarded: number;
      num_blocked: number;
      num_replied: number;
      num_spam: number;
    }>('PATCH', `relayaddresses/${id}/`, requestData);

    return {
      id: response.id,
      address: response.address,
      domain: response.domain,
      fullAddress: response.full_address,
      enabled: response.enabled,
      description: response.description,
      generatedFor: response.generated_for,
      blockListEmails: response.block_list_emails,
      usedOn: response.used_on,
      maskType: response.mask_type,
      createdAt: response.created_at,
      lastModifiedAt: response.last_modified_at,
      lastUsedAt: response.last_used_at,
      numForwarded: response.num_forwarded,
      numBlocked: response.num_blocked,
      numReplied: response.num_replied,
      numSpam: response.num_spam,
    };
  }

  /**
   * Delete a relay address
   * 
   * @param id - Relay address ID
   */
  public async deleteRelayAddress(id: number): Promise<void> {
    await this.request('DELETE', `relayaddresses/${id}/`);
  }

  // ============================================================================
  // Email Sending (Hypothetical - Firefox Relay doesn't currently support sending via API)
  // ============================================================================

  /**
   * Validate that an email address belongs to Firefox Relay
   * 
   * @param email - Email address to validate
   * @returns True if the email is a Firefox Relay address
   */
  public validateRelayAddress(email: string): boolean {
    // Firefox Relay uses the mozmail.com domain
    const relayDomains = ['mozmail.com', 'relay.firefox.com'];
    
    try {
      const [, domain] = email.split('@');
      return relayDomains.includes(domain.toLowerCase());
    } catch {
      return false;
    }
  }

  // ============================================================================
  // Profile Endpoints (Premium features)
  // ============================================================================

  /**
   * Get user profile information
   * 
   * Note: This endpoint may require a premium account
   */
  public async getProfile(): Promise<{
    id: number;
    email: string;
    createdAt: string;
    subscription?: {
      type: string;
      status: string;
      startedAt: string;
      expiresAt: string;
    };
    usage?: {
      numRelayAddresses: number;
      numEmailsForwarded: number;
      numEmailsBlocked: number;
    };
  }> {
    const response = await this.request<{
      id: number;
      email: string;
      created_at: string;
      subscription?: {
        type: string;
        status: string;
        started_at: string;
        expires_at: string;
      };
      usage?: {
        num_relay_addresses: number;
        num_emails_forwarded: number;
        num_emails_blocked: number;
      };
    }>('GET', 'accounts/profile/');

    return {
      id: response.id,
      email: response.email,
      createdAt: response.created_at,
      subscription: response.subscription ? {
        type: response.subscription.type,
        status: response.subscription.status,
        startedAt: response.subscription.started_at,
        expiresAt: response.subscription.expires_at,
      } : undefined,
      usage: response.usage ? {
        numRelayAddresses: response.usage.num_relay_addresses,
        numEmailsForwarded: response.usage.num_emails_forwarded,
        numEmailsBlocked: response.usage.num_emails_blocked,
      } : undefined,
    };
  }

  // ============================================================================
  // Runtime Data Endpoint
  // ============================================================================

  /**
   * Get runtime data (public endpoint, no authentication required)
   * 
   * This endpoint provides general information about Firefox Relay
   */
  public async getRuntimeData(): Promise<{
    version: string;
    featureFlags: Record<string, boolean>;
    relayCounts: {
      totalRelays: number;
      activeRelays: number;
    };
  }> {
    // This endpoint doesn't require authentication
    const client = new FirefoxRelayClient('', this.config, this.baseUrl);
    return client.request('GET', 'runtime_data/');
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  /**
   * Get API usage statistics
   */
  public getApiStats(): {
    totalRequests: number;
    rateLimit: RateLimitStatus;
    lastRequestTime: Date | null;
  } {
    return {
      totalRequests: this.rateLimitState.requestsInWindow,
      rateLimit: this.getRateLimitStatus(),
      lastRequestTime: this.rateLimitState.lastRequestTime 
        ? new Date(this.rateLimitState.lastRequestTime)
        : null,
    };
  }

  /**
   * Reset API rate limit state
   */
  public resetRateLimitState(): void {
    this.rateLimitState = {
      lastRequestTime: 0,
      requestsInWindow: 0,
      windowStart: Date.now(),
    };
  }

  /**
   * Get the API key (redacted)
   */
  public getApiKey(): string {
    return '[REDACTED]';
  }

  /**
   * Check if the API key is valid by making a test request
   */
  public async validateApiKey(): Promise<boolean> {
    try {
      await this.listRelayAddresses();
      return true;
    } catch (error) {
      if (error instanceof AuthError) {
        return false;
      }
      // For other errors, we can't determine if it's an auth issue
      throw error;
    }
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

/**
 * Singleton client instance
 */
let clientInstance: FirefoxRelayClient | null = null;

/**
 * Get the singleton Firefox Relay client instance
 */
export function getClient(config?: Configuration): FirefoxRelayClient {
  if (!clientInstance || config) {
    const actualConfig = config || Configuration.getInstance();
    const apiKey = actualConfig.get('apiKey');
    
    if (!apiKey) {
      throw new AuthError('AGENTANON_EMAIL_API_KEY environment variable is required');
    }
    
    clientInstance = new FirefoxRelayClient(apiKey, actualConfig);
  }
  return clientInstance;
}

/**
 * Reset the singleton instance (useful for testing)
 */
export function resetClient(): void {
  clientInstance = null;
}

// ============================================================================
// Validation Schemas
// ============================================================================

/**
 * Schema for validating relay address creation requests
 */
export const CreateRelayAddressSchema = z.object({
  description: z.string().max(500).optional(),
  enabled: z.boolean().optional().default(true),
  generatedFor: z.string().max(500).optional(),
  blockListEmails: z.boolean().optional().default(false),
  usedOn: z.string().url().optional(),
});

/**
 * Schema for validating relay address update requests
 */
export const UpdateRelayAddressSchema = z.object({
  description: z.string().max(500).optional(),
  enabled: z.boolean().optional(),
  blockListEmails: z.boolean().optional(),
  usedOn: z.string().url().optional(),
});

// ============================================================================
// Exports
// ============================================================================

export default FirefoxRelayClient;
