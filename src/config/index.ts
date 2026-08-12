/**
 * Configuration Management Module
 * 
 * Provides centralized configuration management with environment variable
 * support, validation, and default values for the Firefox Relay MCP Server.
 * Follows golden-standard programming practices for maximal reliability.
 */

import { z } from 'zod/v4';
import { McpServerConfig, DEFAULT_CONFIG } from '../types';

// ============================================================================
// Environment Schema
// ============================================================================

/**
 * Environment variables schema for validation
 */
const EnvironmentSchema = z.object({
  // Required environment variables
  AGENTANON_EMAIL_API_KEY: z.string().min(1, {
    message: 'AGENTANON_EMAIL_API_KEY is required',
  }),
  
  // Optional environment variables with defaults
  AGENTANON_DATABASE_PATH: z.string().default(DEFAULT_CONFIG.databasePath!),
  AGENTANON_ENCRYPTION_KEY: z.string().default(''),
  AGENTANON_SERVER_PORT: z.string().transform(Number).pipe(
    z.number().int().positive().max(65535)
  ).default(DEFAULT_CONFIG.port!.toString()),
  AGENTANON_SERVER_HOST: z.string().default(DEFAULT_CONFIG.host!),
  AGENTANON_LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error'])
    .default(DEFAULT_CONFIG.logLevel!),
  AGENTANON_ENABLE_LOGGING: z.string().transform((val) => 
    val.toLowerCase() !== 'false' && val.toLowerCase() !== '0'
  ).default('true'),
});

// ============================================================================
// Configuration Class
// ============================================================================

/**
 * Configuration manager class
 * 
 * Validates and provides access to application configuration with support
 * for environment variables, defaults, and runtime overrides.
 */
export class Configuration {
  private static instance: Configuration | null = null;
  private readonly config: McpServerConfig;
  private readonly env: Record<string, string>;

  /**
   * Private constructor - use getInstance() instead
   */
  private constructor(
    env: Record<string, string> = process.env,
    overrides: Partial<McpServerConfig> = {}
  ) {
    // Parse and validate environment variables
    const parsedEnv = EnvironmentSchema.safeParse(env);
    
    if (!parsedEnv.success) {
      const errors = parsedEnv.error.issues.map(
        (issue) => `  - ${issue.path.join('.')}: ${issue.message}`
      ).join('\n');
      
      throw new Error(
        `Configuration validation failed:\n${errors}\n\n` +
        `Please ensure all required environment variables are set.`
      );
    }

    const envConfig = parsedEnv.data;

    // Build final configuration
    this.env = env;
    this.config = {
      // Use overrides first, then env, then defaults
      name: overrides.name || DEFAULT_CONFIG.name,
      version: overrides.version || DEFAULT_CONFIG.version,
      apiKey: overrides.apiKey || envConfig.AGENTANON_EMAIL_API_KEY,
      databasePath: overrides.databasePath || envConfig.AGENTANON_DATABASE_PATH,
      encryptionKey: overrides.encryptionKey || envConfig.AGENTANON_ENCRYPTION_KEY,
      port: overrides.port || envConfig.AGENTANON_SERVER_PORT,
      host: overrides.host || envConfig.AGENTANON_SERVER_HOST,
      enableLogging: overrides.enableLogging !== undefined 
        ? overrides.enableLogging 
        : envConfig.AGENTANON_ENABLE_LOGGING,
      logLevel: overrides.logLevel || envConfig.AGENTANON_LOG_LEVEL,
    };

    // Validate encryption key
    if (this.config.encryptionKey && this.config.encryptionKey.length < 32) {
      throw new Error(
        'AGENTANON_ENCRYPTION_KEY must be at least 32 characters long for AES-256-GCM'
      );
    }
  }

  /**
   * Get the singleton configuration instance
   */
  public static getInstance(
    env: Record<string, string> = process.env,
    overrides: Partial<McpServerConfig> = {}
  ): Configuration {
    if (!Configuration.instance) {
      Configuration.instance = new Configuration(env, overrides);
    }
    return Configuration.instance;
  }

  /**
   * Reset the singleton instance (useful for testing)
   */
  public static resetInstance(): void {
    Configuration.instance = null;
  }

  /**
   * Create a new configuration instance (useful for testing)
   */
  public static create(
    env: Record<string, string> = process.env,
    overrides: Partial<McpServerConfig> = {}
  ): Configuration {
    return new Configuration(env, overrides);
  }

  /**
   * Get the full configuration object
   */
  public getConfig(): Readonly<McpServerConfig> {
    return { ...this.config };
  }

  /**
   * Get a specific configuration value by key
   */
  public get<T extends keyof McpServerConfig>(key: T): McpServerConfig[T] {
    return this.config[key];
  }

  /**
   * Check if a configuration value exists and is truthy
   */
  public has<T extends keyof McpServerConfig>(key: T): boolean {
    return Boolean(this.config[key]);
  }

  /**
   * Get configuration as a plain object (for serialization)
   */
  public toJSON(): Record<string, unknown> {
    return {
      name: this.config.name,
      version: this.config.version,
      databasePath: this.config.databasePath,
      port: this.config.port,
      host: this.config.host,
      enableLogging: this.config.enableLogging,
      logLevel: this.config.logLevel,
      // Never expose sensitive data
      apiKey: '[REDACTED]',
      encryptionKey: '[REDACTED]',
    };
  }

  /**
   * Validate that required configuration is present
   */
  public validateRequired(): void {
    const required: (keyof McpServerConfig)[] = ['apiKey'];
    
    const missing = required.filter(key => !this.config[key]);
    
    if (missing.length > 0) {
      throw new Error(
        `Missing required configuration: ${missing.join(', ')}`
      );
    }
  }

  /**
   * Get environment variable names that can be set
   */
  public static getEnvironmentVariableNames(): string[] {
    return [
      'AGENTANON_EMAIL_API_KEY',
      'AGENTANON_DATABASE_PATH',
      'AGENTANON_ENCRYPTION_KEY',
      'AGENTANON_SERVER_PORT',
      'AGENTANON_SERVER_HOST',
      'AGENTANON_LOG_LEVEL',
      'AGENTANON_ENABLE_LOGGING',
    ];
  }

  /**
   * Generate a sample .env file content
   */
  public static generateEnvFile(): string {
    return `# Firefox Relay MCP Server Configuration
# ============================================

# REQUIRED: Firefox Relay API Key (from https://relay.firefox.com/accounts/profile/)
AGENTANON_EMAIL_API_KEY=your-firefox-relay-api-key-here

# Database Configuration
AGENTANON_DATABASE_PATH=./data/anonsec.db

# Encryption Configuration (32+ characters for AES-256-GCM)
AGENTANON_ENCRYPTION_KEY=your-32-character-encryption-key-here

# Server Configuration
AGENTANON_SERVER_PORT=3000
AGENTANON_SERVER_HOST=localhost

# Logging Configuration
AGENTANON_LOG_LEVEL=info
AGENTANON_ENABLE_LOGGING=true
`;
  }
}

// ============================================================================
// Default Export
// ============================================================================

/**
 * Default configuration export
 * 
 * Use Configuration.getInstance() for the singleton pattern,
 * or Configuration.create() for isolated instances.
 */
export const config = Configuration.getInstance();

export default Configuration;
