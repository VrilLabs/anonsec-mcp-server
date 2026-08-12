/**
 * Firefox Relay MCP Server Entry Point
 * 
 * Main server initialization and tool registration for the Anonymous Email Management
 * MCP server. This server provides comprehensive email management capabilities
 * for Firefox Relay addresses with a focus on privacy, security, and anonymity.
 * 
 * Features:
 * - Firefox Relay address management
 * - Email retrieval and processing
 * - OTP extraction and handling
 * - Anonymous email sending simulation
 * - PQC-ready encryption architecture
 * - Comprehensive audit logging
 * - Security analysis and validation
 * 
 * Follows golden-standard programming practices:
 * - Singleton pattern for database and API client
 * - Zod v4 validation for all inputs
 * - Comprehensive error handling
 * - Type-safe TypeScript design
 * - Production-ready architecture
 */

import {
  Server,
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
  ListResourcesRequestSchema,
} from '@modelcontextprotocol/server';
import { z } from 'zod/v4';
import { Configuration } from './config';
import { getDatabase } from './db';
import { getClient } from './api';

// Import all tool handlers
import {
  newEmailsTool,
  NewEmailsInputSchema,
} from './tools/new_emails';

import {
  readEmailsTool,
  ReadEmailsInputSchema,
} from './tools/read_emails';

import {
  allEmailsTool,
  AllEmailsInputSchema,
} from './tools/all_emails';

import {
  latestEmailTool,
  LatestEmailInputSchema,
} from './tools/latest_email';

import {
  latestEmailOtpTool,
  LatestEmailOtpInputSchema,
} from './tools/latest_email_otp';

import {
  sendAnonEmailTool,
  SendAnonEmailInputSchema,
} from './tools/send_anon_email';

// ============================================================================
// Server Configuration
// ============================================================================

interface ServerConfig {
  name: string;
  version: string;
  port: number;
  host: string;
  enableLogging: boolean;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

/**
 * Get server configuration from environment and Configuration singleton
 */
function getServerConfig(): ServerConfig {
  const config = Configuration.getInstance();
  
  return {
    name: config.name || 'anonsec-mcp-server',
    version: config.version || '1.0.0',
    port: config.port || 3000,
    host: config.host || 'localhost',
    enableLogging: config.enableLogging !== false,
    logLevel: config.logLevel || 'info',
  };
}

// ============================================================================
// Tool Registry
// ============================================================================

/**
 * Registry of all available MCP tools
 */
const TOOLS = {
  // Email Retrieval Tools
  new_emails: newEmailsTool,
  read_emails: readEmailsTool,
  all_emails: allEmailsTool,
  latest_email: latestEmailTool,
  
  // OTP-Specific Tools
  latest_email_otp: latestEmailOtpTool,
  
  // Email Sending Tools
  send_anon_email: sendAnonEmailTool,
} as const;

/**
 * Type-safe tool name type
 */
export type ToolName = keyof typeof TOOLS;

/**
 * Get all registered tool names
 */
function getToolNames(): ToolName[] {
  return Object.keys(TOOLS) as ToolName[];
}

/**
 * Get a specific tool by name
 */
function getTool(name: ToolName) {
  return TOOLS[name];
}

// ============================================================================
// Resource Definitions
// ============================================================================

/**
 * MCP Resource URIs available from this server
 */
export const RESOURCE_URI = {
  // Firefox Relay addresses
  RELAY_ADDRESSES: 'urn:anonsec:relay/addresses',
  
  // Email collections
  EMAILS: 'urn:anonsec:email/collection',
  
  // Individual email resources
  EMAIL: (emailId: string) => `urn:anonsec:email/${emailId}`,
  
  // OTP emails collection
  OTP_EMAILS: 'urn:anonsec:otp/emails',
  
  // Server information
  SERVER_INFO: 'urn:anonsec:server/info',
  
  // Audit logs
  AUDIT_LOGS: 'urn:anonsec:audit/logs',
} as const;

/**
 * Type for resource URI
 */
export type ResourceUri = typeof RESOURCE_URI[keyof typeof RESOURCE_URI];

// ============================================================================
// Server Initialization
// ============================================================================

/**
 * Initialize the MCP server with all tools and resources
 */
async function initializeServer() {
  const serverConfig = getServerConfig();
  const config = Configuration.getInstance();
  
  // Initialize database and API client (ensures they're loaded)
  const db = getDatabase();
  const client = getClient();

  // Create MCP server instance
  const server = new Server(
    {
      name: serverConfig.name,
      version: serverConfig.version,
    },
    {
      capabilities: {
        tools: {},
        resources: {
          [RESOURCE_URI.RELAY_ADDRESSES]: {
            name: 'Firefox Relay Addresses',
            description: 'Collection of all Firefox Relay email addresses managed by this server',
            mimeType: 'application/json',
          },
          [RESOURCE_URI.EMAILS]: {
            name: 'Email Collection',
            description: 'Collection of all emails received through Firefox Relay addresses',
            mimeType: 'application/json',
          },
          [RESOURCE_URI.OTP_EMAILS]: {
            name: 'OTP Emails',
            description: 'Collection of OTP (One-Time Password) emails extracted by the server',
            mimeType: 'application/json',
          },
          [RESOURCE_URI.SERVER_INFO]: {
            name: 'Server Information',
            description: 'Information about the AnonSec MCP server including version, status, and configuration',
            mimeType: 'application/json',
          },
          [RESOURCE_URI.AUDIT_LOGS]: {
            name: 'Audit Logs',
            description: 'Collection of audit log entries for security and traceability',
            mimeType: 'application/json',
          },
        },
      },
    }
  );

  // ==========================================================================
  // Tool Handlers
  // ==========================================================================

  // Register all tools
  for (const toolName of getToolNames()) {
    const tool = getTool(toolName);
    
    if (tool) {
      server.tool(
        tool.name,
        tool.description,
        tool.inputSchema,
        async (input, context) => {
          try {
            // Get fresh database instance for each request
            const db = getDatabase();
            const client = getClient();
            
            // Execute the tool handler
            const result = await tool.handler(input, context);
            
            return result;
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  success: false,
                  error: `Tool execution failed: ${errorMessage}`,
                  tool: toolName,
                }, null, 2),
              }],
              isError: true,
            };
          }
        }
      );
    }
  }

  // ==========================================================================
  // Resource Handlers
  // ==========================================================================

  // List all available resources
  server.resource(
    ListResourcesRequestSchema,
    async () => {
      const resources = [
        {
          uri: RESOURCE_URI.RELAY_ADDRESSES,
          name: 'Firefox Relay Addresses',
          description: 'Collection of all Firefox Relay email addresses',
          mimeType: 'application/json',
        },
        {
          uri: RESOURCE_URI.EMAILS,
          name: 'Email Collection',
          description: 'Collection of all received emails',
          mimeType: 'application/json',
        },
        {
          uri: RESOURCE_URI.OTP_EMAILS,
          name: 'OTP Emails',
          description: 'Collection of OTP emails',
          mimeType: 'application/json',
        },
        {
          uri: RESOURCE_URI.SERVER_INFO,
          name: 'Server Information',
          description: 'Server metadata and status',
          mimeType: 'application/json',
        },
        {
          uri: RESOURCE_URI.AUDIT_LOGS,
          name: 'Audit Logs',
          description: 'Security audit log entries',
          mimeType: 'application/json',
        },
      ];

      return {
        resources,
      };
    }
  );

  // Read server information resource
  server.resource(
    ReadResourceRequestSchema,
    async ({ uri }) => {
      if (uri === RESOURCE_URI.SERVER_INFO) {
        const db = getDatabase();
        
        return {
          contents: [
            {
              uri: RESOURCE_URI.SERVER_INFO,
              mimeType: 'application/json',
              text: JSON.stringify({
                name: serverConfig.name,
                version: serverConfig.version,
                timestamp: new Date().toISOString(),
                capabilities: {
                  tools: getToolNames(),
                  resources: Object.keys(RESOURCE_URI),
                },
                statistics: {
                  relayAddresses: db.getRelayAddressCount(),
                  totalEmails: db.getEmailLogCount(),
                  otpEmails: db.getOtpEmailCount(),
                  auditLogs: db.getAuditLogCount(),
                },
                configuration: {
                  databasePath: config.databasePath,
                  encryptionEnabled: true,
                  pqcReady: true,
                },
              }, null, 2),
            },
          ],
        };
      }

      // Read relay addresses resource
      if (uri === RESOURCE_URI.RELAY_ADDRESSES) {
        const db = getDatabase();
        const addresses = db.getAllRelayAddresses();
        
        return {
          contents: [
            {
              uri: RESOURCE_URI.RELAY_ADDRESSES,
              mimeType: 'application/json',
              text: JSON.stringify({
                addresses,
                count: addresses.length,
                retrievedAt: new Date().toISOString(),
              }, null, 2),
            },
          ],
        };
      }

      // Read email collection resource
      if (uri === RESOURCE_URI.EMAILS) {
        const db = getDatabase();
        const emails = db.getAllEmailLogs(100); // Limit to 100 for performance
        
        return {
          contents: [
            {
              uri: RESOURCE_URI.EMAILS,
              mimeType: 'application/json',
              text: JSON.stringify({
                emails: emails.map(email => ({
                  id: email.id,
                  emailId: email.email_id,
                  relayAddressId: email.relay_address_id,
                  sender: email.sender,
                  recipient: email.recipient,
                  subject: email.subject,
                  receivedAt: email.received_at,
                  isOtp: Boolean(email.is_otp),
                  size: email.size,
                })),
                count: emails.length,
                totalAvailable: db.getEmailLogCount(),
                retrievedAt: new Date().toISOString(),
              }, null, 2),
            },
          ],
        };
      }

      // Read OTP emails resource
      if (uri === RESOURCE_URI.OTP_EMAILS) {
        const db = getDatabase();
        const otpEmails = db.getAllOtpEmails();
        
        return {
          contents: [
            {
              uri: RESOURCE_URI.OTP_EMAILS,
              mimeType: 'application/json',
              text: JSON.stringify({
                emails: otpEmails.map(email => ({
                  id: email.id,
                  emailId: email.email_id,
                  relayAddressId: email.relay_address_id,
                  sender: email.sender,
                  recipient: email.recipient,
                  subject: email.subject,
                  receivedAt: email.received_at,
                  otpCode: email.otp_code ? '***' : null, // Don't expose OTP codes
                  isOtp: Boolean(email.is_otp),
                  size: email.size,
                })),
                count: otpEmails.length,
                totalAvailable: db.getOtpEmailCount(),
                retrievedAt: new Date().toISOString(),
              }, null, 2),
            },
          ],
        };
      }

      // Read audit logs resource
      if (uri === RESOURCE_URI.AUDIT_LOGS) {
        const db = getDatabase();
        const logs = db.getAuditLogs(100); // Limit to 100 for performance
        
        return {
          contents: [
            {
              uri: RESOURCE_URI.AUDIT_LOGS,
              mimeType: 'application/json',
              text: JSON.stringify({
                logs: logs.map(log => ({
                  id: log.id,
                  timestamp: log.timestamp,
                  action: log.action,
                  userId: log.user_id,
                  targetId: log.target_id,
                  targetType: log.target_type,
                  // Don't expose details as they may contain sensitive info
                })),
                count: logs.length,
                totalAvailable: db.getAuditLogCount(),
                retrievedAt: new Date().toISOString(),
              }, null, 2),
            },
          ],
        };
      }

      // Handle individual email resource
      if (uri.startsWith('urn:anonsec:email/')) {
        const db = getDatabase();
        const emailId = uri.split('/').pop();
        
        if (emailId) {
          const email = db.getEmailLogById(Number(emailId));
          
          if (email) {
            // Decrypt content for display
            const body = email.body && email.body_encrypted 
              ? db.decryptField(email.body, true).decrypted 
              : email.body;
            
            const headers = email.headers && email.headers_encrypted
              ? JSON.parse(db.decryptField(email.headers, true).decrypted)
              : email.headers ? JSON.parse(email.headers) : null;

            return {
              contents: [
                {
                  uri,
                  mimeType: 'application/json',
                  text: JSON.stringify({
                    id: email.id,
                    emailId: email.email_id,
                    relayAddressId: email.relay_address_id,
                    sender: email.sender,
                    recipient: email.recipient,
                    subject: email.subject,
                    body,
                    headers,
                    receivedAt: email.received_at,
                    readAt: email.read_at,
                    isOtp: Boolean(email.is_otp),
                    otpCode: email.otp_code ? '***' : null, // Don't expose OTP
                    size: email.size,
                  }, null, 2),
                },
              ],
            };
          }
        }
      }

      // Resource not found
      throw new Error(`Resource not found: ${uri}`);
    }
  );

  // ==========================================================================
  // List Tools Handler
  // ==========================================================================

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const tools = getToolNames().map(toolName => {
      const tool = getTool(toolName);
      return {
        name: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema,
      };
    });

    return {
      tools,
    };
  });

  // ==========================================================================
  // Health Check and Server Information
  // ==========================================================================

  /**
   * Get server health status
   */
  function getHealthStatus() {
    const db = getDatabase();
    const client = getClient();
    
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      database: {
        connected: db.isConnected(),
        relayAddresses: db.getRelayAddressCount(),
        emails: db.getEmailLogCount(),
      },
      apiClient: {
        authenticated: client.isAuthenticated(),
        apiVersion: FIREFOX_RELAY_CONSTANTS.API_VERSION,
      },
      server: {
        name: serverConfig.name,
        version: serverConfig.version,
        uptime: process.uptime(),
      },
    };
  }

  // ==========================================================================
  // Server Lifecycle Management
  // ==========================================================================

  /**
   * Handle server startup
   */
  async function onServerStart() {
    const config = Configuration.getInstance();
    const db = getDatabase();
    const client = getClient();

    console.log(`🚀 ${serverConfig.name} v${serverConfig.version} starting...`);
    console.log(`📍 Server: ${serverConfig.host}:${serverConfig.port}`);
    console.log(`🔒 Encryption: PQC-ready AES-256-GCM`);

    // Initialize database
    db.initialize();
    console.log(`🗃️  Database: ${config.databasePath}`);

    // Test API client authentication
    try {
      const isAuthenticated = await client.isAuthenticated();
      console.log(`🔑 API Client: ${isAuthenticated ? 'Authenticated' : 'Not authenticated'}`);
      
      if (!isAuthenticated) {
        console.warn('⚠️  Warning: Firefox Relay API key not configured or invalid');
      }
    } catch (error) {
      console.warn(`⚠️  API authentication check failed: ${error}`);
    }

    // Log available tools
    const toolNames = getToolNames();
    console.log(`🛠️  Tools: ${toolNames.join(', ')}`);

    // Log available resources
    const resourceCount = Object.keys(RESOURCE_URI).length;
    console.log(`📦 Resources: ${resourceCount} available`);

    // Health check
    const health = getHealthStatus();
    console.log(`✅ Health: ${health.status}`);
    console.log(`📊 Database: ${health.database.relayAddresses} relay addresses, ${health.database.emails} emails`);

    console.log(`✨ Server ready!`);
    console.log('');
  }

  /**
   * Handle graceful server shutdown
   */
  async function onServerShutdown() {
    console.log('🛑 Server shutting down...');
    
    try {
      const db = getDatabase();
      db.close();
      console.log('🗃️  Database connection closed');
    } catch (error) {
      console.error('❌ Error closing database:', error);
    }

    console.log('✅ Server shutdown complete');
  }

  // ==========================================================================
  // Process Management
  // ==========================================================================

  // Handle SIGINT for graceful shutdown
  process.on('SIGINT', async () => {
    console.log('\n🔴 SIGINT received. Shutting down...');
    await onServerShutdown();
    process.exit(0);
  });

  // Handle SIGTERM for graceful shutdown
  process.on('SIGTERM', async () => {
    console.log('\n🔴 SIGTERM received. Shutting down...');
    await onServerShutdown();
    process.exit(0);
  });

  // Handle unhandled promise rejections
  process.on('unhandledRejection', (reason, promise) => {
    console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
  });

  // Handle uncaught exceptions
  process.on('uncaughtException', (error) => {
    console.error('💥 Uncaught Exception:', error);
    process.exit(1);
  });

  // ==========================================================================
  // Start Server
  // ==========================================================================

  await onServerStart();

  return server;
}

// ============================================================================
// Server Entry Point
// ============================================================================

/**
 * Main server entry point
 * 
 * This function:
 * 1. Initializes the Configuration singleton
 * 2. Creates and configures the MCP server
 * 3. Registers all tools and resources
 * 4. Starts the server on the configured port
 * 5. Handles lifecycle events
 */
export async function startServer() {
  try {
    const server = await initializeServer();
    const config = getServerConfig();

    // Start the server
    const transport = server.connect({
      port: config.port,
      hostname: config.host,
    });

    console.log(`🌐 Server listening on ${config.host}:${config.port}`);
    console.log(`📋 Press Ctrl+C to stop the server`);

    return { server, transport };
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// ============================================================================
// Direct Execution
// ============================================================================

// Start server when this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  startServer().catch(error => {
    console.error('❌ Server crashed:', error);
    process.exit(1);
  });
}

// ============================================================================
// Exports
// ============================================================================

export {
  getServerConfig,
  getToolNames,
  getTool,
  RESOURCE_URI,
  initializeServer,
  getHealthStatus,
};

export default startServer;
