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

import { McpServer } from '@modelcontextprotocol/server';
import type { CallToolResult } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { Configuration } from './config';
import { getDatabase } from './db';
import { getClient } from './api';
import { MCPTool } from './types';

// Import all tool handlers
import { newEmailsTool } from './tools/new_emails';
import { readEmailsTool } from './tools/read_emails';
import { allEmailsTool } from './tools/all_emails';
import { latestEmailTool } from './tools/latest_email';
import { latestEmailOtpTool } from './tools/latest_email_otp';
import { sendAnonEmailTool } from './tools/send_anon_email';

// ============================================================================
// Server Configuration
// ============================================================================

interface ServerConfig {
  name: string;
  version: string;
  enableLogging: boolean;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

/**
 * Get server configuration from environment and Configuration singleton
 */
function getServerConfig(): ServerConfig {
  const config = Configuration.getInstance().getConfig();

  return {
    name: config.name,
    version: config.version,
    enableLogging: config.enableLogging,
    logLevel: config.logLevel,
  };
}

// ============================================================================
// Tool Registry
// ============================================================================

/**
 * Registry of all available MCP tools
 */
const TOOLS: Record<string, MCPTool> = {
  // Email Retrieval Tools
  new_emails: newEmailsTool,
  read_emails: readEmailsTool,
  all_emails: allEmailsTool,
  latest_email: latestEmailTool,

  // OTP-Specific Tools
  latest_email_otp: latestEmailOtpTool,

  // Email Sending Tools
  send_anon_email: sendAnonEmailTool,
};

/**
 * Type-safe tool name type
 */
export type ToolName = keyof typeof TOOLS;

/**
 * Get all registered tool names
 */
function getToolNames(): ToolName[] {
  return Object.keys(TOOLS);
}

/**
 * Get a specific tool by name
 */
function getTool(name: ToolName): MCPTool {
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
// Health Check
// ============================================================================

interface HealthStatus {
  status: 'healthy';
  timestamp: string;
  database: {
    connected: boolean;
    relayAddresses: number;
    emails: number;
  };
  apiClient: {
    hasApiStats: boolean;
  };
  server: {
    name: string;
    version: string;
    uptime: number;
  };
}

/**
 * Get server health status
 */
function getHealthStatus(): HealthStatus {
  const serverConfig = getServerConfig();
  const db = getDatabase();
  const client = getClient();

  return {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    database: {
      connected: db.healthCheck(),
      relayAddresses: db.getStats().relayAddresses,
      emails: db.getStats().emailLogs,
    },
    apiClient: {
      hasApiStats: Boolean(client.getApiStats()),
    },
    server: {
      name: serverConfig.name,
      version: serverConfig.version,
      uptime: process.uptime(),
    },
  };
}

// ============================================================================
// Server Initialization
// ============================================================================

/**
 * Initialize the MCP server with all tools and resources
 */
function initializeServer(): McpServer {
  const serverConfig = getServerConfig();
  const config = Configuration.getInstance().getConfig();

  // Initialize database and API client (ensures they're loaded)
  getDatabase();
  getClient();

  // Create MCP server instance
  const server = new McpServer({
    name: serverConfig.name,
    version: serverConfig.version,
  });

  // ==========================================================================
  // Tool Handlers
  // ==========================================================================

  for (const toolName of getToolNames()) {
    const tool = getTool(toolName);

    server.registerTool(
      tool.name,
      {
        description: tool.description,
        inputSchema: tool.inputSchema,
      },
      async (input: unknown): Promise<CallToolResult> => {
        try {
          const result = await tool.handler(input);
          return result as CallToolResult;
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          return {
            content: [{
              type: 'text' as const,
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

  // ==========================================================================
  // Resource Handlers
  // ==========================================================================

  server.registerResource(
    'relay-addresses',
    RESOURCE_URI.RELAY_ADDRESSES,
    {
      title: 'Firefox Relay Addresses',
      description: 'Collection of all Firefox Relay email addresses managed by this server',
      mimeType: 'application/json',
    },
    (uri) => {
      const db = getDatabase();
      const addresses = db.listRelayAddresses();

      return {
        contents: [
          {
            uri: uri.href,
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
  );

  server.registerResource(
    'server-info',
    RESOURCE_URI.SERVER_INFO,
    {
      title: 'Server Information',
      description: 'Information about the AnonSec MCP server including version, status, and configuration',
      mimeType: 'application/json',
    },
    (uri) => {
      const db = getDatabase();
      const stats = db.getStats();

      return {
        contents: [
          {
            uri: uri.href,
            mimeType: 'application/json',
            text: JSON.stringify({
              name: serverConfig.name,
              version: serverConfig.version,
              timestamp: new Date().toISOString(),
              capabilities: {
                tools: getToolNames(),
                resources: Object.keys(RESOURCE_URI),
              },
              statistics: stats,
              configuration: {
                databasePath: config.databasePath,
                encryptionEnabled: db.isEncryptionEnabled(),
                pqcReady: true,
              },
            }, null, 2),
          },
        ],
      };
    }
  );

  server.registerResource(
    'audit-logs',
    RESOURCE_URI.AUDIT_LOGS,
    {
      title: 'Audit Logs',
      description: 'Collection of audit log entries for security and traceability',
      mimeType: 'application/json',
    },
    (uri) => {
      const db = getDatabase();
      const logs = db.listAuditLogs(undefined, 100);

      return {
        contents: [
          {
            uri: uri.href,
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
              retrievedAt: new Date().toISOString(),
            }, null, 2),
          },
        ],
      };
    }
  );

  return server;
}

// ============================================================================
// Server Lifecycle Management
// ============================================================================

/**
 * Handle server startup logging
 */
function logServerStart(): void {
  const serverConfig = getServerConfig();
  const config = Configuration.getInstance().getConfig();
  const db = getDatabase();
  const client = getClient();

  console.log(`Starting ${serverConfig.name} v${serverConfig.version}...`);
  console.log(`Database: ${config.databasePath}`);
  console.log(`Encryption: ${db.isEncryptionEnabled() ? 'PQC-ready AES-256-GCM' : 'disabled'}`);
  console.log(`API client authenticated: ${client.getApiKey() !== ''}`);
  console.log(`Tools: ${getToolNames().join(', ')}`);
  console.log(`Resources: ${Object.keys(RESOURCE_URI).length} available`);

  const health = getHealthStatus();
  console.log(`Health: ${health.status}`);
  console.log('Server ready.');
}

/**
 * Handle graceful server shutdown
 */
function onServerShutdown(): void {
  console.log('Server shutting down...');

  try {
    const db = getDatabase();
    db.close();
    console.log('Database connection closed.');
  } catch (error) {
    console.error('Error closing database:', error);
  }

  console.log('Server shutdown complete.');
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
 * 4. Connects the server to a stdio transport
 * 5. Handles lifecycle events
 */
export async function startServer(): Promise<McpServer> {
  const server = initializeServer();
  logServerStart();

  // Handle SIGINT/SIGTERM for graceful shutdown
  process.on('SIGINT', () => {
    onServerShutdown();
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    onServerShutdown();
    process.exit(0);
  });

  // Handle unhandled promise rejections and uncaught exceptions
  process.on('unhandledRejection', (reason) => {
    console.error('Unhandled rejection:', reason);
  });
  process.on('uncaughtException', (error) => {
    console.error('Uncaught exception:', error);
    process.exit(1);
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);

  return server;
}

// ============================================================================
// Direct Execution
// ============================================================================

// Start server when this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  startServer().catch((error: unknown) => {
    console.error('Server crashed:', error);
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
  initializeServer,
  getHealthStatus,
};

export default startServer;
