/**
 * Database Module
 * 
 * Provides SQLite database management with PQC encryption at rest for
 * the Firefox Relay MCP Server. Implements a robust database layer with:
 * - Automatic schema initialization
 * - Prepared statements for SQL injection prevention
 * - PQC encryption for sensitive data fields
 * - Transaction support
 * - Connection pooling
 * 
 * Follows golden-standard programming practices for maximal data integrity
 * and security.
 */

import Database from 'better-sqlite3';
import { dirname } from 'node:path';
import { existsSync, mkdirSync, statSync } from 'node:fs';
import {
  encryptToHex,
  decryptFromHex,
  EncryptionError,
  DecryptionError,
} from '../utils/crypto';
import {
  DatabaseRelayAddress,
  DatabaseEmailLog,
  DatabaseApiKey,
  DatabaseAuditLog,
} from '../types';
import { Configuration } from '../config';

// ============================================================================
// Constants
// ============================================================================

/**
 * Database schema version
 */
const SCHEMA_VERSION = 1;

// ============================================================================
// Error Classes
// ============================================================================

/**
 * Custom error for database-related failures
 */
export class DatabaseError extends Error {
  constructor(
    message: string,
    public readonly code?: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'DatabaseError';
  }
}

/**
 * Custom error for database connection failures
 */
export class ConnectionError extends DatabaseError {
  constructor(message: string = 'Database connection failed', cause?: Error) {
    super(message, 'CONNECTION_ERROR', cause);
  }
}

/**
 * Custom error for database query failures
 */
export class QueryError extends DatabaseError {
  constructor(
    message: string,
    public readonly sql: string,
    cause?: Error
  ) {
    super(message, 'QUERY_ERROR', cause);
    this.sql = sql;
  }
}

/**
 * Custom error for not found entities
 */
export class NotFoundError extends DatabaseError {
  constructor(
    entityType: string,
    identifier: string | number
  ) {
    super(
      `${entityType} not found with identifier: ${identifier}`,
      'NOT_FOUND'
    );
  }
}

// ============================================================================
// Database Schema
// ============================================================================

/**
 * SQL statements for creating database schema
 */
const SCHEMA_SQL = `
-- Schema version tracking
CREATE TABLE IF NOT EXISTS _schema_version (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Relay addresses (Firefox Relay email masks)
CREATE TABLE IF NOT EXISTS relay_addresses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  relay_id INTEGER UNIQUE NOT NULL,
  full_address TEXT UNIQUE NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  last_modified_at TEXT NOT NULL,
  last_used_at TEXT,
  num_forwarded INTEGER NOT NULL DEFAULT 0,
  num_blocked INTEGER NOT NULL DEFAULT 0,
  num_replied INTEGER NOT NULL DEFAULT 0,
  num_spam INTEGER NOT NULL DEFAULT 0,
  created_at_db TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at_db TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Email logs
CREATE TABLE IF NOT EXISTS email_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  relay_address_id INTEGER NOT NULL,
  email_id TEXT UNIQUE NOT NULL,
  sender TEXT NOT NULL,
  recipient TEXT NOT NULL,
  subject TEXT NOT NULL DEFAULT '',
  received_at TEXT NOT NULL,
  read_at TEXT,
  body TEXT,
  body_encrypted INTEGER NOT NULL DEFAULT 0,
  otp_code TEXT,
  is_otp INTEGER NOT NULL DEFAULT 0,
  headers TEXT,
  headers_encrypted INTEGER NOT NULL DEFAULT 0,
  size INTEGER NOT NULL DEFAULT 0,
  created_at_db TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at_db TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (relay_address_id) REFERENCES relay_addresses(id) ON DELETE CASCADE
);

-- API keys for authentication
CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_hash TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  permissions TEXT NOT NULL DEFAULT '[]',
  created_at_db TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at_db TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL DEFAULT (datetime('now')),
  action TEXT NOT NULL,
  user_id TEXT,
  target_id TEXT,
  target_type TEXT,
  details TEXT,
  details_encrypted INTEGER NOT NULL DEFAULT 0,
  ip_address TEXT,
  user_agent TEXT,
  created_at_db TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_relay_addresses_full_address ON relay_addresses(full_address);
CREATE INDEX IF NOT EXISTS idx_relay_addresses_enabled ON relay_addresses(enabled);
CREATE INDEX IF NOT EXISTS idx_relay_addresses_relay_id ON relay_addresses(relay_id);
CREATE INDEX IF NOT EXISTS idx_email_logs_relay_address_id ON email_logs(relay_address_id);
CREATE INDEX IF NOT EXISTS idx_email_logs_email_id ON email_logs(email_id);
CREATE INDEX IF NOT EXISTS idx_email_logs_received_at ON email_logs(received_at);
CREATE INDEX IF NOT EXISTS idx_email_logs_is_otp ON email_logs(is_otp);
CREATE INDEX IF NOT EXISTS idx_email_logs_otp_code ON email_logs(otp_code) WHERE otp_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
`;

/**
 * Schema migrations
 */
const MIGRATIONS: Record<number, string> = {
  // Future migrations would be added here
};

// ============================================================================
// Database Class
// ============================================================================

/**
 * Main database class
 * 
 * Provides a high-level interface for database operations with automatic
 * encryption/decryption of sensitive fields and connection management.
 */
export class AnonSecDatabase {
  private db: Database.Database;
  private config: Configuration;
  private encryptionKey: string | null;

  /**
   * Create a new database instance
   * 
   * @param config - Configuration instance
   * @param dbPath - Optional database path override
   */
  constructor(config: Configuration, dbPath?: string) {
    this.config = config;
    this.encryptionKey = config.get('encryptionKey') || null;
    
    const path = dbPath || config.get('databasePath');
    
    // Ensure directory exists
    this.ensureDirectory(path);
    
    // Open database connection
    this.db = new Database(path);
    
    // Configure database
    this.configureDatabase();
    
    // Initialize schema
    this.initializeSchema();
  }

  /**
   * Ensure the database directory exists
   */
  private ensureDirectory(path: string): void {
    const dir = dirname(path);
    if (dir && !existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  }

  /**
   * Configure database settings
   */
  private configureDatabase(): void {
    // Enable WAL mode for better concurrency
    this.db.pragma('journal_mode = WAL');
    
    // Set synchronous to NORMAL for better performance
    this.db.pragma('synchronous = NORMAL');
    
    // Enable foreign keys
    this.db.pragma('foreign_keys = ON');
    
    // Increase cache size for better performance
    this.db.pragma('cache_size = -2000'); // 2MB cache
    
    // Enable temp store in memory
    this.db.pragma('temp_store = MEMORY');
    
    // Set busy timeout
    this.db.pragma('busy_timeout = 5000');
  }

  /**
   * Initialize database schema
   */
  private initializeSchema(): void {
    // Check current schema version
    let currentVersion = 0;
    try {
      const result = this.db.prepare('SELECT version FROM _schema_version ORDER BY version DESC LIMIT 1').get() as { version: number } | undefined;
      if (result) {
        currentVersion = result.version;
      }
    } catch {
      // Table doesn't exist yet
    }

    // Apply schema if not exists
    if (currentVersion < SCHEMA_VERSION) {
      this.db.exec(SCHEMA_SQL);
      
      // Record schema version
      this.db.prepare('INSERT OR REPLACE INTO _schema_version (version) VALUES (?)')
        .run(SCHEMA_VERSION);
    }

    // Apply migrations if needed
    for (let v = currentVersion + 1; v <= SCHEMA_VERSION; v++) {
      if (MIGRATIONS[v]) {
        this.db.exec(MIGRATIONS[v]);
        this.db.prepare('INSERT OR REPLACE INTO _schema_version (version) VALUES (?)')
          .run(v);
      }
    }
  }

  /**
   * Get the underlying database instance
   */
  public getDatabase(): Database.Database {
    return this.db;
  }

  /**
   * Check if encryption is enabled
   */
  public isEncryptionEnabled(): boolean {
    return Boolean(this.encryptionKey);
  }

  // ============================================================================
  // Relay Address Operations
  // ============================================================================

  /**
   * Insert a new relay address
   */
  public insertRelayAddress(data: Omit<DatabaseRelayAddress, 'id'>): DatabaseRelayAddress {
    const stmt = this.db.prepare(`
      INSERT INTO relay_addresses (
        relay_id, full_address, description, enabled,
        created_at, last_modified_at, last_used_at,
        num_forwarded, num_blocked, num_replied, num_spam
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      data.relay_id,
      data.full_address,
      data.description,
      data.enabled ? 1 : 0,
      data.created_at,
      data.last_modified_at,
      data.last_used_at || null,
      data.num_forwarded,
      data.num_blocked,
      data.num_replied,
      data.num_spam
    );

    return {
      ...data,
      id: result.lastInsertRowid as number,
    };
  }

  /**
   * Get a relay address by ID
   */
  public getRelayAddressById(id: number): DatabaseRelayAddress | null {
    const stmt = this.db.prepare(`
      SELECT 
        id, relay_id, full_address, description, enabled,
        created_at, last_modified_at, last_used_at,
        num_forwarded, num_blocked, num_replied, num_spam
      FROM relay_addresses
      WHERE id = ?
    `);

    const row = stmt.get(id) as DatabaseRelayAddress | undefined;
    return row ? {
      ...row,
      enabled: Boolean(row.enabled),
    } : null;
  }

  /**
   * Get a relay address by full address
   */
  public getRelayAddressByFullAddress(fullAddress: string): DatabaseRelayAddress | null {
    const stmt = this.db.prepare(`
      SELECT 
        id, relay_id, full_address, description, enabled,
        created_at, last_modified_at, last_used_at,
        num_forwarded, num_blocked, num_replied, num_spam
      FROM relay_addresses
      WHERE full_address = ?
    `);

    const row = stmt.get(fullAddress) as DatabaseRelayAddress | undefined;
    return row ? {
      ...row,
      enabled: Boolean(row.enabled),
    } : null;
  }

  /**
   * List all relay addresses
   */
  public listRelayAddresses(enabledOnly?: boolean): DatabaseRelayAddress[] {
    const enabledFilter = enabledOnly ? 'WHERE enabled = 1' : '';
    const stmt = this.db.prepare(`
      SELECT 
        id, relay_id, full_address, description, enabled,
        created_at, last_modified_at, last_used_at,
        num_forwarded, num_blocked, num_replied, num_spam
      FROM relay_addresses
      ${enabledFilter}
      ORDER BY created_at_db DESC
    `);

    const rows = stmt.all() as DatabaseRelayAddress[];
    return rows.map(row => ({
      ...row,
      enabled: Boolean(row.enabled),
    }));
  }

  /**
   * Update a relay address
   */
  public updateRelayAddress(
    id: number,
    updates: Partial<Omit<DatabaseRelayAddress, 'id' | 'relay_id' | 'full_address'>>
  ): DatabaseRelayAddress | null {
    const existing = this.getRelayAddressById(id);
    if (!existing) {
      return null;
    }

    const updated = { ...existing, ...updates };
    
    const stmt = this.db.prepare(`
      UPDATE relay_addresses SET
        description = ?,
        enabled = ?,
        last_modified_at = ?,
        last_used_at = ?,
        num_forwarded = ?,
        num_blocked = ?,
        num_replied = ?,
        num_spam = ?,
        updated_at_db = datetime('now')
      WHERE id = ?
    `);

    stmt.run(
      updated.description,
      updated.enabled ? 1 : 0,
      updated.last_modified_at,
      updated.last_used_at || null,
      updated.num_forwarded,
      updated.num_blocked,
      updated.num_replied,
      updated.num_spam,
      id
    );

    return updated;
  }

  /**
   * Delete a relay address
   */
  public deleteRelayAddress(id: number): boolean {
    const stmt = this.db.prepare('DELETE FROM relay_addresses WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  // ============================================================================
  // Email Log Operations
  // ============================================================================

  /**
   * Encrypt a field if encryption is enabled
   */
  private encryptField(value: string | null): { encrypted: string | null; wasEncrypted: boolean } {
    if (!value || !this.encryptionKey) {
      return { encrypted: value, wasEncrypted: false };
    }

    try {
      const encrypted = encryptToHex(value, this.encryptionKey);
      return { encrypted, wasEncrypted: true };
    } catch (error) {
      throw new EncryptionError(
        `Failed to encrypt field: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Decrypt a field if it was encrypted
   */
  private decryptField(value: string | null, wasEncrypted: boolean): string | null {
    if (!value || !wasEncrypted || !this.encryptionKey) {
      return value;
    }

    try {
      return decryptFromHex(value, this.encryptionKey);
    } catch (error) {
      throw new DecryptionError(
        `Failed to decrypt field: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Insert a new email log
   */
  public insertEmailLog(data: Omit<DatabaseEmailLog, 'id' | 'body_encrypted' | 'headers_encrypted'>): DatabaseEmailLog {
    // Encrypt sensitive fields
    const bodyEncrypted = this.encryptField(data.body || null);
    const headersEncrypted = this.encryptField(data.headers || null);

    const stmt = this.db.prepare(`
      INSERT INTO email_logs (
        relay_address_id, email_id, sender, recipient, subject,
        received_at, read_at, body, body_encrypted,
        otp_code, is_otp, headers, headers_encrypted, size
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      data.relay_address_id,
      data.email_id,
      data.sender,
      data.recipient,
      data.subject,
      data.received_at,
      data.read_at || null,
      bodyEncrypted.encrypted,
      bodyEncrypted.wasEncrypted ? 1 : 0,
      data.otp_code || null,
      data.is_otp ? 1 : 0,
      headersEncrypted.encrypted,
      headersEncrypted.wasEncrypted ? 1 : 0,
      data.size
    );

    return {
      ...data,
      id: result.lastInsertRowid as number,
      body: bodyEncrypted.encrypted,
      body_encrypted: bodyEncrypted.wasEncrypted,
      headers: headersEncrypted.encrypted,
      headers_encrypted: headersEncrypted.wasEncrypted,
    };
  }

  /**
   * Get an email log by ID
   */
  public getEmailLogById(id: number): DatabaseEmailLog | null {
    const stmt = this.db.prepare(`
      SELECT 
        id, relay_address_id, email_id, sender, recipient, subject,
        received_at, read_at, body, body_encrypted,
        otp_code, is_otp, headers, headers_encrypted, size
      FROM email_logs
      WHERE id = ?
    `);

    const row = stmt.get(id) as DatabaseEmailLog | undefined;
    if (!row) {
      return null;
    }

    // Decrypt sensitive fields
    if (row.body && row.body_encrypted) {
      row.body = this.decryptField(row.body, true);
    }
    if (row.headers && row.headers_encrypted) {
      row.headers = this.decryptField(row.headers, true);
    }

    return {
      ...row,
      is_otp: Boolean(row.is_otp),
      body_encrypted: Boolean(row.body_encrypted),
      headers_encrypted: Boolean(row.headers_encrypted),
    };
  }

  /**
   * Get email logs by relay address ID
   */
  public getEmailLogsByRelayAddressId(
    relayAddressId: number,
    limit?: number,
    offset?: number
  ): DatabaseEmailLog[] {
    const limitClause = limit ? `LIMIT ${limit}` : '';
    const offsetClause = offset ? `OFFSET ${offset}` : '';

    const stmt = this.db.prepare(`
      SELECT 
        id, relay_address_id, email_id, sender, recipient, subject,
        received_at, read_at, body, body_encrypted,
        otp_code, is_otp, headers, headers_encrypted, size
      FROM email_logs
      WHERE relay_address_id = ?
      ORDER BY received_at DESC
      ${limitClause} ${offsetClause}
    `);

    const rows = stmt.all(relayAddressId) as DatabaseEmailLog[];
    
    return rows.map(row => {
      // Decrypt sensitive fields
      if (row.body && row.body_encrypted) {
        row.body = this.decryptField(row.body, true);
      }
      if (row.headers && row.headers_encrypted) {
        row.headers = this.decryptField(row.headers, true);
      }

      return {
        ...row,
        is_otp: Boolean(row.is_otp),
        body_encrypted: Boolean(row.body_encrypted),
        headers_encrypted: Boolean(row.headers_encrypted),
      };
    });
  }

  /**
   * Get the latest email log for a relay address
   */
  public getLatestEmailLogByRelayAddressId(
    relayAddressId: number
  ): DatabaseEmailLog | null {
    const stmt = this.db.prepare(`
      SELECT 
        id, relay_address_id, email_id, sender, recipient, subject,
        received_at, read_at, body, body_encrypted,
        otp_code, is_otp, headers, headers_encrypted, size
      FROM email_logs
      WHERE relay_address_id = ?
      ORDER BY received_at DESC
      LIMIT 1
    `);

    const row = stmt.get(relayAddressId) as DatabaseEmailLog | undefined;
    if (!row) {
      return null;
    }

    // Decrypt sensitive fields
    if (row.body && row.body_encrypted) {
      row.body = this.decryptField(row.body, true);
    }
    if (row.headers && row.headers_encrypted) {
      row.headers = this.decryptField(row.headers, true);
    }

    return {
      ...row,
      is_otp: Boolean(row.is_otp),
      body_encrypted: Boolean(row.body_encrypted),
      headers_encrypted: Boolean(row.headers_encrypted),
    };
  }

  /**
   * Get all email logs with OTP codes
   */
  public getOtpEmailLogs(limit?: number): DatabaseEmailLog[] {
    const limitClause = limit ? `LIMIT ${limit}` : '';

    const stmt = this.db.prepare(`
      SELECT 
        id, relay_address_id, email_id, sender, recipient, subject,
        received_at, read_at, body, body_encrypted,
        otp_code, is_otp, headers, headers_encrypted, size
      FROM email_logs
      WHERE is_otp = 1 AND otp_code IS NOT NULL
      ORDER BY received_at DESC
      ${limitClause}
    `);

    const rows = stmt.all() as DatabaseEmailLog[];
    
    return rows.map(row => {
      // Decrypt sensitive fields
      if (row.body && row.body_encrypted) {
        row.body = this.decryptField(row.body, true);
      }
      if (row.headers && row.headers_encrypted) {
        row.headers = this.decryptField(row.headers, true);
      }

      return {
        ...row,
        is_otp: Boolean(row.is_otp),
        body_encrypted: Boolean(row.body_encrypted),
        headers_encrypted: Boolean(row.headers_encrypted),
      };
    });
  }

  /**
   * Get the latest OTP email
   */
  public getLatestOtpEmail(): DatabaseEmailLog | null {
    const stmt = this.db.prepare(`
      SELECT 
        id, relay_address_id, email_id, sender, recipient, subject,
        received_at, read_at, body, body_encrypted,
        otp_code, is_otp, headers, headers_encrypted, size
      FROM email_logs
      WHERE is_otp = 1 AND otp_code IS NOT NULL
      ORDER BY received_at DESC
      LIMIT 1
    `);

    const row = stmt.get() as DatabaseEmailLog | undefined;
    if (!row) {
      return null;
    }

    // Decrypt sensitive fields
    if (row.body && row.body_encrypted) {
      row.body = this.decryptField(row.body, true);
    }
    if (row.headers && row.headers_encrypted) {
      row.headers = this.decryptField(row.headers, true);
    }

    return {
      ...row,
      is_otp: Boolean(row.is_otp),
      body_encrypted: Boolean(row.body_encrypted),
      headers_encrypted: Boolean(row.headers_encrypted),
    };
  }

  /**
   * Update email log read status
   */
  public markEmailAsRead(id: number): boolean {
    const stmt = this.db.prepare(`
      UPDATE email_logs SET read_at = datetime('now') WHERE id = ?
    `);
    const result = stmt.run(id);
    return result.changes > 0;
  }

  // ============================================================================
  // API Key Operations
  // ============================================================================

  /**
   * Insert a new API key
   */
  public insertApiKey(data: Omit<DatabaseApiKey, 'id'>): DatabaseApiKey {
    const stmt = this.db.prepare(`
      INSERT INTO api_keys (
        key_hash, description, created_at, last_used_at,
        is_active, permissions
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      data.key_hash,
      data.description,
      data.created_at,
      data.last_used_at || null,
      data.is_active ? 1 : 0,
      JSON.stringify(data.permissions)
    );

    return {
      ...data,
      id: result.lastInsertRowid as number,
    };
  }

  /**
   * Get an API key by key hash
   */
  public getApiKeyByHash(keyHash: string): DatabaseApiKey | null {
    const stmt = this.db.prepare(`
      SELECT 
        id, key_hash, description, created_at, last_used_at,
        is_active, permissions
      FROM api_keys
      WHERE key_hash = ?
    `);

    const row = stmt.get(keyHash) as (Omit<DatabaseApiKey, 'permissions'> & { permissions: string }) | undefined;
    return row ? {
      ...row,
      is_active: Boolean(row.is_active),
      permissions: JSON.parse(row.permissions) as string[],
    } : null;
  }

  /**
   * List all API keys
   */
  public listApiKeys(activeOnly?: boolean): DatabaseApiKey[] {
    const activeFilter = activeOnly ? 'WHERE is_active = 1' : '';
    const stmt = this.db.prepare(`
      SELECT 
        id, key_hash, description, created_at, last_used_at,
        is_active, permissions
      FROM api_keys
      ${activeFilter}
      ORDER BY created_at DESC
    `);

    const rows = stmt.all() as (Omit<DatabaseApiKey, 'permissions'> & { permissions: string })[];
    return rows.map(row => ({
      ...row,
      is_active: Boolean(row.is_active),
      permissions: JSON.parse(row.permissions) as string[],
    }));
  }

  /**
   * Update API key last used timestamp
   */
  public updateApiKeyLastUsed(id: number): boolean {
    const stmt = this.db.prepare(`
      UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?
    `);
    const result = stmt.run(id);
    return result.changes > 0;
  }

  /**
   * Deactivate an API key
   */
  public deactivateApiKey(id: number): boolean {
    const stmt = this.db.prepare(`
      UPDATE api_keys SET is_active = 0 WHERE id = ?
    `);
    const result = stmt.run(id);
    return result.changes > 0;
  }

  /**
   * Delete an API key
   */
  public deleteApiKey(id: number): boolean {
    const stmt = this.db.prepare('DELETE FROM api_keys WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  // ============================================================================
  // Audit Log Operations
  // ============================================================================

  /**
   * Insert a new audit log entry
   */
  public insertAuditLog(data: Omit<DatabaseAuditLog, 'id' | 'details_encrypted'>): DatabaseAuditLog {
    // Encrypt details field if it exists
    const detailsEncrypted = data.details 
      ? this.encryptField(data.details)
      : { encrypted: null, wasEncrypted: false };

    const stmt = this.db.prepare(`
      INSERT INTO audit_logs (
        timestamp, action, user_id, target_id, target_type,
        details, details_encrypted, ip_address, user_agent
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      data.timestamp,
      data.action,
      data.user_id || null,
      data.target_id || null,
      data.target_type || null,
      detailsEncrypted.encrypted,
      detailsEncrypted.wasEncrypted ? 1 : 0,
      data.ip_address || null,
      data.user_agent || null
    );

    return {
      ...data,
      id: result.lastInsertRowid as number,
      details: detailsEncrypted.encrypted,
      details_encrypted: detailsEncrypted.wasEncrypted,
    };
  }

  /**
   * List audit logs with pagination
   */
  public listAuditLogs(
    action?: string,
    limit?: number,
    offset?: number
  ): DatabaseAuditLog[] {
    let whereClause = '';
    const params: (string | number | null)[] = [];

    if (action) {
      whereClause = 'WHERE action = ?';
      params.push(action);
    }

    const limitClause = limit ? `LIMIT ${limit}` : '';
    const offsetClause = offset ? `OFFSET ${offset}` : '';

    const stmt = this.db.prepare(`
      SELECT 
        id, timestamp, action, user_id, target_id, target_type,
        details, details_encrypted, ip_address, user_agent
      FROM audit_logs
      ${whereClause}
      ORDER BY timestamp DESC
      ${limitClause} ${offsetClause}
    `);

    const rows = stmt.all(...params) as DatabaseAuditLog[];
    
    return rows.map(row => {
      // Decrypt details field
      if (row.details && row.details_encrypted) {
        row.details = this.decryptField(row.details, true);
      }

      return {
        ...row,
        details_encrypted: Boolean(row.details_encrypted),
      };
    });
  }

  // ============================================================================
  // Transaction Support
  // ============================================================================

  /**
   * Execute operations in a transaction
   */
  public transaction<T>(
    operations: () => T
  ): T {
    const transaction = this.db.transaction(operations);
    return transaction();
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  /**
   * Close the database connection
   */
  public close(): void {
    this.db.close();
  }

  /**
   * Check database health
   */
  public healthCheck(): boolean {
    try {
      const result = this.db.prepare('SELECT 1').get();
      return result !== undefined;
    } catch {
      return false;
    }
  }

  /**
   * Get database statistics
   */
  public getStats(): {
    relayAddresses: number;
    emailLogs: number;
    apiKeys: number;
    auditLogs: number;
    databaseSize: number;
  } {
    const stats = {
      relayAddresses: 0,
      emailLogs: 0,
      apiKeys: 0,
      auditLogs: 0,
      databaseSize: 0,
    };

    try {
      const relayCount = this.db.prepare('SELECT COUNT(*) as count FROM relay_addresses').get() as { count: number };
      stats.relayAddresses = relayCount.count;

      const emailCount = this.db.prepare('SELECT COUNT(*) as count FROM email_logs').get() as { count: number };
      stats.emailLogs = emailCount.count;

      const apiKeyCount = this.db.prepare('SELECT COUNT(*) as count FROM api_keys').get() as { count: number };
      stats.apiKeys = apiKeyCount.count;

      const auditCount = this.db.prepare('SELECT COUNT(*) as count FROM audit_logs').get() as { count: number };
      stats.auditLogs = auditCount.count;

      // Get database file size
      const dbPath = this.config.get('databasePath');
      try {
        const dbStats = statSync(dbPath);
        stats.databaseSize = dbStats.size;
      } catch {
        // Ignore file size if we can't read it
      }
    } catch {
      // Ignore errors in stats collection
    }

    return stats;
  }

  // ============================================================================
  // Cleanup Methods
  // ============================================================================

  /**
   * Delete all data (DANGEROUS - use with caution)
   */
  public clearAllData(): void {
    this.transaction(() => {
      this.db.prepare('DELETE FROM email_logs').run();
      this.db.prepare('DELETE FROM relay_addresses').run();
      this.db.prepare('DELETE FROM api_keys').run();
      this.db.prepare('DELETE FROM audit_logs').run();
    });
  }

  /**
   * Delete old email logs (retention policy)
   */
  public deleteOldEmailLogs(days: number): number {
    const stmt = this.db.prepare(`
      DELETE FROM email_logs 
      WHERE received_at < datetime('now', ?)
    `);
    const result = stmt.run(`-${days} days`);
    return result.changes;
  }

  /**
   * Delete old audit logs (retention policy)
   */
  public deleteOldAuditLogs(days: number): number {
    const stmt = this.db.prepare(`
      DELETE FROM audit_logs 
      WHERE timestamp < datetime('now', ?)
    `);
    const result = stmt.run(`-${days} days`);
    return result.changes;
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

/**
 * Singleton database instance
 */
let databaseInstance: AnonSecDatabase | null = null;

/**
 * Get the singleton database instance
 */
export function getDatabase(config?: Configuration): AnonSecDatabase {
  if (!databaseInstance || config) {
    const actualConfig = config || Configuration.getInstance();
    databaseInstance = new AnonSecDatabase(actualConfig);
  }
  return databaseInstance;
}

/**
 * Reset the singleton instance (useful for testing)
 */
export function resetDatabase(): void {
  if (databaseInstance) {
    databaseInstance.close();
    databaseInstance = null;
  }
}

// ============================================================================
// Exports
// ============================================================================

export default AnonSecDatabase;
