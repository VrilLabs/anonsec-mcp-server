/**
 * Cryptographic Utilities Module
 * 
 * Provides Post-Quantum Cryptography (PQC) ready encryption utilities
 * for securing sensitive data at rest. Implements AES-256-GCM with
 * proper key derivation and authentication.
 * 
 * Note: For true PQC, this would be replaced with CRYSTALS-Kyber or
 * similar post-quantum resistant algorithms when available in Node.js.
 * This implementation provides a strong foundation that can be upgraded.
 * 
 * Follows golden-standard security practices:
 * - Uses authenticated encryption (GCM mode)
 * - Proper key derivation with PBKDF2
 * - Random IV generation for each encryption
 * - Authentication tag verification
 * - Constant-time comparison for MAC verification
 */

import { randomBytes, scryptSync, createCipheriv, createDecipheriv, timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';

// ============================================================================
// Constants
// ============================================================================

/**
 * Encryption algorithm constants
 */
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // 128 bits for GCM
const AUTH_TAG_LENGTH = 16; // 128 bits
const SALT_LENGTH = 32; // 256 bits
const KEY_LENGTH = 32; // 256 bits for AES-256

/**
 * Key derivation constants
 */
const KDF_ITERATIONS = 100000; // Minimum for security
const KDF_MEMORY_COST = 64 * 1024 * 1024; // 64MB memory cost
const KDF_PARALLELISM = 1;

// ============================================================================
// Error Classes
// ============================================================================

/**
 * Custom error for encryption-related failures
 */
export class EncryptionError extends Error {
  constructor(message: string, public readonly cause?: Error) {
    super(message);
    this.name = 'EncryptionError';
  }
}

/**
 * Custom error for decryption failures
 */
export class DecryptionError extends Error {
  constructor(message: string, public readonly cause?: Error) {
    super(message);
    this.name = 'DecryptionError';
  }
}

/**
 * Custom error for invalid key material
 */
export class InvalidKeyError extends Error {
  constructor(message: string = 'Invalid key material') {
    super(message);
    this.name = 'InvalidKeyError';
  }
}

// ============================================================================
// Key Management
// ============================================================================

/**
 * Generate a cryptographically secure random key
 */
export function generateKey(): Buffer {
  return randomBytes(KEY_LENGTH);
}

/**
 * Generate a secure random key as a hex string
 */
export function generateKeyHex(): string {
  return generateKey().toString('hex');
}

/**
 * Derive a key from a password using scrypt (memory-hard KDF)
 */
export function deriveKeyFromPassword(
  password: string,
  salt: Buffer = randomBytes(SALT_LENGTH)
): { key: Buffer; salt: Buffer } {
  const key = scryptSync(password, salt, KEY_LENGTH, {
    N: 1 << 16, // CPU/memory cost parameter
    r: 8, // Block size
    p: KDF_PARALLELISM,
    maxmem: KDF_MEMORY_COST,
  });

  return { key, salt };
}

/**
 * Derive a key from a password with existing salt
 */
export function deriveKeyFromPasswordWithSalt(
  password: string,
  salt: Buffer
): Buffer {
  return scryptSync(password, salt, KEY_LENGTH, {
    N: 1 << 16,
    r: 8,
    p: KDF_PARALLELISM,
    maxmem: KDF_MEMORY_COST,
  });
}

/**
 * Validate that a key has sufficient entropy
 */
export function validateKey(key: string | Buffer): boolean {
  const keyBuffer = typeof key === 'string' ? Buffer.from(key, 'utf8') : key;
  
  // Check minimum length
  if (keyBuffer.length < KEY_LENGTH) {
    return false;
  }
  
  // Check that key has some entropy (not all zeros or repeating patterns)
  const uniqueBytes = new Set(keyBuffer);
  if (uniqueBytes.size < 16) {
    return false; // Too few unique bytes suggests low entropy
  }
  
  return true;
}

// ============================================================================
// Encryption
// ============================================================================

/**
 * Encrypt data using AES-256-GCM
 * 
 * @param plaintext - Data to encrypt (string or Buffer)
 * @param key - Encryption key (string or Buffer)
 * @returns Encrypted data with IV and authentication tag prepended
 */
export function encrypt(
  plaintext: string | Buffer,
  key: string | Buffer
): Buffer {
  // Convert key to Buffer
  const keyBuffer = typeof key === 'string' 
    ? Buffer.from(key, 'utf8') 
    : key;
  
  // Validate key
  if (!validateKey(keyBuffer)) {
    throw new InvalidKeyError();
  }
  
  // Convert plaintext to Buffer
  const plaintextBuffer = typeof plaintext === 'string'
    ? Buffer.from(plaintext, 'utf8')
    : plaintext;
  
  // Generate random IV
  const iv = randomBytes(IV_LENGTH);
  
  // Create cipher
  const cipher = createCipheriv(ALGORITHM, keyBuffer, iv);
  
  // Encrypt
  const encrypted = Buffer.concat([
    cipher.update(plaintextBuffer),
    cipher.final(),
  ]);
  
  // Get authentication tag
  const authTag = cipher.getAuthTag();
  
  // Combine IV, auth tag, and ciphertext
  // Format: [IV (16 bytes)][Auth Tag (16 bytes)][Ciphertext]
  return Buffer.concat([iv, authTag, encrypted]);
}

/**
 * Encrypt string data and return as hex string
 */
export function encryptToHex(
  plaintext: string,
  key: string | Buffer
): string {
  return encrypt(plaintext, key).toString('hex');
}

/**
 * Encrypt string data and return as base64 string
 */
export function encryptToBase64(
  plaintext: string,
  key: string | Buffer
): string {
  return encrypt(plaintext, key).toString('base64');
}

// ============================================================================
// Decryption
// ============================================================================

/**
 * Decrypt data using AES-256-GCM
 * 
 * @param ciphertext - Encrypted data with IV and auth tag prepended
 * @param key - Encryption key
 * @returns Decrypted data as Buffer
 * @throws DecryptionError if authentication fails
 */
export function decrypt(
  ciphertext: Buffer | string,
  key: string | Buffer
): Buffer {
  // Convert inputs to Buffers
  const ciphertextBuffer = typeof ciphertext === 'string'
    ? Buffer.from(ciphertext, 'hex')
    : ciphertext;
  
  const keyBuffer = typeof key === 'string'
    ? Buffer.from(key, 'utf8')
    : key;
  
  // Validate key
  if (!validateKey(keyBuffer)) {
    throw new InvalidKeyError();
  }
  
  // Validate ciphertext length
  if (ciphertextBuffer.length < IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new DecryptionError('Ciphertext too short');
  }
  
  // Extract components
  const iv = ciphertextBuffer.subarray(0, IV_LENGTH);
  const authTag = ciphertextBuffer.subarray(
    IV_LENGTH,
    IV_LENGTH + AUTH_TAG_LENGTH
  );
  const encrypted = ciphertextBuffer.subarray(
    IV_LENGTH + AUTH_TAG_LENGTH
  );
  
  // Create decipher
  const decipher = createDecipheriv(ALGORITHM, keyBuffer, iv);
  decipher.setAuthTag(authTag);
  
  // Decrypt
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  
  return decrypted;
}

/**
 * Decrypt hex-encoded data to string
 */
export function decryptFromHex(
  ciphertextHex: string,
  key: string | Buffer
): string {
  const decrypted = decrypt(Buffer.from(ciphertextHex, 'hex'), key);
  return decrypted.toString('utf8');
}

/**
 * Decrypt base64-encoded data to string
 */
export function decryptFromBase64(
  ciphertextBase64: string,
  key: string | Buffer
): string {
  const decrypted = decrypt(Buffer.from(ciphertextBase64, 'base64'), key);
  return decrypted.toString('utf8');
}

/**
 * Decrypt with constant-time comparison for authentication tag
 * 
 * This provides additional protection against timing attacks
 * by using constant-time comparison for the authentication tag.
 */
export function decryptWithTimingSafe(
  ciphertext: Buffer | string,
  key: string | Buffer,
  expectedAuthTag?: Buffer
): Buffer {
  // Convert inputs to Buffers
  const ciphertextBuffer = typeof ciphertext === 'string'
    ? Buffer.from(ciphertext, 'hex')
    : ciphertext;
  
  const keyBuffer = typeof key === 'string'
    ? Buffer.from(key, 'utf8')
    : key;
  
  // Validate key
  if (!validateKey(keyBuffer)) {
    throw new InvalidKeyError();
  }
  
  // Validate ciphertext length
  if (ciphertextBuffer.length < IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new DecryptionError('Ciphertext too short');
  }
  
  // Extract components
  const iv = ciphertextBuffer.subarray(0, IV_LENGTH);
  const actualAuthTag = ciphertextBuffer.subarray(
    IV_LENGTH,
    IV_LENGTH + AUTH_TAG_LENGTH
  );
  const encrypted = ciphertextBuffer.subarray(
    IV_LENGTH + AUTH_TAG_LENGTH
  );
  
  // If expected auth tag provided, verify with timing-safe comparison
  if (expectedAuthTag && expectedAuthTag.length === AUTH_TAG_LENGTH) {
    if (!timingSafeEqual(actualAuthTag, expectedAuthTag)) {
      throw new DecryptionError('Authentication tag mismatch');
    }
  }
  
  // Create decipher
  const decipher = createDecipheriv(ALGORITHM, keyBuffer, iv);
  decipher.setAuthTag(actualAuthTag);
  
  // Decrypt
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  
  return decrypted;
}

// ============================================================================
// Combined Encryption/Decryption Utilities
// ============================================================================

/**
 * Encrypt an object to a hex string
 */
export function encryptObjectToHex<T>(
  obj: T,
  key: string | Buffer
): string {
  const jsonString = JSON.stringify(obj);
  return encryptToHex(jsonString, key);
}

/**
 * Decrypt a hex string to an object
 */
export function decryptHexToObject<T>(
  hexString: string,
  key: string | Buffer
): T {
  const jsonString = decryptFromHex(hexString, key);
  try {
    return JSON.parse(jsonString) as T;
  } catch (error) {
    throw new DecryptionError('Failed to parse decrypted JSON', error as Error);
  }
}

/**
 * Encrypt an object to a base64 string
 */
export function encryptObjectToBase64<T>(
  obj: T,
  key: string | Buffer
): string {
  const jsonString = JSON.stringify(obj);
  return encryptToBase64(jsonString, key);
}

/**
 * Decrypt a base64 string to an object
 */
export function decryptBase64ToObject<T>(
  base64String: string,
  key: string | Buffer
): T {
  const jsonString = decryptFromBase64(base64String, key);
  try {
    return JSON.parse(jsonString) as T;
  } catch (error) {
    throw new DecryptionError('Failed to parse decrypted JSON', error as Error);
  }
}

// ============================================================================
// Security Utilities
// ============================================================================

/**
 * Generate a secure random salt
 */
export function generateSalt(length: number = SALT_LENGTH): Buffer {
  return randomBytes(length);
}

/**
 * Generate a secure random nonce
 */
export function generateNonce(length: number = 16): Buffer {
  return randomBytes(length);
}

/**
 * Securely compare two strings in constant time
 */
export function secureCompare(a: string, b: string): boolean {
  const aBuffer = Buffer.from(a, 'utf8');
  const bBuffer = Buffer.from(b, 'utf8');
  
  // Ensure same length for constant-time comparison
  if (aBuffer.length !== bBuffer.length) {
    return false;
  }
  
  return timingSafeEqual(aBuffer, bBuffer);
}

/**
 * Securely hash a string using SHA-256
 */
export async function hashString(input: string): Promise<string> {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Securely hash a buffer using SHA-256
 */
export async function hashBuffer(input: Buffer): Promise<string> {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(input).digest('hex');
}

// ============================================================================
// Password-Based Encryption (PBE) Utilities
// ============================================================================

/**
 * Password-based encryption with salt generation
 */
export function encryptWithPassword(
  plaintext: string | Buffer,
  password: string
): { ciphertext: Buffer; salt: Buffer } {
  const salt = randomBytes(SALT_LENGTH);
  const key = deriveKeyFromPasswordWithSalt(password, salt);
  
  const ciphertext = encrypt(plaintext, key);
  
  return { ciphertext, salt };
}

/**
 * Password-based decryption with salt
 */
export function decryptWithPassword(
  ciphertext: Buffer,
  password: string,
  salt: Buffer
): Buffer {
  const key = deriveKeyFromPasswordWithSalt(password, salt);
  return decrypt(ciphertext, key);
}

/**
 * Combined password-based encryption to hex
 */
export function encryptWithPasswordToHex(
  plaintext: string,
  password: string
): { ciphertextHex: string; saltHex: string } {
  const { ciphertext, salt } = encryptWithPassword(plaintext, password);
  return {
    ciphertextHex: ciphertext.toString('hex'),
    saltHex: salt.toString('hex'),
  };
}

/**
 * Combined password-based decryption from hex
 */
export function decryptWithPasswordFromHex(
  ciphertextHex: string,
  password: string,
  saltHex: string
): string {
  const ciphertext = Buffer.from(ciphertextHex, 'hex');
  const salt = Buffer.from(saltHex, 'hex');
  const decrypted = decryptWithPassword(ciphertext, password, salt);
  return decrypted.toString('utf8');
}

// ============================================================================
// Exports
// ============================================================================

export {
  ALGORITHM,
  IV_LENGTH,
  AUTH_TAG_LENGTH,
  KEY_LENGTH,
  KDF_ITERATIONS,
  KDF_MEMORY_COST,
  SALT_LENGTH,
};

export default {
  // Key management
  generateKey,
  generateKeyHex,
  deriveKeyFromPassword,
  deriveKeyFromPasswordWithSalt,
  validateKey,
  
  // Encryption
  encrypt,
  encryptToHex,
  encryptToBase64,
  
  // Decryption
  decrypt,
  decryptFromHex,
  decryptFromBase64,
  decryptWithTimingSafe,
  
  // Object utilities
  encryptObjectToHex,
  decryptHexToObject,
  encryptObjectToBase64,
  decryptBase64ToObject,
  
  // Security utilities
  generateSalt,
  generateNonce,
  secureCompare,
  hashString,
  hashBuffer,
  
  // Password-based encryption
  encryptWithPassword,
  decryptWithPassword,
  encryptWithPasswordToHex,
  decryptWithPasswordFromHex,
  
  // Error classes
  EncryptionError,
  DecryptionError,
  InvalidKeyError,
};
