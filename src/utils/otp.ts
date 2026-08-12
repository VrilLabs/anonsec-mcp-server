/**
 * OTP Extraction Utilities Module
 * 
 * Provides comprehensive OTP (One-Time Password) extraction from email content
 * with support for various formats, providers, and confidence scoring.
 * 
 * Follows golden-standard programming practices for maximal reliability
 * and accuracy in OTP extraction.
 */

import { OtpExtractionResult, SECURITY_CONSTANTS } from '../types';

// ============================================================================
// Constants
// ============================================================================

/**
 * Known OTP providers and their patterns
 */
const OTP_PROVIDERS = {
  // Common patterns for various services
  GOOGLE: {
    patterns: [
      // Google verification codes
      /Google\s+verification\s+code:\s*(\d{6})/i,
      /Your\s+Google\s+verification\s+code\s+is:\s*(\d{6})/i,
      /Google\s+code:\s*(\d{6})/i,
      // Gmail verification
      /Gmail\s+verification\s+code:\s*(\d{6})/i,
      /Your\s+Gmail\s+code\s+is:\s*(\d{6})/i,
    ],
    codeLength: 6,
    providerName: 'Google',
  },

  GITHUB: {
    patterns: [
      /GitHub\s+OTP:\s*(\d{6})/i,
      /Your\s+GitHub\s+verification\s+code:\s*(\d{6})/i,
      /GitHub\s+verification\s+code:\s*(\d{6})/i,
    ],
    codeLength: 6,
    providerName: 'GitHub',
  },

  AWS: {
    patterns: [
      /AWS\s+MFA\s+code:\s*(\d{6})/i,
      /Amazon\s+Web\s+Services\s+verification:\s*(\d{6})/i,
      /AWS\s+verification\s+code:\s*(\d{6})/i,
    ],
    codeLength: 6,
    providerName: 'AWS',
  },

  MICROSOFT: {
    patterns: [
      /Microsoft\s+verification\s+code:\s*(\d{6})/i,
      /Your\s+Microsoft\s+account\s+code:\s*(\d{6})/i,
      /Outlook\s+verification\s+code:\s*(\d{6})/i,
    ],
    codeLength: 6,
    providerName: 'Microsoft',
  },

  APPLE: {
    patterns: [
      /Apple\s+ID\s+verification\s+code:\s*(\d{6})/i,
      /Your\s+Apple\s+verification\s+code\s+is:\s*(\d{6})/i,
      /iCloud\s+verification\s+code:\s*(\d{6})/i,
    ],
    codeLength: 6,
    providerName: 'Apple',
  },

  FACEBOOK: {
    patterns: [
      /Facebook\s+login\s+code:\s*(\d{6})/i,
      /Your\s+Facebook\s+verification\s+code:\s*(\d{6})/i,
      /Meta\s+verification\s+code:\s*(\d{6})/i,
    ],
    codeLength: 6,
    providerName: 'Facebook',
  },

  TWITTER: {
    patterns: [
      /Twitter\s+verification\s+code:\s*(\d{6})/i,
      /Your\s+Twitter\s+login\s+code:\s*(\d{6})/i,
      /X\s+verification\s+code:\s*(\d{6})/i,
    ],
    codeLength: 6,
    providerName: 'Twitter/X',
  },

  SLACK: {
    patterns: [
      /Slack\s+verification\s+code:\s*(\d{6})/i,
      /Your\s+Slack\s+code:\s*(\d{6})/i,
    ],
    codeLength: 6,
    providerName: 'Slack',
  },

  DISCORD: {
    patterns: [
      /Discord\s+verification\s+code:\s*(\d{6})/i,
      /Your\s+Discord\s+backup\s+code:\s*(\d{6})/i,
    ],
    codeLength: 6,
    providerName: 'Discord',
  },

  LINKEDIN: {
    patterns: [
      /LinkedIn\s+verification\s+code:\s*(\d{6})/i,
      /Your\s+LinkedIn\s+security\s+code:\s*(\d{6})/i,
    ],
    codeLength: 6,
    providerName: 'LinkedIn',
  },

  // Generic patterns
  GENERIC: {
    patterns: [
      // Common OTP patterns
      /verification\s+code:\s*(\d{4,8})/i,
      /OTP:\s*(\d{4,8})/i,
      /one-time\s+password:\s*(\d{4,8})/i,
      /authentication\s+code:\s*(\d{4,8})/i,
      /security\s+code:\s*(\d{4,8})/i,
      /login\s+code:\s*(\d{4,8})/i,
      /access\s+code:\s*(\d{4,8})/i,
      // Patterns in different formats
      /Your\s+code\s+is:\s*(\d{4,8})/i,
      /Here's\s+your\s+code:\s*(\d{4,8})/i,
      /Code:\s*(\d{4,8})/i,
      // 2FA codes
      /2FA\s+code:\s*(\d{4,8})/i,
      /two-factor\s+code:\s*(\d{4,8})/i,
      /MFA\s+code:\s*(\d{4,8})/i,
    ],
    codeLength: [4, 6, 8],
    providerName: null,
  },

  // Alphanumeric codes
  ALPHANUMERIC: {
    patterns: [
      /verification\s+code:\s*([A-Z0-9]{4,10})/i,
      /OTP:\s*([A-Z0-9]{4,10})/i,
      /code:\s*([A-Z0-9]{4,10})/i,
    ],
    codeLength: [4, 6, 8, 10],
    providerName: null,
    codeType: 'alphanumeric',
  },
} as const;

/**
 * Expiration patterns for OTP codes
 */
const EXPIRATION_PATTERNS = [
  /expires\s+(?:in|after)\s+(\d+)\s*(?:seconds?|sec|s|minutes?|min|m|hours?|hrs|h|days?|d)/i,
  /valid\s+(?:for|until)\s+(\d+:\d+(?::\d+)?)\s*(?:UTC|GMT|EST|PST)?/i,
  /expires\s+at\s+([\dT:\s-]+Z?)/i,
  /expires\s+([\d/]+\s+[\d:]+\s*(?:AM|PM)?)/i,
];

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Normalize text by removing HTML tags, extra whitespace, and normalizing line breaks
 */
function normalizeText(text: string): string {
  // Remove HTML tags
  let normalized = text.replace(/<[^>]*>/g, ' ');
  
  // Replace multiple spaces with single space
  normalized = normalized.replace(/\s+/g, ' ');
  
  // Trim whitespace
  normalized = normalized.trim();
  
  return normalized;
}

/**
 * Clean OTP code by removing non-digit or non-alphanumeric characters
 */
function cleanCode(code: string): string {
  // For numeric codes
  const numericCode = code.replace(/\D/g, '');
  if (numericCode.length >= 4) {
    return numericCode;
  }
  
  // For alphanumeric codes
  const alphaNumCode = code.replace(/[^A-Z0-9]/gi, '').toUpperCase();
  if (alphaNumCode.length >= 4) {
    return alphaNumCode;
  }
  
  return code;
}

/**
 * Parse expiration information from text
 */
function parseExpiration(text: string): { expiresAt: string | null; ttlSeconds: number | null } {
  const normalized = normalizeText(text);
  
  for (const pattern of EXPIRATION_PATTERNS) {
    const match = normalized.match(pattern);
    if (match) {
      // Try to parse as ISO date
      if (match[1]?.includes('T') || match[1]?.includes('-')) {
        const date = new Date(match[1]);
        if (!isNaN(date.getTime())) {
          return {
            expiresAt: date.toISOString(),
            ttlSeconds: Math.floor((date.getTime() - Date.now()) / 1000),
          };
        }
      }
      
      // Try to parse as time duration
      const durationMatch = normalized.match(/(\d+)\s*(seconds?|sec|s|minutes?|min|m|hours?|hrs|h|days?|d)/i);
      if (durationMatch) {
        const value = parseInt(durationMatch[1], 10);
        const unit = durationMatch[2].toLowerCase();
        
        let seconds = value;
        if (unit.includes('min')) seconds *= 60;
        else if (unit.includes('hour')) seconds *= 3600;
        else if (unit.includes('day')) seconds *= 86400;
        
        return {
          expiresAt: new Date(Date.now() + seconds * 1000).toISOString(),
          ttlSeconds: seconds,
        };
      }
    }
  }
  
  return { expiresAt: null, ttlSeconds: null };
}

/**
 * Calculate confidence score based on various factors
 */
function calculateConfidence(
  provider: string | null,
  codeLength: number,
  patternMatches: number,
  codePosition: number,
  textLength: number
): number {
  let confidence = 0.5; // Base confidence
  
  // Provider match increases confidence
  if (provider) {
    confidence += 0.2;
  }
  
  // Standard code lengths (6 digits) increase confidence
  if (codeLength === 6) {
    confidence += 0.15;
  } else if (codeLength === 4 || codeLength === 8) {
    confidence += 0.1;
  }
  
  // Multiple pattern matches increase confidence
  confidence += Math.min(patternMatches * 0.05, 0.15);
  
  // Codes found early in the text are more likely to be the actual OTP
  const positionScore = 1 - Math.min(codePosition / textLength, 0.5);
  confidence += positionScore * 0.1;
  
  // Ensure confidence is between 0 and 1
  return Math.min(Math.max(confidence, 0), 1);
}

// ============================================================================
// Main OTP Extraction Functions
// ============================================================================

/**
 * Extract OTP codes from text using regex patterns
 */
function extractCodesFromText(
  text: string,
  providerPatterns?: typeof OTP_PROVIDERS[keyof typeof OTP_PROVIDERS]
): { code: string; provider: string | null; type: string; patternIndex: number }[] {
  const results: { code: string; provider: string | null; type: string; patternIndex: number }[] = [];
  
  const normalized = normalizeText(text);
  const patterns = providerPatterns ? [providerPatterns] : Object.values(OTP_PROVIDERS);
  
  for (const patternInfo of patterns) {
    const { patterns: regexPatterns, providerName, codeType = 'numeric' } = patternInfo;
    
    for (let i = 0; i < regexPatterns.length; i++) {
      const regex = regexPatterns[i];
      const match = normalized.match(regex);
      
      if (match) {
        const code = cleanCode(match[1]);
        
        // Skip if code is too short
        if (code.length < 4) continue;
        
        // Validate code length if specified
        const validLengths = Array.isArray(codeType) 
          ? codeType.map(l => typeof l === 'number' ? l : parseInt(l, 10))
          : [typeof codeType === 'number' ? codeType : parseInt(codeType, 10)];
        
        if (!validLengths.includes(code.length) && codeType === 'numeric') {
          // For alphanumeric, accept broader range
          if (codeType === 'numeric' && !/^\d+$/.test(code)) continue;
        }
        
        results.push({
          code,
          provider: providerName,
          type: codeType,
          patternIndex: i,
        });
      }
    }
  }
  
  return results;
}

/**
 * Extract all potential OTP codes from email content
 */
function extractAllPotentialCodes(text: string): OtpExtractionResult[] {
  const results: OtpExtractionResult[] = [];
  
  // Extract codes from known providers
  for (const [providerName, patternInfo] of Object.entries(OTP_PROVIDERS)) {
    if (providerName === 'GENERIC' || providerName === 'ALPHANUMERIC') continue;
    
    const codes = extractCodesFromText(text, patternInfo);
    
    for (const { code, type } of codes) {
      const { expiresAt, ttlSeconds } = parseExpiration(text);
      const confidence = calculateConfidence(
        patternInfo.providerName,
        code.length,
        1,
        text.indexOf(code),
        text.length
      );
      
      results.push({
        code,
        provider: patternInfo.providerName,
        type,
        expiresAt,
        confidence,
      });
    }
  }
  
  // Extract generic codes
  const genericCodes = extractCodesFromText(text, OTP_PROVIDERS.GENERIC);
  for (const { code, type } of genericCodes) {
    // Avoid duplicates
    if (results.some(r => r.code === code)) continue;
    
    const { expiresAt, ttlSeconds } = parseExpiration(text);
    const confidence = calculateConfidence(
      null,
      code.length,
      1,
      text.indexOf(code),
      text.length
    );
    
    results.push({
      code,
      provider: null,
      type,
      expiresAt,
      confidence,
    });
  }
  
  // Extract alphanumeric codes
  const alphaNumCodes = extractCodesFromText(text, OTP_PROVIDERS.ALPHANUMERIC);
  for (const { code, type } of alphaNumCodes) {
    // Avoid duplicates
    if (results.some(r => r.code === code)) continue;
    
    const { expiresAt, ttlSeconds } = parseExpiration(text);
    const confidence = calculateConfidence(
      null,
      code.length,
      1,
      text.indexOf(code),
      text.length
    );
    
    results.push({
      code,
      provider: null,
      type,
      expiresAt,
      confidence,
    });
  }
  
  return results;
}

/**
 * Find OTP using the default pattern from types
 */
function findOtpWithDefaultPattern(text: string): OtpExtractionResult[] {
  const results: OtpExtractionResult[] = [];
  const normalized = normalizeText(text);
  const otpPattern = SECURITY_CONSTANTS.OTP_PATTERN;
  
  const matches = normalized.match(otpPattern);
  if (matches) {
    for (const code of matches) {
      const { expiresAt } = parseExpiration(text);
      
      results.push({
        code,
        provider: null,
        type: /^\d+$/.test(code) ? 'numeric' : 'alphanumeric',
        expiresAt,
        confidence: 0.7,
      });
    }
  }
  
  return results;
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Extract OTP code from email body or text content
 * 
 * This function intelligently searches for OTP codes using multiple strategies:
 * - Known provider patterns (Google, GitHub, AWS, etc.)
 * - Generic OTP patterns
 * - Alphanumeric code patterns
 * - Default regex pattern from security constants
 * 
 * @param text - The email body or text to search
 * @param options - Extraction options
 * @returns Array of OTP extraction results, sorted by confidence
 */
export function extractOtpFromText(
  text: string,
  options: {
    preferProvider?: string;
    minConfidence?: number;
    returnAll?: boolean;
  } = {}
): OtpExtractionResult[] {
  if (!text || typeof text !== 'string') {
    return [];
  }
  
  const normalized = normalizeText(text);
  const { preferProvider, minConfidence = 0, returnAll = false } = options;
  
  // Combine all extraction methods
  const allResults = [
    ...extractAllPotentialCodes(normalized),
    ...findOtpWithDefaultPattern(normalized),
  ];
  
  // Filter by minimum confidence
  const filtered = allResults.filter(r => r.confidence >= minConfidence);
  
  // Sort by confidence (descending)
  filtered.sort((a, b) => b.confidence - a.confidence);
  
  // If preferProvider is specified, prioritize those results
  if (preferProvider) {
    filtered.sort((a, b) => {
      const aPriority = a.provider?.toLowerCase() === preferProvider.toLowerCase() ? 1 : 0;
      const bPriority = b.provider?.toLowerCase() === preferProvider.toLowerCase() ? 1 : 0;
      return bPriority - aPriority || b.confidence - a.confidence;
    });
  }
  
  // Remove duplicates (same code)
  const uniqueResults: OtpExtractionResult[] = [];
  const seenCodes = new Set<string>();
  
  for (const result of filtered) {
    if (!seenCodes.has(result.code)) {
      seenCodes.add(result.code);
      uniqueResults.push(result);
    }
  }
  
  // Return only the top result unless returnAll is true
  if (!returnAll && uniqueResults.length > 0) {
    return [uniqueResults[0]];
  }
  
  return uniqueResults;
}

/**
 * Extract the most likely OTP code from email content
 * 
 * @param text - The email body or text to search
 * @returns The highest confidence OTP result, or null if none found
 */
export function extractOtp(text: string): OtpExtractionResult | null {
  const results = extractOtpFromText(text, { minConfidence: 0.3 });
  return results.length > 0 ? results[0] : null;
}

/**
 * Extract OTP code specifically from HTML email content
 * 
 * @param html - HTML content to search
 * @returns The highest confidence OTP result, or null if none found
 */
export function extractOtpFromHtml(html: string): OtpExtractionResult | null {
  // Convert HTML to plain text by stripping tags
  const text = html.replace(/<[^>]*>/g, ' ');
  return extractOtp(text);
}

/**
 * Extract OTP from email subject line
 * 
 * @param subject - Email subject to search
 * @returns The highest confidence OTP result, or null if none found
 */
export function extractOtpFromSubject(subject: string): OtpExtractionResult | null {
  return extractOtp(subject);
}

/**
 * Validate that a code looks like a valid OTP
 * 
 * @param code - The code to validate
 * @returns True if the code appears to be a valid OTP
 */
export function isValidOtpCode(code: string): boolean {
  if (!code || typeof code !== 'string') {
    return false;
  }
  
  const clean = cleanCode(code);
  
  // Must be at least 4 characters
  if (clean.length < 4) {
    return false;
  }
  
  // Must be all digits or all alphanumeric
  if (!/^[\d]+$/.test(clean) && !/^[A-Z0-9]+$/i.test(clean)) {
    return false;
  }
  
  // Common OTP lengths
  const validLengths = [4, 5, 6, 7, 8, 10];
  if (!validLengths.includes(clean.length)) {
    // Allow slightly longer codes for some services
    if (clean.length > 10) {
      return false;
    }
  }
  
  return true;
}

/**
 * Extract OTP from structured email data
 * 
 * @param email - Email content object
 * @returns The highest confidence OTP result, or null if none found
 */
export function extractOtpFromEmail(email: { subject?: string; body?: string; html?: string }): OtpExtractionResult | null {
  // Try subject first
  if (email.subject) {
    const otp = extractOtpFromSubject(email.subject);
    if (otp) return otp;
  }
  
  // Try HTML body
  if (email.html) {
    const otp = extractOtpFromHtml(email.html);
    if (otp) return otp;
  }
  
  // Try plain text body
  if (email.body) {
    const otp = extractOtp(email.body);
    if (otp) return otp;
  }
  
  return null;
}

// ============================================================================
// Provider-Specific Extraction
// ============================================================================

/**
 * Extract OTP code from Google verification emails
 */
export function extractGoogleOtp(text: string): OtpExtractionResult | null {
  const results = extractOtpFromText(text, { preferProvider: 'Google' });
  return results.find(r => r.provider?.toLowerCase().includes('google')) || results[0] || null;
}

/**
 * Extract OTP code from GitHub verification emails
 */
export function extractGithubOtp(text: string): OtpExtractionResult | null {
  const results = extractOtpFromText(text, { preferProvider: 'GitHub' });
  return results.find(r => r.provider?.toLowerCase().includes('github')) || results[0] || null;
}

/**
 * Extract OTP code from AWS verification emails
 */
export function extractAwsOtp(text: string): OtpExtractionResult | null {
  const results = extractOtpFromText(text, { preferProvider: 'AWS' });
  return results.find(r => r.provider?.toLowerCase().includes('aws')) || results[0] || null;
}

/**
 * Extract OTP code from Microsoft verification emails
 */
export function extractMicrosoftOtp(text: string): OtpExtractionResult | null {
  const results = extractOtpFromText(text, { preferProvider: 'Microsoft' });
  return results.find(r => r.provider?.toLowerCase().includes('microsoft')) || results[0] || null;
}

/**
 * Extract OTP code from Apple verification emails
 */
export function extractAppleOtp(text: string): OtpExtractionResult | null {
  const results = extractOtpFromText(text, { preferProvider: 'Apple' });
  return results.find(r => r.provider?.toLowerCase().includes('apple')) || results[0] || null;
}

// ============================================================================
// Batch Extraction
// ============================================================================

/**
 * Extract OTP codes from multiple text sources
 * 
 * @param texts - Array of text strings to search
 * @returns Array of unique OTP results from all sources
 */
export function extractOtpFromMultiple(texts: string[]): OtpExtractionResult[] {
  const allResults: OtpExtractionResult[] = [];
  const seenCodes = new Set<string>();
  
  for (const text of texts) {
    const results = extractOtpFromText(text, { returnAll: true });
    
    for (const result of results) {
      if (result.code && !seenCodes.has(result.code)) {
        seenCodes.add(result.code);
        allResults.push(result);
      }
    }
  }
  
  return allResults;
}

// ============================================================================
// Exports
// ============================================================================

export {
  OTP_PROVIDERS,
  EXPIRATION_PATTERNS,
  normalizeText,
  cleanCode,
  parseExpiration,
  calculateConfidence,
  extractCodesFromText,
  extractAllPotentialCodes,
  findOtpWithDefaultPattern,
};

export default {
  extractOtp,
  extractOtpFromText,
  extractOtpFromHtml,
  extractOtpFromSubject,
  extractOtpFromEmail,
  isValidOtpCode,
  extractGoogleOtp,
  extractGithubOtp,
  extractAwsOtp,
  extractMicrosoftOtp,
  extractAppleOtp,
  extractOtpFromMultiple,
};
