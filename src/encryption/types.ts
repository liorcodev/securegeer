/**
 * Type definitions for encryption utilities
 */

/**
 * Encrypted string format: "salt:iv:ciphertext"
 * All parts are base64url encoded
 */
export type EncryptedString = string & { readonly __brand: 'EncryptedString' };

/**
 * Encryption secret (256-bit recommended)
 */
export type EncryptionSecret = string;

/**
 * Options for encryption operations
 */
export interface EncryptOptions {
  /**
   * Optional metadata to include in the encryption
   * This is authenticated but not encrypted
   * @experimental Not yet implemented
   */
  metadata?: Record<string, string>;
}

/**
 * Options for decryption operations
 */
export interface DecryptOptions {
  /**
   * Maximum age in milliseconds
   * If provided, will check if encryption timestamp is within this range
   * @experimental Not yet implemented
   */
  maxAge?: number;
}

/**
 * Result from encryption with metadata
 */
export interface EncryptionResult {
  ciphertext: EncryptedString;
  metadata?: Record<string, string>;
}
