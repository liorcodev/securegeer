/**
 * High-Performance Encryption Utilities
 *
 * Built on the Web Crypto API and AES-GCM. Works in Cloudflare Workers, Bun, Deno,
 * browsers and Node.js 18+.
 *
 * Simple usage:
 * ```ts
 * import { encrypt, decrypt } from 'securegeer/encryption';
 *
 * const encrypted = await encrypt('secret data', process.env.ENCRYPTION_KEY);
 * const decrypted = await decrypt(encrypted, process.env.ENCRYPTION_KEY);
 * ```
 *
 * Features:
 * - AES-256-GCM authenticated encryption
 * - Per-message random salt + HKDF-SHA256 key derivation (secrets must be >= 32 chars)
 * - Automatic JSON handling
 * - Key rotation support
 * - Type-safe
 */

// Core encryption functions
export { encrypt, decrypt, decryptJSON, generateSecret } from './encryption.js';

// Key rotation support
export {
  EncryptionKeyRotation,
  initKeyRotationFromEnv,
  generateNewSecret
} from './key-rotation.js';
export type { KeyRotationConfig } from './key-rotation.js';
export { EncryptionWithRotation } from './encryption-with-rotation.js';

// Types
export type {
  EncryptedString,
  EncryptionSecret,
  EncryptOptions,
  DecryptOptions,
  EncryptionResult
} from './types.js';

// All errors
export * from './errors.js';
