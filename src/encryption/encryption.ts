/**
 * High-Performance Encryption/Decryption
 *
 * - Web Crypto API (native performance)
 * - AES-256-GCM for authenticated encryption (encryption + integrity in one pass)
 * - A fresh key per message: HKDF-SHA256(secret, random 16-byte salt)
 *
 * Format: `salt:iv:ciphertext` (all parts base64url encoded)
 *
 * The secret must be high-entropy (>= 32 characters, e.g. from `generateSecret()`): HKDF is
 * fast but does not slow down brute-force attacks on weak, human-chosen secrets.
 *
 * @example
 * ```ts
 * const secret = generateSecret();
 * const encrypted = await encrypt('secret data', secret);
 * // "c2FsdC4uLg:aXYuLi4:Y2lwaGVy..."
 * const decrypted = await decrypt(encrypted, secret);
 * // "secret data"
 * ```
 */

import { fromBase64Url, toBase64Url } from '../shared/base64url.js';
import {
  AuthenticationFailedError,
  DecryptionError,
  EncryptionError,
  InvalidCiphertextError,
  InvalidKeyError
} from './errors.js';

const AES_KEY_LENGTH = 256;
const IV_LENGTH = 12; // 96 bits - recommended for AES-GCM
const SALT_LENGTH = 16;
const ALGORITHM = 'AES-GCM';
const MIN_SECRET_LENGTH = 32;
const HKDF_INFO = new TextEncoder().encode('securegeer-aes-256-gcm-v1');

const assertSecret = (secret: string): void => {
  if (secret.trim().length < MIN_SECRET_LENGTH) {
    throw new InvalidKeyError(`Secret must be at least ${MIN_SECRET_LENGTH} characters long`);
  }
};

/**
 * Derive a unique AES key for one message using HKDF-SHA256
 */
const deriveKey = async (secret: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> => {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    'HKDF',
    false,
    ['deriveKey']
  );

  return await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: HKDF_INFO },
    keyMaterial,
    { name: ALGORITHM, length: AES_KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
};

/**
 * Encrypt data using AES-256-GCM
 *
 * Every call generates a random salt and IV, so each message gets its own key.
 *
 * @param data - The data to encrypt (string or object - will be JSON stringified)
 * @param secret - The encryption secret (high-entropy, at least 32 characters)
 * @returns Encrypted string in format `salt:iv:ciphertext` (base64url encoded)
 * @throws {InvalidKeyError} If the secret is shorter than 32 characters
 * @throws {EncryptionError} If encryption fails
 *
 * @example
 * ```ts
 * const encrypted = await encrypt({ userId: 123 }, generateSecret());
 * ```
 */
export const encrypt = async (data: string | object, secret: string): Promise<string> => {
  assertSecret(secret);

  try {
    const plaintext = typeof data === 'string' ? data : JSON.stringify(data);
    const plaintextBytes = new TextEncoder().encode(plaintext);

    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

    const key = await deriveKey(secret, salt);

    const ciphertextBuffer = await crypto.subtle.encrypt(
      { name: ALGORITHM, iv },
      key,
      plaintextBytes
    );

    return `${toBase64Url(salt)}:${toBase64Url(iv)}:${toBase64Url(new Uint8Array(ciphertextBuffer))}`;
  } catch (error) {
    throw new EncryptionError(error instanceof Error ? error.message : 'Encryption failed');
  }
};

/**
 * Decrypt data using AES-256-GCM
 *
 * @param ciphertext - The encrypted string in format `salt:iv:ciphertext`
 * @param secret - The encryption secret used for encryption
 * @returns Decrypted string
 * @throws {InvalidCiphertextError} If the ciphertext format is invalid
 * @throws {InvalidKeyError} If the secret is shorter than 32 characters
 * @throws {AuthenticationFailedError} If authentication fails (wrong secret or tampered data)
 * @throws {DecryptionError} If decryption fails for other reasons
 *
 * @example
 * ```ts
 * const decrypted = await decrypt(encrypted, secret);
 * ```
 */
export const decrypt = async (ciphertext: string, secret: string): Promise<string> => {
  const parts = ciphertext.split(':');
  if (parts.length !== 3) {
    throw new InvalidCiphertextError();
  }
  assertSecret(secret);

  const [saltStr, ivStr, ciphertextStr] = parts as [string, string, string];

  try {
    const key = await deriveKey(secret, fromBase64Url(saltStr));

    const plaintextBuffer = await crypto.subtle.decrypt(
      { name: ALGORITHM, iv: fromBase64Url(ivStr) },
      key,
      fromBase64Url(ciphertextStr)
    );

    return new TextDecoder().decode(plaintextBuffer);
  } catch (error) {
    // AES-GCM will throw on authentication failure
    if (error instanceof Error && error.name === 'OperationError') {
      throw new AuthenticationFailedError();
    }
    throw new DecryptionError(error instanceof Error ? error.message : 'Decryption failed');
  }
};

/**
 * Decrypt and parse JSON data
 *
 * Convenience function for decrypting objects that were encrypted
 *
 * @param ciphertext - The encrypted string
 * @param secret - The encryption secret
 * @returns Parsed JSON object
 * @throws {InvalidKeyError} If the secret is shorter than 32 characters
 * @throws {DecryptionError} If decryption or JSON parsing fails
 *
 * @example
 * ```ts
 * const me = await decryptJSON<{ userId: number }>(encrypted, secret);
 * console.log(me.userId);
 * ```
 */
export const decryptJSON = async <T = unknown>(ciphertext: string, secret: string): Promise<T> => {
  const decrypted = await decrypt(ciphertext, secret);
  try {
    return JSON.parse(decrypted) as T;
  } catch (error) {
    throw new DecryptionError('Failed to parse decrypted data as JSON');
  }
};

/**
 * Generate a random encryption secret
 *
 * Generates a cryptographically secure random string suitable for use as an encryption key.
 * The secret is 32 bytes (256 bits) encoded as base64url.
 *
 * @returns Random base64url string (32 bytes = 43 characters in base64url)
 *
 * @example
 * ```ts
 * const secret = generateSecret();
 * // Store this in your environment variables
 * ```
 */
export const generateSecret = (): string => {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return toBase64Url(bytes);
};
