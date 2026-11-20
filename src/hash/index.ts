/**
 * Password and token hashing using the Web Crypto API
 *
 * Password hashes are self-describing: `pbkdf2-sha256$iterations$salt$hash` (salt and hash in
 * hex), so verification always uses the parameters the hash was created with.
 *
 * @example
 * ```ts
 * import { hashPassword, verifyPasswordHash, sha256 } from 'securegeer/hash';
 * ```
 */

import { hmacSign } from '../hmac/index.js';

const SCHEME = 'pbkdf2-sha256';
const DEFAULT_ITERATIONS = 100000; // Cloudflare Workers' maximum for PBKDF2
const SALT_LENGTH = 16;
const HASH_BITS = 256;
const HASH_PATTERN = /^pbkdf2-sha256\$(\d+)\$([0-9a-f]{32})\$([0-9a-f]{64})$/;

export interface HashPasswordOptions {
  /** Number of PBKDF2 iterations (default: 100000) */
  iterations?: number;
  /**
   * Optional server-side secret mixed into the password (HMAC-SHA256) before hashing.
   * It is not stored with the hash and must be passed to `verifyPasswordHash` as well:
   * losing or changing it makes every hash created with it unverifiable.
   */
  pepper?: string;
}

export interface VerifyPasswordOptions {
  /** The pepper used when the hash was created, if any */
  pepper?: string;
}

/**
 * Converts a byte array to a hexadecimal string
 */
const toHex = (bytes: Uint8Array): string => {
  const hexChars = '0123456789abcdef';
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i] as number;
    hex += (hexChars[byte >> 4] as string) + hexChars[byte & 0x0f];
  }
  return hex;
};

/**
 * Converts a validated, even-length hexadecimal string to a byte array
 */
const fromHex = (hex: string): Uint8Array<ArrayBuffer> => {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
};

/**
 * Compares two equal-length hex strings in constant time to avoid leaking
 * information via response-time differences. Cheap (single pass over ~64
 * chars) so it adds no meaningful CPU cost on a Worker's limited CPU budget.
 */
const timingSafeEqual = (a: string, b: string): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
};

const derive = async (
  password: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number,
  pepper: string | undefined
): Promise<string> => {
  if (pepper !== undefined && pepper.length === 0) {
    throw new Error('Pepper must not be empty');
  }
  const input = pepper === undefined ? password : await hmacSign(password, pepper);

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(input),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    HASH_BITS
  );
  return toHex(new Uint8Array(bits));
};

/**
 * Hashes a password using PBKDF2 with SHA-256 and a random salt
 *
 * @param password - The password to hash
 * @param options - Optional iterations and pepper
 * @returns Hash string in format `pbkdf2-sha256$iterations$salt$hash`
 *
 * @example
 * ```ts
 * const hashed = await hashPassword('password');
 * // "pbkdf2-sha256$100000$a1b2c3d4...$e5f6g7h8..."
 * ```
 */
export const hashPassword = async (
  password: string,
  options?: HashPasswordOptions
): Promise<string> => {
  const iterations = options?.iterations ?? DEFAULT_ITERATIONS;
  if (!Number.isSafeInteger(iterations) || iterations < 1) {
    throw new Error('Iterations must be a positive integer');
  }

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const hash = await derive(password, salt, iterations, options?.pepper);
  return `${SCHEME}$${iterations}$${toHex(salt)}$${hash}`;
};

/**
 * Verifies a password against a stored hash
 *
 * @param storedHash - The stored hash string in format `pbkdf2-sha256$iterations$salt$hash`
 * @param password - The password to verify
 * @param options - The pepper used when the hash was created, if any
 * @returns True if the password matches the hash
 * @throws {Error} If the stored hash is malformed
 *
 * @example
 * ```ts
 * const isValid = await verifyPasswordHash(storedHash, 'password');
 * ```
 */
export const verifyPasswordHash = async (
  storedHash: string,
  password: string,
  options?: VerifyPasswordOptions
): Promise<boolean> => {
  const match = HASH_PATTERN.exec(storedHash);
  if (!match) {
    throw new Error('Invalid hash format');
  }
  const [, iterationsStr, saltHex, originalHash] = match as unknown as [
    string,
    string,
    string,
    string
  ];
  const iterations = parseInt(iterationsStr, 10);
  if (!Number.isSafeInteger(iterations) || iterations < 1) {
    throw new Error('Invalid hash format');
  }

  const attemptHash = await derive(password, fromHex(saltHex), iterations, options?.pepper);
  return timingSafeEqual(attemptHash, originalHash);
};

/**
 * Hashes data using SHA-256 (fast, deterministic, no salt)
 *
 * Use this for high-entropy random values such as API tokens, where you need to look up the
 * hash in a database. The security comes from the value's randomness, not the hash.
 * Never use it for passwords: use `hashPassword` instead.
 *
 * @param data - The data to hash
 * @returns Hexadecimal hash string
 *
 * @example
 * ```ts
 * const tokenHash = await sha256('ex_abc123...');
 * // "e5f6g7h8a1b2c3d4..."
 * ```
 */
export const sha256 = async (data: string): Promise<string> => {
  const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
  return toHex(new Uint8Array(hashBuffer));
};
