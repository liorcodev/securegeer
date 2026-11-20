/**
 * HMAC sign / verify using the Web Crypto API
 *
 * Signatures are returned base64url encoded (no padding).
 *
 * @example
 * ```ts
 * import { hmacSign, hmacVerify } from 'securegeer/hmac';
 *
 * const signature = await hmacSign('payload', 'my-secret');
 * const ok = await hmacVerify('payload', signature, 'my-secret'); // true
 * ```
 */

import { fromBase64Url, toBase64Url } from '../shared/base64url.js';

export type HmacAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';

const importKey = (secret: string, algorithm: HmacAlgorithm): Promise<CryptoKey> =>
  crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: algorithm },
    false,
    ['sign', 'verify']
  );

/**
 * Sign a message with HMAC
 *
 * @param message - The message to sign
 * @param secret - The HMAC secret
 * @param algorithm - Hash algorithm (default: SHA-256)
 * @returns base64url encoded signature
 */
export const hmacSign = async (
  message: string,
  secret: string,
  algorithm: HmacAlgorithm = 'SHA-256'
): Promise<string> => {
  const key = await importKey(secret, algorithm);
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return toBase64Url(new Uint8Array(signature));
};

/**
 * Verify an HMAC signature (constant-time comparison via Web Crypto)
 *
 * @param message - The signed message
 * @param signature - base64url encoded signature
 * @param secret - The HMAC secret
 * @param algorithm - Hash algorithm (default: SHA-256)
 * @returns True if the signature is valid; false if invalid or malformed
 */
export const hmacVerify = async (
  message: string,
  signature: string,
  secret: string,
  algorithm: HmacAlgorithm = 'SHA-256'
): Promise<boolean> => {
  try {
    const key = await importKey(secret, algorithm);
    return await crypto.subtle.verify(
      'HMAC',
      key,
      fromBase64Url(signature),
      new TextEncoder().encode(message)
    );
  } catch {
    return false;
  }
};
