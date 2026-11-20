/**
 * JWT wrapper with automatic key rotation support
 * Simple integration layer for production use
 */

import { jwt, verifyJwt, decodeJwt } from './jwt.js';
import { JWTKeyRotation } from './key-rotation.js';
import type { JWTPayload, JWTSignOptions, JWTVerifyOptions } from './types.js';

export class JWTWithRotation {
  constructor(private keyRotation: JWTKeyRotation) {}

  /**
   * Sign a JWT with the current secret version
   */
  async sign<T = Record<string, unknown>>(
    payload: JWTPayload<T>,
    options: Omit<JWTSignOptions, 'keyId'>
  ): Promise<string> {
    const { secret, version } = this.keyRotation.getCurrentSecret();

    return jwt(payload, secret, {
      ...options,
      keyId: `v${version}` // Automatically add key version
    });
  }

  /**
   * Verify a JWT - automatically tries current and previous secrets
   */
  async verify<T = Record<string, unknown>>(
    token: string,
    options: JWTVerifyOptions
  ): Promise<JWTPayload<T>> {
    const validSecrets = this.keyRotation.getValidSecrets();

    // Try to decode first to get the key ID hint (if present)
    try {
      const { header } = decodeJwt(token);

      // If token has kid (key ID), try that version first
      if (header.kid) {
        const version = parseInt(header.kid.replace('v', ''), 10);
        const secretWithVersion = validSecrets.find(s => s.version === version);

        if (secretWithVersion && this.keyRotation.isVersionValid(version)) {
          try {
            return await verifyJwt<T>(token, secretWithVersion.secret, options);
          } catch {
            // Fall through to try all secrets
          }
        }
      }
    } catch {
      // If decode fails, fall through to try all secrets
    }

    // Try all valid secrets (current first, then older versions)
    let lastError: Error | null = null;

    for (const { secret } of validSecrets) {
      try {
        return await verifyJwt<T>(token, secret, options);
      } catch (error) {
        lastError = error as Error;
      }
    }

    // All secrets failed - throw the last error
    throw lastError || new Error('Token verification failed');
  }

  /**
   * Get current key version (useful for monitoring/logging)
   */
  getCurrentVersion(): number {
    return this.keyRotation.getCurrentSecret().version;
  }
}

/**
 * Example usage in a Cloudflare Worker
 *
 * import { initKeyRotationFromEnv, JWTWithRotation } from 'securegeer/jwt';
 *
 * export default {
 *   async fetch(request: Request, env: Env) {
 *     const keyRotation = initKeyRotationFromEnv(env);
 *     const jwtService = new JWTWithRotation(keyRotation);
 *
 *     // Sign a token
 *     const token = await jwtService.sign(
 *       { userId: '123' },
 *       { algorithm: 'HS256', expiresIn: '7d' }
 *     );
 *
 *     // Verify a token (automatically handles old versions during grace period)
 *     const payload = await jwtService.verify(token, { algorithm: 'HS256' });
 *
 *     return new Response(JSON.stringify(payload));
 *   }
 * };
 */
