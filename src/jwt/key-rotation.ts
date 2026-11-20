/**
 * Simple JWT Key Rotation
 *
 * Strategy (STATELESS - no time tracking needed):
 * 1. Store multiple secrets with version IDs (e.g. Cloudflare Secrets)
 * 2. Sign tokens with the CURRENT secret (based on JWT_CURRENT_VERSION env var)
 * 3. Verify tokens with CURRENT or PREVIOUS secrets (tries both on each request)
 * 4. Rotate secrets by updating env vars (manual or automated)
 *
 * How "Grace Period" Works:
 * - NOT time-based tracking in the worker (workers are stateless!)
 * - It's how long YOU keep both secrets in Cloudflare before deleting old one
 * - During grace period: Both V1 and V2 secrets exist in Cloudflare
 * - Worker tries V2 first, falls back to V1 if verification fails
 * - After grace period: Delete V1 secret from Cloudflare, only V2 remains
 *
 * Example Timeline:
 * - Day 0: Deploy with JWT_CURRENT_VERSION=2, secrets V1+V2 exist
 * - Day 0-7: Worker signs with V2, verifies V2 OR V1 (both work!)
 * - Day 7: All V1 tokens expired, run: wrangler secret delete JWT_SECRET_V1
 * - Day 7+: Only V2 secret exists, only V2 tokens work
 *
 * Usage:
 * - Store secrets in Wrangler as: JWT_SECRET_V1, JWT_SECRET_V2, etc.
 * - Set JWT_CURRENT_VERSION to active version number
 */

import type { KeyRotationConfig } from './types.js';

export type { KeyRotationConfig };

export class JWTKeyRotation {
  private config: KeyRotationConfig;

  constructor(config: KeyRotationConfig) {
    this.config = {
      gracePeriodVersions: 1,
      ...config
    };
  }

  /**
   * Get the current secret for signing new tokens
   */
  getCurrentSecret(): { secret: string; version: number } {
    const secret = this.config.secrets.get(this.config.currentVersion);
    if (!secret) {
      throw new Error(`Secret for current version ${this.config.currentVersion} not found`);
    }
    return {
      secret,
      version: this.config.currentVersion
    };
  }

  /**
   * Get all valid secrets for verification (current + grace period)
   */
  getValidSecrets(): Array<{ secret: string; version: number }> {
    const validVersions: Array<{ secret: string; version: number }> = [];
    const minVersion = this.config.currentVersion - (this.config.gracePeriodVersions || 1);

    for (let version = this.config.currentVersion; version >= minVersion; version--) {
      const secret = this.config.secrets.get(version);
      if (secret) {
        validVersions.push({ secret, version });
      }
    }

    return validVersions;
  }

  /**
   * Check if a specific version is still valid for verification
   */
  isVersionValid(version: number): boolean {
    const minVersion = this.config.currentVersion - (this.config.gracePeriodVersions || 1);
    return version >= minVersion && version <= this.config.currentVersion;
  }
}

/**
 * Helper to initialize key rotation from an environment object
 *
 * Setup in wrangler.jsonc:
 * [vars]
 * JWT_CURRENT_VERSION = 2
 *
 * Secrets (via wrangler secret put):
 * JWT_SECRET_V1
 * JWT_SECRET_V2
 */
export function initKeyRotationFromEnv(env: Record<string, any>): JWTKeyRotation {
  const currentVersion = parseInt(env.JWT_CURRENT_VERSION || '1', 10);
  const secrets = new Map<number, string>();

  // Load all secrets from environment
  for (let i = 1; i <= currentVersion + 1; i++) {
    const secretKey = `JWT_SECRET_V${i}`;
    const secret = env[secretKey];
    if (secret) {
      secrets.set(i, secret);
    }
  }

  if (secrets.size === 0) {
    throw new Error('No JWT secrets found in environment');
  }

  return new JWTKeyRotation({
    currentVersion,
    secrets,
    gracePeriodVersions: 1 // Accept current + 1 previous version
  });
}

/**
 * Generate a new secret for rotation
 * Run this locally and add via: wrangler secret put JWT_SECRET_V{N}
 */
export async function generateNewSecret(): Promise<string> {
  const array = new Uint8Array(32); // 256-bit secret
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}
