/**
 * Simple Encryption Key Rotation
 *
 * Strategy (STATELESS - no time tracking needed):
 * 1. Store multiple encryption secrets with version IDs (e.g. Cloudflare Secrets)
 * 2. Encrypt data with the CURRENT secret (based on ENCRYPTION_CURRENT_VERSION env var)
 * 3. Decrypt data with CURRENT or PREVIOUS secrets (tries both on each request)
 * 4. Rotate secrets by updating env vars (manual or automated)
 *
 * How "Grace Period" Works:
 * - NOT time-based tracking in the worker (workers are stateless!)
 * - It's how long YOU keep both secrets in Cloudflare before deleting old one
 * - During grace period: Both V1 and V2 secrets exist in Cloudflare
 * - Worker encrypts with V2, decrypts with V2 OR V1 (both work!)
 * - After grace period: Delete V1 secret from Cloudflare, only V2 remains
 *
 * Example Timeline:
 * - Day 0: Deploy with ENCRYPTION_CURRENT_VERSION=2, secrets V1+V2 exist
 * - Day 0-30: Worker encrypts with V2, decrypts V2 OR V1 (both work!)
 * - Day 30: All V1 encrypted data re-encrypted, run: wrangler secret delete ENCRYPTION_SECRET_V1
 * - Day 30+: Only V2 secret exists, only V2 encrypted data works
 *
 * Usage:
 * - Store secrets in Wrangler as: ENCRYPTION_SECRET_V1, ENCRYPTION_SECRET_V2, etc.
 * - Set ENCRYPTION_CURRENT_VERSION to active version number
 */

export interface KeyRotationConfig {
  currentVersion: number;
  secrets: Map<number, string>; // version -> secret
  gracePeriodVersions?: number; // How many old versions to accept (default: 1 = current + 1 previous)
}

export class EncryptionKeyRotation {
  private config: KeyRotationConfig;

  constructor(config: KeyRotationConfig) {
    this.config = {
      gracePeriodVersions: 1,
      ...config
    };
  }

  /**
   * Get the current secret for encrypting new data
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
   * Get all valid secrets for decryption (current + grace period)
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
   * Check if a specific version is still valid for decryption
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
 * ENCRYPTION_CURRENT_VERSION = 2
 *
 * Secrets (via wrangler secret put):
 * ENCRYPTION_SECRET_V1
 * ENCRYPTION_SECRET_V2
 */
export function initKeyRotationFromEnv(env: Record<string, any>): EncryptionKeyRotation {
  const currentVersion = parseInt(env.ENCRYPTION_CURRENT_VERSION || '1', 10);
  const secrets = new Map<number, string>();

  // Load all secrets from environment
  for (let i = 1; i <= currentVersion + 1; i++) {
    const secretKey = `ENCRYPTION_SECRET_V${i}`;
    const secret = env[secretKey];
    if (secret) {
      secrets.set(i, secret);
    }
  }

  if (secrets.size === 0) {
    throw new Error('No encryption secrets found in environment');
  }

  return new EncryptionKeyRotation({
    currentVersion,
    secrets,
    gracePeriodVersions: 1 // Accept current + 1 previous version
  });
}

/**
 * Generate a new secret for rotation
 * Run this locally and add via: wrangler secret put ENCRYPTION_SECRET_V{N}
 */
export async function generateNewSecret(): Promise<string> {
  const array = new Uint8Array(32); // 256-bit secret
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}
