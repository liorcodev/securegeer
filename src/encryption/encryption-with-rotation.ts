/**
 * Encryption wrapper with automatic key rotation support
 * Simple integration layer for production use
 */

import { encrypt, decrypt } from './encryption.js';
import { InvalidCiphertextError } from './errors.js';
import { EncryptionKeyRotation } from './key-rotation.js';

/**
 * Format for encrypted data with version metadata
 * Format: `v{version}:{salt}:{iv}:{ciphertext}`
 */
const VERSION_PREFIX = 'v';
const SEPARATOR = ':';

export class EncryptionWithRotation {
  constructor(private keyRotation: EncryptionKeyRotation) {}

  /**
   * Encrypt data with the current secret version
   * Output format: `v{version}:{salt}:{iv}:{ciphertext}`
   */
  async encrypt(data: string | object): Promise<string> {
    const { secret, version } = this.keyRotation.getCurrentSecret();

    // Encrypt with current secret
    const encrypted = await encrypt(data, secret);

    // Prepend version identifier
    return `${VERSION_PREFIX}${version}${SEPARATOR}${encrypted}`;
  }

  /**
   * Decrypt data - automatically tries current and previous secrets
   * Expects the versioned format produced by `encrypt`
   * @throws {InvalidCiphertextError} If the ciphertext has no version prefix
   */
  async decrypt(ciphertext: string): Promise<string> {
    const versionMatch = ciphertext.match(/^v(\d+):(.+)$/);
    if (!versionMatch || !versionMatch[1] || !versionMatch[2]) {
      throw new InvalidCiphertextError();
    }

    const version = parseInt(versionMatch[1], 10);
    const encryptedData = versionMatch[2];

    const validSecrets = this.keyRotation.getValidSecrets();

    // Try the specific version first if it's still valid
    const secretWithVersion = validSecrets.find(s => s.version === version);
    if (secretWithVersion && this.keyRotation.isVersionValid(version)) {
      try {
        return await decrypt(encryptedData, secretWithVersion.secret);
      } catch {
        // Fall through to try all secrets
      }
    }

    // Try all valid secrets (current first, then older versions)
    for (const { secret } of validSecrets) {
      try {
        return await decrypt(encryptedData, secret);
      } catch {
        // Continue to next secret
      }
    }

    throw new Error('Decryption failed: Unable to decrypt with any available secret version');
  }

  /**
   * Decrypt and parse JSON data
   */
  async decryptJSON<T = unknown>(ciphertext: string): Promise<T> {
    const decrypted = await this.decrypt(ciphertext);
    try {
      return JSON.parse(decrypted) as T;
    } catch (error) {
      throw new Error('Failed to parse decrypted data as JSON');
    }
  }

  /**
   * Get current key version (useful for monitoring/logging)
   */
  getCurrentVersion(): number {
    return this.keyRotation.getCurrentSecret().version;
  }

  /**
   * Extract version from encrypted data (if versioned)
   */
  extractVersion(ciphertext: string): number | null {
    const versionMatch = ciphertext.match(/^v(\d+):/);
    return versionMatch && versionMatch[1] ? parseInt(versionMatch[1], 10) : null;
  }

  /**
   * Check if encrypted data needs re-encryption (not using the current version)
   * Useful for background re-encryption tasks during key rotation
   */
  needsReEncryption(ciphertext: string): boolean {
    return this.extractVersion(ciphertext) !== this.getCurrentVersion();
  }

  /**
   * Re-encrypt data with the current version
   * Useful during key rotation to migrate old encrypted data
   */
  async reEncrypt(ciphertext: string): Promise<string> {
    const decrypted = await this.decrypt(ciphertext);
    return await this.encrypt(decrypted);
  }
}

/**
 * Example usage in a Cloudflare Worker
 *
 * import { initKeyRotationFromEnv, EncryptionWithRotation } from 'securegeer/encryption';
 *
 * export default {
 *   async fetch(request: Request, env: Env) {
 *     const keyRotation = initKeyRotationFromEnv(env);
 *     const encryptionService = new EncryptionWithRotation(keyRotation);
 *
 *     // Encrypt sensitive data
 *     const encrypted = await encryptionService.encrypt({
 *       userId: '123',
 *       email: 'me@example.com'
 *     });
 *
 *     // Decrypt (automatically handles old versions during grace period)
 *     const decrypted = await encryptionService.decryptJSON(encrypted);
 *
 *     // Check if data needs re-encryption
 *     if (encryptionService.needsReEncryption(encrypted)) {
 *       const reEncrypted = await encryptionService.reEncrypt(encrypted);
 *       // Save reEncrypted back to database
 *     }
 *
 *     return new Response(JSON.stringify(decrypted));
 *   }
 * };
 */
