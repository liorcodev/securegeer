/**
 * JWT Utilities with Key Rotation Support (HMAC: HS256 / HS384 / HS512)
 *
 * Simple usage:
 * - Use JWTWithRotation for production with automatic key rotation
 * - Use jwt/verifyJwt directly for simple single-key scenarios
 *
 * ```ts
 * import { jwt, verifyJwt } from 'securegeer/jwt';
 * ```
 */

// Core JWT functions
export { jwt, verifyJwt, decodeJwt, parseTime } from './jwt.js';

// Types
export type {
  JWTPayload,
  JWTSignOptions,
  JWTVerifyOptions,
  JWTHeader,
  KeyRotationConfig
} from './types.js';

// Key rotation
export { JWTKeyRotation, initKeyRotationFromEnv, generateNewSecret } from './key-rotation.js';

// High-level API with rotation
export { JWTWithRotation } from './jwt-with-rotation.js';

// All errors
export * from './errors.js';
