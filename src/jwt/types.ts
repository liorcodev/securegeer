/**
 * JWT Type Definitions
 */

// JWT Header type
export interface JWTHeader {
  alg: 'HS256' | 'HS384' | 'HS512';
  typ: 'JWT';
  kid?: string; // Key ID for rotation (e.g., "v2")
}

// JWT Payload type
export type JWTPayload<T = Record<string, unknown>> = {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
} & T;

// JWT Sign Options
export interface JWTSignOptions {
  algorithm: 'HS256' | 'HS384' | 'HS512'; // REQUIRED - no default
  expiresIn?: number | string;
  notBefore?: number | string;
  issuer?: string;
  subject?: string;
  audience?: string | string[];
  jwtid?: string;
  keyId?: string; // Key version identifier (e.g., "v2")
}

// JWT Verify Options
export interface JWTVerifyOptions {
  algorithm: 'HS256' | 'HS384' | 'HS512'; // REQUIRED
  issuer?: string;
  subject?: string;
  audience?: string | string[];
  clockTolerance?: number;
}

// Key Rotation Config
export interface KeyRotationConfig {
  currentVersion: number;
  secrets: Map<number, string>; // version -> secret
  gracePeriodVersions?: number; // How many old versions to accept (default: 1 = current + 1 previous)
}
