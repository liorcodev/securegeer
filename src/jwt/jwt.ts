import { hmacSign, hmacVerify, type HmacAlgorithm } from '../hmac/index.js';
import { fromBase64Url, toBase64Url } from '../shared/base64url.js';
import {
  JWTAlgorithmMismatchError,
  JWTAudienceMismatchError,
  JWTExpiredError,
  JWTInvalidFormatError,
  JWTInvalidHeaderError,
  JWTInvalidPayloadError,
  JWTInvalidSignatureError,
  JWTInvalidTimeFormatError,
  JWTInvalidTokenError,
  JWTInvalidTokenTypeError,
  JWTIssuerMismatchError,
  JWTNotBeforeError,
  JWTSubjectMismatchError
} from './errors.js';
import type { JWTHeader, JWTPayload, JWTSignOptions, JWTVerifyOptions } from './types.js';

export type { JWTHeader, JWTPayload, JWTSignOptions, JWTVerifyOptions };

const ALGORITHM_HASH_MAP: Record<'HS256' | 'HS384' | 'HS512', HmacAlgorithm> = {
  HS256: 'SHA-256',
  HS384: 'SHA-384',
  HS512: 'SHA-512'
};

const TIME_MULTIPLIERS = {
  s: 1,
  m: 60,
  h: 3600,
  d: 86400,
  w: 604800
} as const;

const base64UrlEncode = (data: string): string => toBase64Url(new TextEncoder().encode(data));

const base64UrlDecode = (data: string): string => new TextDecoder().decode(fromBase64Url(data));

export const parseTime = (time: string | number): number => {
  if (typeof time === 'number') return time;
  const match = time.match(/^(\d+)([smhdw])$/);
  if (!match) throw new JWTInvalidTimeFormatError(time);
  const value = parseInt(match[1]!, 10);
  const unit = match[2] as keyof typeof TIME_MULTIPLIERS;
  return value * TIME_MULTIPLIERS[unit];
};

export const jwt = async <T = Record<string, unknown>>(
  payload: JWTPayload<T>,
  secret: string,
  options: JWTSignOptions // REQUIRED
): Promise<string> => {
  const header: JWTHeader = {
    alg: options.algorithm,
    typ: 'JWT',
    ...(options.keyId && { kid: options.keyId })
  };

  const now = Math.floor(Date.now() / 1000);
  const claims: JWTPayload = { ...payload };

  if (!claims.iat) claims.iat = now;
  if (options.expiresIn) claims.exp = now + parseTime(options.expiresIn);
  if (options.notBefore) claims.nbf = now + parseTime(options.notBefore);
  if (options.issuer) claims.iss = options.issuer;
  if (options.subject) claims.sub = options.subject;
  if (options.audience) claims.aud = options.audience;
  if (options.jwtid) claims.jti = options.jwtid;

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(claims));
  const message = `${encodedHeader}.${encodedPayload}`;

  const encodedSignature = await hmacSign(message, secret, ALGORITHM_HASH_MAP[options.algorithm]);
  return `${message}.${encodedSignature}`;
};

export const verifyJwt = async <T = Record<string, unknown>>(
  token: string,
  secret: string,
  options: JWTVerifyOptions // REQUIRED
): Promise<JWTPayload<T>> => {
  const parts = token.split('.');
  if (parts.length !== 3) throw new JWTInvalidFormatError();

  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];

  let header: JWTHeader;
  try {
    header = JSON.parse(base64UrlDecode(encodedHeader)) as JWTHeader;
  } catch {
    throw new JWTInvalidHeaderError();
  }

  if (header.alg !== options.algorithm) {
    throw new JWTAlgorithmMismatchError(options.algorithm, header.alg);
  }

  if (header.typ !== 'JWT') throw new JWTInvalidTokenTypeError();

  const message = `${encodedHeader}.${encodedPayload}`;
  const isValid = await hmacVerify(
    message,
    encodedSignature,
    secret,
    ALGORITHM_HASH_MAP[header.alg]
  );
  if (!isValid) throw new JWTInvalidSignatureError();

  let payload: JWTPayload<T>;
  try {
    payload = JSON.parse(base64UrlDecode(encodedPayload)) as JWTPayload<T>;
  } catch {
    throw new JWTInvalidPayloadError();
  }

  const now = Math.floor(Date.now() / 1000);
  const clockTolerance = options.clockTolerance ?? 0;

  if (payload.exp && now > payload.exp + clockTolerance) {
    throw new JWTExpiredError();
  }
  if (payload.nbf && now < payload.nbf - clockTolerance) {
    throw new JWTNotBeforeError();
  }
  if (options.issuer && payload.iss !== options.issuer) {
    throw new JWTIssuerMismatchError(options.issuer, payload.iss);
  }
  if (options.subject && payload.sub !== options.subject) {
    throw new JWTSubjectMismatchError(options.subject, payload.sub);
  }
  if (options.audience) {
    const expectedAud = Array.isArray(options.audience) ? options.audience : [options.audience];
    const actualAud = payload.aud ? (Array.isArray(payload.aud) ? payload.aud : [payload.aud]) : [];
    if (!expectedAud.some(aud => actualAud.includes(aud))) {
      throw new JWTAudienceMismatchError();
    }
  }

  return payload;
};

export const decodeJwt = (token: string): { header: JWTHeader; payload: JWTPayload } => {
  const parts = token.split('.');
  if (parts.length !== 3) throw new JWTInvalidFormatError();

  try {
    const header = JSON.parse(base64UrlDecode(parts[0]!)) as JWTHeader;
    const payload = JSON.parse(base64UrlDecode(parts[1]!)) as JWTPayload;
    return { header, payload };
  } catch {
    throw new JWTInvalidTokenError();
  }
};
