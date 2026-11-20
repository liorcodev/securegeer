import { describe, expect, test } from 'bun:test';
import {
  JWTAlgorithmMismatchError,
  JWTAudienceMismatchError,
  JWTError,
  JWTExpiredError,
  JWTInvalidFormatError,
  JWTInvalidHeaderError,
  JWTInvalidPayloadError,
  JWTInvalidSignatureError,
  JWTInvalidTimeFormatError,
  JWTInvalidTokenError,
  JWTInvalidTokenTypeError,
  JWTIssuerMismatchError,
  JWTKeyRotation,
  JWTNotBeforeError,
  JWTSubjectMismatchError,
  JWTWithRotation,
  decodeJwt,
  generateNewSecret,
  initKeyRotationFromEnv,
  jwt,
  parseTime,
  verifyJwt
} from '../src/jwt/index.js';
import { hmacSign } from '../src/hmac/index.js';

const SECRET = 'jwt-secret-value';

const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');

// Builds a token with a valid HS256 signature over arbitrary header/payload parts
const forge = async (header: unknown, payload: unknown, secret = SECRET): Promise<string> => {
  const message = `${typeof header === 'string' ? header : b64(header)}.${
    typeof payload === 'string' ? payload : b64(payload)
  }`;
  return `${message}.${await hmacSign(message, secret, 'SHA-256')}`;
};

describe('jwt', () => {
  test('signs and verifies for every algorithm', async () => {
    for (const algorithm of ['HS256', 'HS384', 'HS512'] as const) {
      const token = await jwt({ userId: '1' }, SECRET, { algorithm, expiresIn: '1h' });
      const payload = await verifyJwt<{ userId: string }>(token, SECRET, { algorithm });
      expect(payload.userId).toBe('1');
      expect(decodeJwt(token).header.alg).toBe(algorithm);
    }
  });

  test('produces a standard HS256 token (RFC 7515 compatible signature)', async () => {
    const token = await jwt({ a: 1 }, SECRET, { algorithm: 'HS256' });
    const [h, p, s] = token.split('.') as [string, string, string];
    const expected = new Bun.CryptoHasher('sha256', SECRET).update(`${h}.${p}`).digest('base64url');
    expect(s).toBe(expected);
  });

  test('rejects wrong secret, wrong algorithm and expired tokens', async () => {
    const token = await jwt({}, SECRET, { algorithm: 'HS256', expiresIn: '1h' });
    await expect(verifyJwt(token, 'another-secret', { algorithm: 'HS256' })).rejects.toBeInstanceOf(
      JWTInvalidSignatureError
    );
    await expect(verifyJwt(token, SECRET, { algorithm: 'HS512' })).rejects.toBeInstanceOf(
      JWTAlgorithmMismatchError
    );
    const expired = await jwt({}, SECRET, { algorithm: 'HS256', expiresIn: -10 });
    await expect(verifyJwt(expired, SECRET, { algorithm: 'HS256' })).rejects.toBeInstanceOf(
      JWTExpiredError
    );
  });

  test('parseTime handles units', () => {
    expect(parseTime('2h')).toBe(7200);
    expect(parseTime(30)).toBe(30);
    expect(() => parseTime('2x')).toThrow();
  });

  test('parseTime supports every unit and rejects malformed values', () => {
    expect(parseTime('10s')).toBe(10);
    expect(parseTime('5m')).toBe(300);
    expect(parseTime('1d')).toBe(86400);
    expect(parseTime('2w')).toBe(1209600);
    for (const bad of ['', 'h', '1', '1.5h', '-1h', '1 h', '1H']) {
      expect(() => parseTime(bad)).toThrow(JWTInvalidTimeFormatError);
    }
  });

  test('sets iat and the registered claims from sign options', async () => {
    const before = Math.floor(Date.now() / 1000);
    const token = await jwt({ role: 'admin' }, SECRET, {
      algorithm: 'HS256',
      expiresIn: '1h',
      issuer: 'issuer',
      subject: 'subject',
      audience: 'aud',
      jwtid: 'id-1',
      keyId: 'k1'
    });
    const { header, payload } = decodeJwt(token);
    expect(header).toEqual({ alg: 'HS256', typ: 'JWT', kid: 'k1' });
    expect(payload.role).toBe('admin');
    expect(payload.iat).toBeGreaterThanOrEqual(before);
    expect(payload.exp).toBe((payload.iat as number) + 3600);
    expect(payload.iss).toBe('issuer');
    expect(payload.sub).toBe('subject');
    expect(payload.aud).toBe('aud');
    expect(payload.jti).toBe('id-1');
  });

  test('keeps an explicit iat and round-trips unicode payloads', async () => {
    const token = await jwt({ iat: 1000, name: 'שלום 🔐' }, SECRET, { algorithm: 'HS256' });
    const payload = await verifyJwt<{ name: string }>(token, SECRET, { algorithm: 'HS256' });
    expect(payload.iat).toBe(1000);
    expect(payload.name).toBe('שלום 🔐');
  });

  test('rejects tokens that are not yet valid, honouring clockTolerance', async () => {
    const token = await jwt({}, SECRET, { algorithm: 'HS256', notBefore: 60 });
    await expect(verifyJwt(token, SECRET, { algorithm: 'HS256' })).rejects.toBeInstanceOf(
      JWTNotBeforeError
    );
    await expect(
      verifyJwt(token, SECRET, { algorithm: 'HS256', clockTolerance: 120 })
    ).resolves.toBeDefined();
  });

  test('clockTolerance accepts recently expired tokens only within the tolerance', async () => {
    const token = await jwt({}, SECRET, { algorithm: 'HS256', expiresIn: -10 });
    await expect(
      verifyJwt(token, SECRET, { algorithm: 'HS256', clockTolerance: 60 })
    ).resolves.toBeDefined();
    await expect(
      verifyJwt(token, SECRET, { algorithm: 'HS256', clockTolerance: 1 })
    ).rejects.toBeInstanceOf(JWTExpiredError);
  });

  test('validates issuer, subject and audience', async () => {
    const token = await jwt({}, SECRET, {
      algorithm: 'HS256',
      issuer: 'me',
      subject: 'user-1',
      audience: ['web', 'api']
    });
    const base = { algorithm: 'HS256' } as const;
    await expect(
      verifyJwt(token, SECRET, { ...base, issuer: 'me', subject: 'user-1', audience: 'api' })
    ).resolves.toBeDefined();
    await expect(
      verifyJwt(token, SECRET, { ...base, audience: ['x', 'web'] })
    ).resolves.toBeDefined();
    await expect(verifyJwt(token, SECRET, { ...base, issuer: 'other' })).rejects.toBeInstanceOf(
      JWTIssuerMismatchError
    );
    await expect(verifyJwt(token, SECRET, { ...base, subject: 'user-2' })).rejects.toBeInstanceOf(
      JWTSubjectMismatchError
    );
    await expect(verifyJwt(token, SECRET, { ...base, audience: 'other' })).rejects.toBeInstanceOf(
      JWTAudienceMismatchError
    );

    const noAud = await jwt({}, SECRET, base);
    await expect(verifyJwt(noAud, SECRET, { ...base, audience: 'web' })).rejects.toBeInstanceOf(
      JWTAudienceMismatchError
    );
  });

  test('rejects malformed tokens with specific errors', async () => {
    const opts = { algorithm: 'HS256' } as const;
    for (const bad of ['', 'abc', 'a.b', 'a.b.c.d']) {
      await expect(verifyJwt(bad, SECRET, opts)).rejects.toBeInstanceOf(JWTInvalidFormatError);
    }
    await expect(verifyJwt('%%%.e30.sig', SECRET, opts)).rejects.toBeInstanceOf(
      JWTInvalidHeaderError
    );
    await expect(
      verifyJwt(await forge({ alg: 'HS256', typ: 'JWE' }, {}), SECRET, opts)
    ).rejects.toBeInstanceOf(JWTInvalidTokenTypeError);
    await expect(
      verifyJwt(await forge({ alg: 'HS256', typ: 'JWT' }, 'not-json'), SECRET, opts)
    ).rejects.toBeInstanceOf(JWTInvalidPayloadError);
  });

  test('rejects tampered payloads and a stripped signature', async () => {
    const token = await jwt({ admin: false }, SECRET, { algorithm: 'HS256' });
    const [h, , s] = token.split('.') as [string, string, string];
    const tampered = `${h}.${b64({ admin: true })}.${s}`;
    await expect(verifyJwt(tampered, SECRET, { algorithm: 'HS256' })).rejects.toBeInstanceOf(
      JWTInvalidSignatureError
    );
    await expect(
      verifyJwt(`${h}.${token.split('.')[1]}.`, SECRET, { algorithm: 'HS256' })
    ).rejects.toBeInstanceOf(JWTInvalidSignatureError);
  });

  test('rejects alg "none" tokens even when the expected algorithm is HS256', async () => {
    const none = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ admin: true })}.`;
    await expect(verifyJwt(none, SECRET, { algorithm: 'HS256' })).rejects.toBeInstanceOf(
      JWTAlgorithmMismatchError
    );
  });

  test('all errors extend JWTError', async () => {
    const token = await jwt({}, SECRET, { algorithm: 'HS256', expiresIn: -10 });
    const error = await verifyJwt(token, SECRET, { algorithm: 'HS256' }).catch(e => e);
    expect(error).toBeInstanceOf(JWTError);
    expect(error).toBeInstanceOf(Error);
  });

  test('decodeJwt does not verify but rejects unreadable tokens', () => {
    expect(() => decodeJwt('a.b')).toThrow(JWTInvalidFormatError);
    expect(() => decodeJwt('%%%.%%%.sig')).toThrow(JWTInvalidTokenError);
  });
});

describe('jwt key rotation', () => {
  test('tokens signed with the previous version still verify', async () => {
    const v1 = new JWTWithRotation(
      new JWTKeyRotation({ currentVersion: 1, secrets: new Map([[1, 'secret-one-value']]) })
    );
    const token = await v1.sign({ a: 1 }, { algorithm: 'HS256', expiresIn: '1h' });
    expect(decodeJwt(token).header.kid).toBe('v1');

    const v2 = new JWTWithRotation(
      initKeyRotationFromEnv({
        JWT_CURRENT_VERSION: '2',
        JWT_SECRET_V1: 'secret-one-value',
        JWT_SECRET_V2: 'secret-two-value'
      })
    );
    expect((await v2.verify<{ a: number }>(token, { algorithm: 'HS256' })).a).toBe(1);
    expect(v2.getCurrentVersion()).toBe(2);
  });

  const secrets = new Map([
    [1, 'secret-one-value'],
    [2, 'secret-two-value'],
    [3, 'secret-three-value']
  ]);
  const options = { algorithm: 'HS256' } as const;

  test('rejects tokens signed with a version older than the grace period', async () => {
    const v1 = new JWTWithRotation(new JWTKeyRotation({ currentVersion: 1, secrets }));
    const token = await v1.sign({}, options);

    const v3 = new JWTWithRotation(new JWTKeyRotation({ currentVersion: 3, secrets }));
    await expect(v3.verify(token, options)).rejects.toBeInstanceOf(JWTInvalidSignatureError);

    const wide = new JWTWithRotation(
      new JWTKeyRotation({ currentVersion: 3, secrets, gracePeriodVersions: 2 })
    );
    await expect(wide.verify(token, options)).resolves.toBeDefined();
  });

  test('signs with the current version in the kid header', async () => {
    const service = new JWTWithRotation(new JWTKeyRotation({ currentVersion: 2, secrets }));
    expect(decodeJwt(await service.sign({}, options)).header.kid).toBe('v2');
  });

  test('verifies tokens without a kid by trying every valid secret', async () => {
    const service = new JWTWithRotation(new JWTKeyRotation({ currentVersion: 2, secrets }));
    const token = await jwt({ a: 1 }, secrets.get(1)!, options);
    expect(decodeJwt(token).header.kid).toBeUndefined();
    await expect(service.verify(token, options)).resolves.toMatchObject({ a: 1 });
  });

  test('falls back to other secrets when the kid is wrong, but still rejects foreign tokens', async () => {
    const service = new JWTWithRotation(new JWTKeyRotation({ currentVersion: 2, secrets }));
    const wrongKid = await jwt({ a: 1 }, secrets.get(1)!, { ...options, keyId: 'v2' });
    await expect(service.verify(wrongKid, options)).resolves.toMatchObject({ a: 1 });

    const foreign = await jwt({}, 'some-other-secret-value', { ...options, keyId: 'v2' });
    await expect(service.verify(foreign, options)).rejects.toBeInstanceOf(JWTInvalidSignatureError);
    await expect(service.verify('garbage', options)).rejects.toBeInstanceOf(JWTError);
  });

  test('throws when the current version has no secret', async () => {
    const service = new JWTWithRotation(
      new JWTKeyRotation({ currentVersion: 9, secrets: new Map([[1, 'secret-one-value']]) })
    );
    await expect(service.sign({}, options)).rejects.toThrow('current version 9');
  });

  test('initKeyRotationFromEnv defaults to version 1 and requires at least one secret', () => {
    expect(
      new JWTWithRotation(
        initKeyRotationFromEnv({ JWT_SECRET_V1: 'secret-one-value' })
      ).getCurrentVersion()
    ).toBe(1);
    expect(() => initKeyRotationFromEnv({})).toThrow('No JWT secrets');
  });

  test('generateNewSecret returns 64 random hex characters', async () => {
    const a = await generateNewSecret();
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(await generateNewSecret()).not.toBe(a);
  });
});
