import { describe, expect, test } from 'bun:test';
import {
  AuthenticationFailedError,
  DecryptionError,
  EncryptionKeyRotation,
  EncryptionWithRotation,
  InvalidCiphertextError,
  InvalidKeyError,
  decrypt,
  decryptJSON,
  encrypt,
  generateNewSecret,
  generateSecret,
  initKeyRotationFromEnv
} from '../src/encryption/index.js';

const SECRET = 'my-secret-key-that-is-32-bytes-long!!';

describe('encrypt / decrypt', () => {
  test('round-trips strings and JSON', async () => {
    expect(await decrypt(await encrypt('hello', SECRET), SECRET)).toBe('hello');
    const encrypted = await encrypt({ userId: 123 }, SECRET);
    expect(await decryptJSON<{ userId: number }>(encrypted, SECRET)).toEqual({ userId: 123 });
  });

  test('round-trips large payloads', async () => {
    const data = 'x'.repeat(100_000);
    expect(await decrypt(await encrypt(data, SECRET), SECRET)).toBe(data);
  });

  test('uses a random salt and iv per message (salt:iv:ciphertext)', async () => {
    const a = await encrypt('a', SECRET);
    const b = await encrypt('a', SECRET);
    expect(a).not.toBe(b);
    const [saltA, ivA] = a.split(':');
    const [saltB, ivB] = b.split(':');
    expect(a.split(':')).toHaveLength(3);
    expect(saltA).not.toBe(saltB);
    expect(ivA).not.toBe(ivB);
  });

  test('rejects short secrets, malformed, tampered and wrongly-keyed ciphertext', async () => {
    await expect(encrypt('a', 'too-short-secret')).rejects.toBeInstanceOf(InvalidKeyError);
    await expect(decrypt('nocolon', SECRET)).rejects.toBeInstanceOf(InvalidCiphertextError);
    await expect(decrypt('a:b', SECRET)).rejects.toBeInstanceOf(InvalidCiphertextError);
    await expect(decrypt('a:b:c:d', SECRET)).rejects.toBeInstanceOf(InvalidCiphertextError);

    const encrypted = await encrypt('a', SECRET);
    await expect(decrypt(encrypted, generateSecret())).rejects.toBeInstanceOf(
      AuthenticationFailedError
    );

    const [, iv, data] = encrypted.split(':') as [string, string, string];
    const otherSalt = (await encrypt('a', SECRET)).split(':')[0];
    await expect(decrypt(`${otherSalt}:${iv}:${data}`, SECRET)).rejects.toBeInstanceOf(
      AuthenticationFailedError
    );
  });

  test('generateSecret returns a 43 char base64url string usable as a secret', async () => {
    const secret = generateSecret();
    expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await decrypt(await encrypt('x', secret), secret)).toBe('x');
    expect(generateSecret()).not.toBe(secret);
  });

  test('round-trips empty strings, unicode and nested JSON', async () => {
    expect(await decrypt(await encrypt('', SECRET), SECRET)).toBe('');
    expect(await decrypt(await encrypt('שלום 🔐 héllo', SECRET), SECRET)).toBe('שלום 🔐 héllo');
    const nested = { a: [1, { b: null }], c: 'd' };
    expect(await decryptJSON(await encrypt(nested, SECRET), SECRET)).toEqual(nested);
  });

  test('rejects tampering with any part of the ciphertext', async () => {
    const [salt, iv, data] = (await encrypt('hello world', SECRET)).split(':') as [
      string,
      string,
      string
    ];
    const flip = (value: string): string => `${value[0] === 'A' ? 'B' : 'A'}${value.slice(1)}`;
    for (const tampered of [
      `${flip(salt)}:${iv}:${data}`,
      `${salt}:${flip(iv)}:${data}`,
      `${salt}:${iv}:${flip(data)}`,
      `${salt}:${iv}:${data.slice(0, -4)}`
    ]) {
      await expect(decrypt(tampered, SECRET)).rejects.toBeInstanceOf(AuthenticationFailedError);
    }
  });

  test('decryptJSON throws DecryptionError for non-JSON plaintext', async () => {
    await expect(decryptJSON(await encrypt('not json', SECRET), SECRET)).rejects.toBeInstanceOf(
      DecryptionError
    );
  });

  test('whitespace-only secrets and short secrets are rejected on decrypt too', async () => {
    const encrypted = await encrypt('a', SECRET);
    await expect(encrypt('a', ' '.repeat(40))).rejects.toBeInstanceOf(InvalidKeyError);
    await expect(decrypt(encrypted, 'short')).rejects.toBeInstanceOf(InvalidKeyError);
  });

  test('malformed base64 parts surface as DecryptionError', async () => {
    await expect(decrypt('%%%:%%%:%%%', SECRET)).rejects.toBeInstanceOf(DecryptionError);
  });
});

describe('key rotation', () => {
  const v1 = 'secret-version-one-with-32-chars!!';
  const v2 = 'secret-version-two-with-32-chars!!';
  const v3 = 'secret-version-three-with-32-chars!';
  const secrets = new Map([
    [1, v1],
    [2, v2],
    [3, v3]
  ]);

  test('data from a version older than the grace period cannot be decrypted', async () => {
    const old = new EncryptionWithRotation(
      new EncryptionKeyRotation({ currentVersion: 1, secrets })
    );
    const encrypted = await old.encrypt('data');

    const current = new EncryptionWithRotation(
      new EncryptionKeyRotation({ currentVersion: 3, secrets })
    );
    await expect(current.decrypt(encrypted)).rejects.toThrow('Unable to decrypt');

    const wide = new EncryptionWithRotation(
      new EncryptionKeyRotation({ currentVersion: 3, secrets, gracePeriodVersions: 2 })
    );
    expect(await wide.decrypt(encrypted)).toBe('data');
  });

  test('getValidSecrets lists current first, then the grace-period versions', () => {
    const rotation = new EncryptionKeyRotation({ currentVersion: 3, secrets });
    expect(rotation.getValidSecrets().map(s => s.version)).toEqual([3, 2]);
    expect(rotation.isVersionValid(3)).toBe(true);
    expect(rotation.isVersionValid(2)).toBe(true);
    expect(rotation.isVersionValid(1)).toBe(false);
    expect(rotation.isVersionValid(4)).toBe(false);
  });

  test('skips missing versions and throws when the current secret is missing', () => {
    const gap = new EncryptionKeyRotation({
      currentVersion: 3,
      secrets: new Map([
        [1, v1],
        [3, v3]
      ])
    });
    expect(gap.getValidSecrets().map(s => s.version)).toEqual([3]);
    const missing = new EncryptionKeyRotation({ currentVersion: 5, secrets });
    expect(() => missing.getCurrentSecret()).toThrow('current version 5');
  });

  test('extractVersion and needsReEncryption handle unversioned input', async () => {
    const service = new EncryptionWithRotation(
      new EncryptionKeyRotation({ currentVersion: 2, secrets })
    );
    const encrypted = await service.encrypt('x');
    expect(service.extractVersion(encrypted)).toBe(2);
    expect(service.extractVersion('salt:iv:data')).toBeNull();
    expect(service.needsReEncryption('salt:iv:data')).toBe(true);
    expect(service.needsReEncryption(encrypted)).toBe(false);
  });

  test('a wrong version prefix still decrypts via the other valid secrets', async () => {
    const service = new EncryptionWithRotation(
      new EncryptionKeyRotation({ currentVersion: 2, secrets })
    );
    const withV1 = await new EncryptionWithRotation(
      new EncryptionKeyRotation({ currentVersion: 1, secrets })
    ).encrypt('data');
    expect(await service.decrypt(withV1.replace(/^v1:/, 'v2:'))).toBe('data');
  });

  test('tampered or foreign versioned ciphertext fails', async () => {
    const service = new EncryptionWithRotation(
      new EncryptionKeyRotation({ currentVersion: 2, secrets })
    );
    const foreign = `v2:${await encrypt('data', 'a-completely-different-secret-of-32-chars')}`;
    await expect(service.decrypt(foreign)).rejects.toThrow('Unable to decrypt');
    await expect(service.decrypt('v2:')).rejects.toBeInstanceOf(InvalidCiphertextError);
    await expect(service.decryptJSON(await service.encrypt('not json'))).rejects.toThrow(
      'Failed to parse'
    );
  });

  test('encrypts objects and round-trips them through decryptJSON', async () => {
    const service = new EncryptionWithRotation(
      new EncryptionKeyRotation({ currentVersion: 1, secrets })
    );
    expect(await service.decryptJSON(await service.encrypt({ a: [1, 2] }))).toEqual({ a: [1, 2] });
  });

  test('initKeyRotationFromEnv defaults to version 1 and generateNewSecret is 64 hex chars', async () => {
    const service = new EncryptionWithRotation(
      initKeyRotationFromEnv({ ENCRYPTION_SECRET_V1: v1 })
    );
    expect(service.getCurrentVersion()).toBe(1);
    expect(() => initKeyRotationFromEnv({})).toThrow('No encryption secrets');
    const generated = await generateNewSecret();
    expect(generated).toMatch(/^[0-9a-f]{64}$/);
    expect(await decrypt(await encrypt('x', generated), generated)).toBe('x');
  });
});

describe('key rotation (basics)', () => {
  const v1 = 'secret-version-one-with-32-chars!!';
  const v2 = 'secret-version-two-with-32-chars!!';

  test('encrypts with current version and decrypts old versions', async () => {
    const old = new EncryptionWithRotation(
      new EncryptionKeyRotation({ currentVersion: 1, secrets: new Map([[1, v1]]) })
    );
    const previous = await old.encrypt({ a: 1 });
    expect(previous.startsWith('v1:')).toBe(true);

    const current = new EncryptionWithRotation(
      new EncryptionKeyRotation({
        currentVersion: 2,
        secrets: new Map([
          [1, v1],
          [2, v2]
        ])
      })
    );
    expect(await current.decryptJSON(previous)).toEqual({ a: 1 });
    expect(current.needsReEncryption(previous)).toBe(true);

    const reEncrypted = await current.reEncrypt(previous);
    expect(reEncrypted.startsWith('v2:')).toBe(true);
    expect(current.needsReEncryption(reEncrypted)).toBe(false);
  });

  test('rejects unversioned ciphertext', async () => {
    const service = new EncryptionWithRotation(
      new EncryptionKeyRotation({ currentVersion: 1, secrets: new Map([[1, v1]]) })
    );
    await expect(service.decrypt(await encrypt('a', v1))).rejects.toBeInstanceOf(
      InvalidCiphertextError
    );
  });

  test('initKeyRotationFromEnv reads versioned secrets', () => {
    const service = new EncryptionWithRotation(
      initKeyRotationFromEnv({
        ENCRYPTION_CURRENT_VERSION: '2',
        ENCRYPTION_SECRET_V1: v1,
        ENCRYPTION_SECRET_V2: v2
      })
    );
    expect(service.getCurrentVersion()).toBe(2);
    expect(() => initKeyRotationFromEnv({})).toThrow();
  });
});
