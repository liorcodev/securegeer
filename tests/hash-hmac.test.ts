import { describe, expect, test } from 'bun:test';
import { hashPassword, sha256, verifyPasswordHash } from '../src/hash/index.js';
import { hmacSign, hmacVerify } from '../src/hmac/index.js';

describe('hmac', () => {
  test('matches an independent HMAC-SHA256 implementation (base64url)', async () => {
    const expected = new Bun.CryptoHasher('sha256', 'key')
      .update('The quick brown fox jumps over the lazy dog')
      .digest('base64url');
    expect(await hmacSign('The quick brown fox jumps over the lazy dog', 'key')).toBe(expected);
  });

  test('verifies valid signatures and rejects invalid ones', async () => {
    for (const alg of ['SHA-256', 'SHA-384', 'SHA-512'] as const) {
      const sig = await hmacSign('msg', 'secret', alg);
      expect(await hmacVerify('msg', sig, 'secret', alg)).toBe(true);
      expect(await hmacVerify('tampered', sig, 'secret', alg)).toBe(false);
      expect(await hmacVerify('msg', sig, 'other', alg)).toBe(false);
    }
    expect(await hmacVerify('msg', '!!!not-base64!!!', 'secret')).toBe(false);
  });

  test('SHA-384 and SHA-512 match an independent implementation', async () => {
    for (const [alg, name] of [
      ['SHA-384', 'sha384'],
      ['SHA-512', 'sha512']
    ] as const) {
      const expected = new Bun.CryptoHasher(name, 'key').update('message').digest('base64url');
      expect(await hmacSign('message', 'key', alg)).toBe(expected);
    }
  });

  test('signatures are deterministic and algorithm-specific', async () => {
    expect(await hmacSign('m', 's')).toBe(await hmacSign('m', 's', 'SHA-256'));
    expect(await hmacSign('m', 's')).not.toBe(await hmacSign('m', 's', 'SHA-512'));
    const sha512 = await hmacSign('m', 's', 'SHA-512');
    expect(await hmacVerify('m', sha512, 's', 'SHA-256')).toBe(false);
  });

  test('handles empty messages and unicode', async () => {
    const sig = await hmacSign('', 'secret');
    expect(await hmacVerify('', sig, 'secret')).toBe(true);
    const unicode = await hmacSign('שלום 🔐', 'סוד');
    expect(await hmacVerify('שלום 🔐', unicode, 'סוד')).toBe(true);
  });

  test('rejects truncated, empty and extended signatures', async () => {
    const sig = await hmacSign('msg', 'secret');
    expect(await hmacVerify('msg', sig.slice(0, -2), 'secret')).toBe(false);
    expect(await hmacVerify('msg', '', 'secret')).toBe(false);
    expect(await hmacVerify('msg', `${sig}AA`, 'secret')).toBe(false);
  });
});

describe('hash', () => {
  test('hashPassword / verifyPasswordHash round-trip in a self-describing format', async () => {
    const stored = await hashPassword('hunter2');
    expect(stored).toMatch(/^pbkdf2-sha256\$100000\$[0-9a-f]{32}\$[0-9a-f]{64}$/);
    expect(await verifyPasswordHash(stored, 'hunter2')).toBe(true);
    expect(await verifyPasswordHash(stored, 'hunter3')).toBe(false);
    expect(await hashPassword('hunter2')).not.toBe(stored);
  });

  test('verifies with the iterations stored in the hash', async () => {
    const stored = await hashPassword('hunter2', { iterations: 1000 });
    expect(stored.startsWith('pbkdf2-sha256$1000$')).toBe(true);
    expect(await verifyPasswordHash(stored, 'hunter2')).toBe(true);
  });

  test('optional pepper must match on verify', async () => {
    const stored = await hashPassword('hunter2', { pepper: 'server-pepper' });
    expect(await verifyPasswordHash(stored, 'hunter2', { pepper: 'server-pepper' })).toBe(true);
    expect(await verifyPasswordHash(stored, 'hunter2', { pepper: 'other-pepper' })).toBe(false);
    expect(await verifyPasswordHash(stored, 'hunter2')).toBe(false);
    await expect(hashPassword('hunter2', { pepper: '' })).rejects.toThrow();
  });

  test('rejects malformed stored hashes and invalid iterations', async () => {
    await expect(verifyPasswordHash('salt:hash', 'x')).rejects.toThrow('Invalid hash format');
    await expect(verifyPasswordHash('pbkdf2-sha256$100000$zz$zz', 'x')).rejects.toThrow(
      'Invalid hash format'
    );
    await expect(hashPassword('x', { iterations: 0 })).rejects.toThrow();
  });

  test('sha256 is deterministic SHA-256 hex', async () => {
    expect(await sha256('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
  });

  test('sha256 handles empty and unicode input', async () => {
    expect(await sha256('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
    expect(await sha256('שלום')).toBe(new Bun.CryptoHasher('sha256').update('שלום').digest('hex'));
  });

  test('derives a hash matching an independent PBKDF2-SHA256 implementation', async () => {
    const salt = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
    const expected = (await import('node:crypto'))
      .pbkdf2Sync('hunter2', Buffer.from(salt, 'hex'), 1000, 32, 'sha256')
      .toString('hex');
    expect(await verifyPasswordHash(`pbkdf2-sha256$1000$${salt}$${expected}`, 'hunter2')).toBe(
      true
    );
  });

  test('pepper is applied as HMAC-SHA256 before PBKDF2', async () => {
    const salt = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
    const peppered = await hmacSign('hunter2', 'pepper');
    const expected = (await import('node:crypto'))
      .pbkdf2Sync(peppered, Buffer.from(salt, 'hex'), 1000, 32, 'sha256')
      .toString('hex');
    const stored = `pbkdf2-sha256$1000$${salt}$${expected}`;
    expect(await verifyPasswordHash(stored, 'hunter2', { pepper: 'pepper' })).toBe(true);
    expect(await verifyPasswordHash(stored, 'hunter2')).toBe(false);
  });

  test('handles empty, long and unicode passwords', async () => {
    for (const password of ['', 'p'.repeat(1000), 'סיסמה 🔐']) {
      const stored = await hashPassword(password, { iterations: 1000 });
      expect(await verifyPasswordHash(stored, password)).toBe(true);
      expect(await verifyPasswordHash(stored, `${password}x`)).toBe(false);
    }
  });

  test('rejects a tampered hash or salt without throwing', async () => {
    const stored = await hashPassword('hunter2', { iterations: 1000 });
    const [scheme, iterations, salt, hash] = stored.split('$') as [string, string, string, string];
    const flip = (hex: string): string => `${hex[0] === '0' ? '1' : '0'}${hex.slice(1)}`;
    expect(
      await verifyPasswordHash([scheme, iterations, salt, flip(hash)].join('$'), 'hunter2')
    ).toBe(false);
    expect(
      await verifyPasswordHash([scheme, iterations, flip(salt), hash].join('$'), 'hunter2')
    ).toBe(false);
    expect(await verifyPasswordHash([scheme, '2000', salt, hash].join('$'), 'hunter2')).toBe(false);
  });

  test('rejects hashes with the wrong scheme, uppercase hex or wrong lengths', async () => {
    const stored = await hashPassword('x', { iterations: 1000 });
    const [, iterations, salt, hash] = stored.split('$') as [string, string, string, string];
    for (const bad of [
      `bcrypt$${iterations}$${salt}$${hash}`,
      `pbkdf2-sha256$${iterations}$${salt.toUpperCase().replace(/[0-9]/g, 'A')}$${hash}`,
      `pbkdf2-sha256$${iterations}$${salt.slice(2)}$${hash}`,
      `pbkdf2-sha256$${iterations}$${salt}$${hash}00`,
      `pbkdf2-sha256$0$${salt}$${hash}`,
      `pbkdf2-sha256$$${salt}$${hash}`,
      ''
    ]) {
      await expect(verifyPasswordHash(bad, 'x')).rejects.toThrow('Invalid hash format');
    }
  });

  test('rejects non-integer and non-finite iteration counts', async () => {
    for (const iterations of [-1, 1.5, NaN, Infinity]) {
      await expect(hashPassword('x', { iterations })).rejects.toThrow('positive integer');
    }
  });

  test('empty pepper on verify is rejected like on hash', async () => {
    const stored = await hashPassword('x', { iterations: 1000 });
    await expect(verifyPasswordHash(stored, 'x', { pepper: '' })).rejects.toThrow('Pepper');
  });
});
