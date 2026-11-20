<p align="center">
  <img src="./assets/securegeer-logo-full.png" alt="SecureGeer - Web Crypto Utilities" width="200" />
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/securegeer">
    <img src="https://img.shields.io/npm/v/securegeer?style=flat-square&color=blue" alt="npm version" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square" alt="License: MIT" />
  </a>
</p>

Web Crypto utilities with no runtime dependencies: AES-256-GCM encryption, JWT (HS256/384/512), HMAC
and password/token hashing, with stateless key rotation. Works in Cloudflare Workers, Bun, Deno,
browsers and Node.js 18+.

Each module is a separate subpath export, so you only bundle what you import:

| Import                  | Contents                                                        |
| ----------------------- | --------------------------------------------------------------- |
| `securegeer/encryption` | `encrypt`, `decrypt`, `decryptJSON`, `generateSecret`, rotation |
| `securegeer/jwt`        | `jwt`, `verifyJwt`, `decodeJwt`, `JWTWithRotation`, errors      |
| `securegeer/hmac`       | `hmacSign`, `hmacVerify` (used internally by `jwt`)             |
| `securegeer/hash`       | `hashPassword`, `verifyPasswordHash`, `sha256`                  |

## Usage

```ts
import { encrypt, decryptJSON, generateSecret } from 'securegeer/encryption';
import { jwt, verifyJwt } from 'securegeer/jwt';
import { hmacSign, hmacVerify } from 'securegeer/hmac';
import { hashPassword, verifyPasswordHash } from 'securegeer/hash';

const secret = generateSecret();
const token = await encrypt({ userId: 123 }, secret); // "salt:iv:ciphertext" (base64url)
const data = await decryptJSON<{ userId: number }>(token, secret);

const accessToken = await jwt({ sub: '1' }, secret, { algorithm: 'HS256', expiresIn: '1h' });
const payload = await verifyJwt(accessToken, secret, { algorithm: 'HS256' });

const signature = await hmacSign('payload', secret); // base64url, SHA-256 by default
const ok = await hmacVerify('payload', signature, secret);

const stored = await hashPassword('hunter2'); // "pbkdf2-sha256$100000$salt$hash"
await verifyPasswordHash(stored, 'hunter2');

// Optional pepper: a server secret mixed in before hashing, never stored with the hash.
// Required on verify too; losing or changing it invalidates every hash created with it.
const peppered = await hashPassword('hunter2', { pepper: env.PASSWORD_PEPPER });
await verifyPasswordHash(peppered, 'hunter2', { pepper: env.PASSWORD_PEPPER });
```

### Key rotation

Both `encryption` and `jwt` support versioned secrets. Provide `{ENCRYPTION|JWT}_CURRENT_VERSION`
and `{ENCRYPTION|JWT}_SECRET_V{n}` in your environment:

```ts
import { EncryptionWithRotation, initKeyRotationFromEnv } from 'securegeer/encryption';

const service = new EncryptionWithRotation(initKeyRotationFromEnv(env));
const encrypted = await service.encrypt('secret'); // "v2:salt:iv:ciphertext"
const plain = await service.decrypt(encrypted); // current + 1 previous version accepted

if (service.needsReEncryption(encrypted)) {
  const migrated = await service.reEncrypt(encrypted);
}
```

`securegeer/jwt` exposes the same pattern via `JWTWithRotation` and its own
`initKeyRotationFromEnv`.

## Scripts

| Script              | Description                      |
| ------------------- | -------------------------------- |
| `bun run build`     | Compile `src` to `dist` with tsc |
| `bun run typecheck` | Type-check sources and tests     |
| `bun test`          | Run the test suite               |
| `bun run format`    | Format with Prettier             |

## Encryption format and secrets

`encrypt` derives a fresh AES-256-GCM key for every message using HKDF-SHA256 with a random 16-byte
salt, and returns `salt:iv:ciphertext` (base64url). This is cheap on CPU and removes the usual limit
on messages per key.

- **Secrets must be high-entropy** (at least 32 characters; use `generateSecret()`). HKDF does not
  slow down brute-force attacks, so don't use human-chosen passwords. Use `hash` for passwords.
