# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-20

### Added

- `securegeer/encryption`: AES-256-GCM `encrypt`, `decrypt`, `decryptJSON`, `generateSecret`, with
  stateless key rotation.
- `securegeer/jwt`: `jwt`, `verifyJwt`, `decodeJwt` (HS256/384/512), `JWTWithRotation` and typed
  errors.
- `securegeer/hmac`: `hmacSign` and `hmacVerify`.
- `securegeer/hash`: `hashPassword`, `verifyPasswordHash` and `sha256`.
- Zero runtime dependencies; works in Cloudflare Workers, Bun, Deno, browsers and Node.js 18+.
- MIT license.

[1.0.0]: https://www.npmjs.com/package/securegeer/v/1.0.0
