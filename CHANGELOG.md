# Changelog

All notable changes to `@agenticvalley/pqjwt` are documented in this file. The
format follows the Keep a Changelog convention, and this project adheres to
Semantic Versioning.

## [0.1.1] - 2026-10-26

### Added

- The default (namespace) export now also carries `ErrorCode`, every error class
  (`PqJwtError`, `TokenExpiredError`, …), `SignatureAlgorithm`, the algorithm
  constants and registry helpers, the low-level signing/encoding helpers, and
  `parseToken`. So `pqjwt.ErrorCode.TOKEN_EXPIRED`, `pqjwt.SignatureAlgorithm`,
  and friends now work without any named imports.

## [0.1.0] - 2026-09-27

### Added

- **Post-quantum-only JWT/JWS.** Create and verify compact JSON Web Tokens
  signed exclusively with NIST **ML-DSA** (FIPS-204), per RFC 9964. No classical
  algorithms, no hybrids, and no `alg: none`.
  - `signJwt(payload, privateKey, options?)` — RFC 7515 §5.1 compact-JWS signing
    with convenience claim options (`issuer`, `audience`, `expiresIn`,
    `notBefore`, `issuedAt`, `subject`, `jwtId`).
  - `verifyJwt(token, key, options?)` — RFC 7515 §5.2 signature verification with
    strict algorithm pinning, followed by RFC 7519 §7.2 claim validation
    (`exp`, `nbf`, `iat`/`maxTokenAge`, `iss`, `aud`, `sub`, `jti`,
    `requiredClaims`, `clockTolerance`). Accepts a single key or a key set.
  - `decodeJwt` / `decodeProtectedHeader` / `parseToken` — inspection without
    verification.
- **Familiar single-namespace facade.** A default export plus `sign` / `verify` /
  `decode` aliases: `verify` returns the claims directly and supports an
  Express-style `(err, claims)` callback that never throws; `decode` returns
  `null` on malformed input. Human-friendly durations (`expiresIn: '1h'`) are
  accepted alongside numeric seconds and `Date`s.
- **Keys as AKP JWKs** (RFC 9964).
  - `generateKeyPair(algorithm?, options?)` producing `{ privateKey, publicKey }`
    AKP JWKs, with the seed-form `priv` (RFC 9964 §4).
  - `jwkThumbprint` (RFC 7638) used as the default `kid`, `toPublicJwk`, and
    strict `assertPublicJwk` / `assertPrivateJwk` validators.
- **Algorithms.** `ML-DSA-44`, `ML-DSA-65` (default), and `ML-DSA-87`, with a
  crypto-agile registry and low-level `signWithSeed` / `verifySignature` /
  `derivePublicKey` / `generateSeed` primitives.
- **Typed error hierarchy** with stable `ErrorCode`s: `TokenExpiredError`,
  `TokenNotBeforeError`, `SignatureVerificationError`, `ClaimValidationError`,
  `TokenMalformedError`, `InvalidKeyError`, and more.
- **Tests** including a known-answer test against the RFC 9964 Appendix A
  all-zeros vectors (public key + JWK thumbprint) for all three parameter sets.

[0.1.0]: https://github.com/agenticvalley/pqjwt/releases/tag/v0.1.0
