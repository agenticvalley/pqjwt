# @agenticvalley/pqjwt

> Post-quantum-only JSON Web Tokens. The JWT you already know — signed
> exclusively with NIST **ML-DSA** (FIPS-204), per **RFC 9964**. No classical
> crypto, no hybrids, no `alg: none`.

`pqjwt` is a small, strict, dependency-light TypeScript library for issuing and
verifying **compact JWTs whose only signature algorithm is post-quantum**. It
keeps the familiar JWT mental model — a `header.payload.signature` string, the
registered claims (`iss`, `sub`, `aud`, `exp`, …), key IDs, JWKs — and swaps the
signature primitive for the Module-Lattice Digital Signature Algorithm
(**ML-DSA**, the standardized form of CRYSTALS-Dilithium).

## Why post-quantum only?

A large-scale quantum computer running Shor's algorithm would break every
classical signature scheme in production today (RSA, ECDSA, EdDSA). Tokens and
the keys behind them can have long lifetimes, and signatures captured today can
be challenged tomorrow — so "**harvest now, forge later**" is a real concern for
long-lived assertions.

Many migrations hedge with a **hybrid** (classical + PQC) signature. That is a
sensible transitional default — but this library intentionally does **not** do
it. `pqjwt` is for the destination, not the journey: a token minted here has

- **no classical component** an adversary could attack instead, and
- **no `none`/downgrade path** to be tricked into.

If you need a hybrid today, use a hybrid library. If you want pure post-quantum
tokens, this is that.

## How a JWT works internally (and where PQC slots in)

A signed JWT is a **JWS in compact serialization**
(RFC 7515). It is three base64url
segments joined by dots:

```text
       BASE64URL(UTF8(JOSE Header))
  '.'  BASE64URL(UTF8(JWT Claims Set))
  '.'  BASE64URL( Signature over the first two segments )
```

```text
  JOSE Header   { "alg": "ML-DSA-65", "typ": "JWT", "kid": … }
  JWT Claims    { "iss", "sub", "aud", "exp", "nbf", "iat", "jti", … }
       │
       │  base64url-encode each, then join with "."
       ▼
  Signing Input   =   encodedHeader "." encodedPayload
       │
       │  ML-DSA sign  (with the 32-byte seed)
       ▼
  Signature   ──►   base64url   ──►   encodedSignature
       │
       │  append with "."
       ▼
  Token   =   encodedHeader "." encodedPayload "." encodedSignature
```

1. **JOSE Header** — describes how the token was signed:
   `{ "alg": "ML-DSA-65", "typ": "JWT", "kid": "…" }`. Here `alg` is **always** a
   post-quantum ML-DSA identifier.
2. **JWT Claims Set** — the payload
   (RFC 7519): the registered claims
   plus your own. Time claims are **NumericDate** — integer seconds since the
   Unix epoch.
3. **Signature** — ML-DSA over the ASCII **Signing Input**
   `encodedHeader.encodedPayload`. This is the exact JWS procedure; only the
   algorithm is different.

Keys are **AKP** JSON Web Keys (the `kty` introduced by RFC 9964):

```json
{
  "kty": "AKP",
  "alg": "ML-DSA-65",
  "pub": "Qksv…", // base64url public key
  "priv": "AAAA…", // base64url 32-byte seed (private keys only)
  "kid": "Suiu29qbfuaBaR4Ats-c6XQBePB_OpAxAwcTR_0KXVM" // RFC 7638 thumbprint
}
```

## Install

```bash
npm install @agenticvalley/pqjwt
```

Requires Node.js ≥ 18. Ships as ESM with full TypeScript types.

## Quick start

```ts
import { generateKeyPair, signJwt, verifyJwt } from '@agenticvalley/pqjwt';

// 1. Create a post-quantum key pair (defaults to ML-DSA-65).
const { privateKey, publicKey } = generateKeyPair();

// 2. Sign some claims.
const token = signJwt({ sub: 'agent-42', scope: 'read:things' }, privateKey, {
  issuer: 'https://issuer.example',
  audience: 'https://api.example',
  expiresIn: 3600, // seconds → sets `exp`
});

// 3. Verify the signature AND the claim policy on the other side.
const { payload } = verifyJwt(token, publicKey, {
  issuer: 'https://issuer.example',
  audience: 'https://api.example',
});

console.log(payload.sub); // 'agent-42'
```

### Familiar single-import style

Prefer the classic one-object style? Import the default export and call methods
on it — including string lifetimes like `'1h'` and the Express-style callback:

```ts
import pqjwt from '@agenticvalley/pqjwt';

const { privateKey, publicKey } = pqjwt.generateKeyPair();

// Generate a token expiring in 1 hour
const token = pqjwt.sign({ sub: 'agent-42' }, privateKey, { expiresIn: '1h' });

// Verify on a protected route (Express-style callback)
pqjwt.verify(token, publicKey, (err, user) => {
  if (err) return res.sendStatus(403); // invalid or expired token
  req.user = user;
  next(); // proceed to the protected route
});
```

> ESM only: use `import pqjwt from '@agenticvalley/pqjwt'` (there is no CommonJS
> `require`). `sign` / `verify` / `decode` are also available as named imports.

Runnable examples live in [`examples/`](./examples):

```bash
npm run example:keys     # generate keys for every ML-DSA parameter set
npm run example:sign     # full sign → verify → tamper/expiry rejection
npm run example:decode   # inspect a header and pick a key from a set by kid
```

## API

### `generateKeyPair(algorithm?, options?) → { privateKey, publicKey }`

Generates an AKP JWK key pair. `algorithm` defaults to `ML-DSA-65`. Options:
`seed` (a specific 32-byte seed) and `includeKid` (attach the RFC 7638
thumbprint as `kid`, default `true`). **Keep `privateKey` secret** (store it in
your KMS/HSM); publish `publicKey`.

### `signJwt(payload, privateKey, options?) → string`

Produces a compact token. Convenience options set the corresponding registered
claim (and win over a claim already in `payload`):

| Option          | Sets   | Notes                                                       |
| --------------- | ------ | ----------------------------------------------------------- |
| `issuer`        | `iss`  |                                                             |
| `subject`       | `sub`  |                                                             |
| `audience`      | `aud`  | `string` or `string[]`                                      |
| `jwtId`         | `jti`  |                                                             |
| `expiresIn`     | `exp`  | `3600` (seconds), `'1h'`/`'30m'`/`'7d'` (span), or a `Date` |
| `notBefore`     | `nbf`  | `0` (seconds), `'5m'` (span), or a `Date`                   |
| `issuedAt`      | `iat`  | defaults to now; `false` omits it                           |
| `typ`           | header | defaults to `"JWT"`; `false` omits it                       |
| `kid`           | header | defaults to the key's own thumbprint                        |
| `header`        | header | extra protected-header params (cannot override `alg`)       |
| `deterministic` | —      | deterministic instead of the default hedged ML-DSA signing  |

### `verifyJwt(token, key, options?) → { header, payload }`

Verifies the signature, **then** applies claim policy. `key` may be a single JWK
or an array (a key set), selected by `kid`/`alg`. Options:

| Option           | Effect                                                                 |
| ---------------- | ---------------------------------------------------------------------- |
| `algorithms`     | Allow-list of accepted `alg`s (default: all ML-DSA). Rejects the rest. |
| `issuer`         | Require `iss` to match (string or list).                               |
| `audience`       | Require `aud` to include (string or list).                             |
| `subject`        | Require `sub` to equal.                                                |
| `jwtId`          | Require `jti` to equal.                                                |
| `requiredClaims` | Require these claims to be present.                                    |
| `clockTolerance` | Seconds of leeway for `exp`/`nbf` (default `0`).                       |
| `maxTokenAge`    | Max age in seconds derived from `iat` (makes `iat` required).          |
| `typ`            | Require the header `typ` to match.                                     |

Verification **fails closed**: a bad signature, a disallowed algorithm, or a
failed claim throws a typed error (see below) — it never returns a partial
result.

### `decodeJwt(token)` / `decodeProtectedHeader(token)`

Parse a token **without** verifying it. Useful for reading a `kid` to select a
key, or for debugging. **Never trust this output for authorization.**

### `sign` / `verify` / `decode` — the classic style

Ergonomic aliases with the classic shape, available as named imports and on the
default export. `sign` is `signJwt`. `verify` returns the **claims** directly
(not `{ header, payload }`) and additionally accepts a Node-style callback
`(err, claims) => …` that never throws — ideal for Express middleware. `decode`
returns the claims (or `{ header, payload }` with `{ complete: true }`) and
yields `null` on a malformed token instead of throwing.

### Low-level & helpers

`signWithSeed`, `verifySignature`, `derivePublicKey`, `generateSeed`,
`jwkThumbprint`, `toPublicJwk`, `assertPublicJwk`, `assertPrivateJwk`,
`publicKeyBytes`, `seedBytes`, `base64UrlEncode`, `base64UrlDecode`, and the full
algorithm registry (`SIGNATURE_ALGORITHMS`, `getSignatureAlgorithmInfo`, …).

## Algorithms

| `alg`       | NIST cat. | Public key | Signature | Seed | Notes                 |
| ----------- | :-------: | ---------: | --------: | :--: | --------------------- |
| `ML-DSA-44` |     2     |     1312 B |    2420 B | 32 B | ~AES-128              |
| `ML-DSA-65` |     3     |     1952 B |    3309 B | 32 B | **default**, ~AES-192 |
| `ML-DSA-87` |     5     |     2592 B |    4627 B | 32 B | ~AES-256              |

> **Token size.** Post-quantum signatures are large: an ML-DSA-65 token carries a
> ~3.3 KB signature (≈4.4 KB base64url), versus tens of bytes for ECDSA. This is
> the price of quantum resistance. Prefer sending these tokens in bodies or
> headers with adequate limits rather than tight URL query strings, and consider
> `kid` thumbprints instead of re-embedding public keys.

## Security notes

- **Keep `priv` secret.** The 32-byte seed _is_ the signing key; anyone with it
  can mint tokens. Store it in a KMS/HSM and never log it.
- **Algorithm pinning.** `verifyJwt` rejects any `alg` not on the allow-list
  before touching keys — the standard defence against algorithm substitution.
  Because there is no classical or `none` path, there is nothing to downgrade to.
- **Hedged by default.** Signatures use the FIPS-204 hedged (randomized) mode;
  pass `deterministic: true` only when you need reproducible test vectors.
- **Empty context.** Per RFC 9964 §5, the ML-DSA context is always the empty
  string.
- This library is **stateless**: it never stores keys or tokens. Replay
  protection (e.g. tracking `jti`) is the integrator's responsibility.

## Errors

Every failure is a `PqJwtError` subclass carrying a stable `.code`
(`ErrorCode`), so you can branch programmatically:

| Class                        | Example `code`              | Meaning                                     |
| ---------------------------- | --------------------------- | ------------------------------------------- |
| `TokenMalformedError`        | `E3000_TOKEN_MALFORMED`     | Not a well-formed compact token             |
| `SignatureVerificationError` | `E4000_SIGNATURE_INVALID`   | Forged/altered token, or disallowed `alg`   |
| `TokenExpiredError`          | `E5000_TOKEN_EXPIRED`       | `exp` in the past                           |
| `TokenNotBeforeError`        | `E5001_TOKEN_NOT_YET_VALID` | `nbf` in the future                         |
| `ClaimValidationError`       | `E5002_CLAIM_MISMATCH`      | `iss`/`aud`/`sub`/`jti`/required-claim fail |
| `InvalidKeyError`            | `E2001_INVALID_KEY`         | Malformed or wrong-size key                 |

```ts
import { verifyJwt, ErrorCode, PqJwtError } from '@agenticvalley/pqjwt';

try {
  verifyJwt(token, publicKey);
} catch (err) {
  if (err instanceof PqJwtError && err.code === ErrorCode.TOKEN_EXPIRED) {
    // expected: ask the client to refresh — don't page anyone
  }
}
```

## Standards

- **RFC 9964** — ML-DSA for JOSE and COSE (algorithm ids, the `AKP` key type,
  seed-form private keys, thumbprints).
- **RFC 7515 / 7519 / 7517 / 7518 / 7638** — JWS, JWT, JWK, JWA, JWK Thumbprint.
- **NIST FIPS-204** — the ML-DSA standard itself.

Cryptography is provided by audited, independently maintained libraries pinned
in `package.json`.

## Development

```bash
npm install
npm run check   # typecheck + lint + format:check + test
npm test        # vitest
npm run build   # emit dist/ (ESM + .d.ts)
```

## License

[MIT](./LICENSE) © AgenticValley
