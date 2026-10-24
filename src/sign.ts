/**
 * @packageDocumentation
 * Token **creation** — the signing half of the library.
 *
 * {@link signJwt} follows the JWS Compact Serialization signing procedure of
 * RFC 7515 §5.1, specialized to post-quantum ML-DSA:
 *
 * 1. Assemble the **JOSE header** `{ "alg": "ML-DSA-…", "typ": "JWT", … }`.
 * 2. Assemble the **JWT Claims Set** (the payload), applying convenience options
 *    such as `expiresIn` → `exp`.
 * 3. Compute the two encoded segments and join them into the **Signing Input**:
 *    `BASE64URL(UTF8(header)) || '.' || BASE64URL(UTF8(claims))`.
 * 4. **Sign** the ASCII bytes of that Signing Input with ML-DSA.
 * 5. Append `'.' || BASE64URL(signature)` to obtain the finished token.
 */

import { signWithSeed } from './crypto/mldsa.js';
import { InvalidArgumentError } from './errors.js';
import { assertPrivateJwk, type PrivateJwk } from './jwk.js';
import type { JoseHeader, JwtClaims, SignJwtOptions } from './types.js';
import {
  base64UrlDecode,
  base64UrlEncode,
  base64UrlEncodeString,
  nowInSeconds,
  resolveTimeClaim,
  stringifyJson,
  toNumericDate,
  utf8ToBytes,
} from './utils/index.js';

/**
 * Sign a set of claims into a compact, post-quantum JWT.
 *
 * @param payload - The {@link JwtClaims} to embed. Convenience options below can
 *   set or override individual registered claims.
 * @param privateKey - The signer's private AKP JWK (its `alg` selects the
 *   ML-DSA suite).
 * @param options - {@link SignJwtOptions}.
 * @returns The signed token in compact form: `header.payload.signature`.
 * @throws {InvalidArgumentError} If `payload` is not a plain object.
 * @throws {InvalidKeyError} If `privateKey` is not a valid private AKP JWK.
 *
 * @example
 * ```ts
 * const token = signJwt(
 *   { sub: 'agent-42', role: 'reader' },
 *   privateKey,
 *   { issuer: 'https://issuer.example', audience: 'https://api.example', expiresIn: 3600 },
 * );
 * ```
 */
export function signJwt(payload: JwtClaims, privateKey: PrivateJwk, options: SignJwtOptions = {}): string {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new InvalidArgumentError('JWT payload must be a plain claims object');
  }

  const key = assertPrivateJwk(privateKey);
  const seed = base64UrlDecode(key.priv);
  const now = nowInSeconds(options.clock);

  const header = buildHeader(key, options);
  const claims = buildClaims(payload, options, now);

  // The Signing Input is pure ASCII (both segments are base64url), so a UTF-8
  // encode of the joined string yields exactly the bytes RFC 7515 signs over.
  const encodedHeader = base64UrlEncodeString(stringifyJson(header));
  const encodedPayload = base64UrlEncodeString(stringifyJson(claims));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signature = signWithSeed(key.alg, seed, utf8ToBytes(signingInput), {
    deterministic: options.deterministic === true,
  });

  return `${signingInput}.${base64UrlEncode(signature)}`;
}

/**
 * Assemble the protected JOSE header.
 *
 * `alg` is always taken from the signing key and is written **last** so that no
 * caller-supplied `header` entry can smuggle in a different (or downgraded)
 * algorithm.
 */
function buildHeader(key: PrivateJwk, options: SignJwtOptions): JoseHeader {
  const header: JoseHeader = {
    ...(options.header ?? {}),
    alg: key.alg,
  };

  // `typ` defaults to "JWT" and can be omitted entirely with `typ: false`.
  if (options.typ !== false) {
    header.typ = options.typ ?? 'JWT';
  }

  // `kid` defaults to the key's own thumbprint, letting verifiers select it.
  const kid = options.kid ?? key.kid;
  if (kid !== undefined) {
    header.kid = kid;
  }

  return header;
}

/**
 * Assemble the JWT Claims Set by layering the convenience options over the
 * caller-provided payload. Explicit options win over pre-existing claims.
 */
function buildClaims(payload: JwtClaims, options: SignJwtOptions, now: number): JwtClaims {
  const claims: JwtClaims = { ...payload };

  if (options.issuer !== undefined) {
    claims.iss = options.issuer;
  }
  if (options.subject !== undefined) {
    claims.sub = options.subject;
  }
  if (options.audience !== undefined) {
    claims.aud = options.audience;
  }
  if (options.jwtId !== undefined) {
    claims.jti = options.jwtId;
  }

  // `iat`: default to now, honour an explicit value, or drop it with `false`.
  if (options.issuedAt === false) {
    delete claims.iat;
  } else if (options.issuedAt !== undefined) {
    claims.iat = toNumericDate(options.issuedAt);
  } else {
    // Default to "now" only when the caller has not already supplied `iat`.
    claims.iat ??= now;
  }

  // `nbf` / `exp`: a number is a relative offset in seconds from `now`.
  if (options.notBefore !== undefined) {
    claims.nbf = resolveTimeClaim(options.notBefore, now);
  }
  if (options.expiresIn !== undefined) {
    claims.exp = resolveTimeClaim(options.expiresIn, now);
  }

  return claims;
}
