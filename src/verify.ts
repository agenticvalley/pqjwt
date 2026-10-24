/**
 * @packageDocumentation
 * Token **verification** — the security-critical half of the library.
 *
 * {@link verifyJwt} implements the JWS validation procedure of
 * RFC 7515 §5.2 followed by the JWT claim checks of RFC 7519 §7.2, in the only
 * safe order:
 *
 * 1. **Parse** the compact token into header, claims and signature.
 * 2. **Pin the algorithm.** The header `alg` must be a supported ML-DSA suite
 *    *and* be on the caller's allow-list. This is the front-line defence against
 *    algorithm-substitution / `alg: none` downgrade attacks — and here it is
 *    doubly moot, because the library has no classical or `none` code path to
 *    downgrade *to*.
 * 3. **Verify the signature** against the chosen public key(s). Only after this
 *    succeeds is the payload considered authentic.
 * 4. **Apply claim policy** (`exp`, `nbf`, `iat`/`maxTokenAge`, `iss`, `aud`,
 *    `sub`, `jti`, required claims).
 *
 * Authenticate first, then authorize: nothing from the payload is trusted until
 * step 3 has passed.
 */

import { SUPPORTED_ALGORITHMS, type SignatureAlgorithm, isSignatureAlgorithm } from './crypto/algorithms.js';
import { verifySignature } from './crypto/mldsa.js';
import {
  ClaimValidationError,
  ErrorCode,
  SignatureVerificationError,
  TokenExpiredError,
  TokenMalformedError,
  TokenNotBeforeError,
} from './errors.js';
import { parseToken } from './decode.js';
import { publicKeyBytes, type PrivateJwk, type PublicJwk } from './jwk.js';
import type { DecodedToken, JoseHeader, JwtClaims, VerifyJwtOptions } from './types.js';
import { nowInSeconds, utf8ToBytes } from './utils/index.js';

/**
 * A verification key, or a set of them.
 *
 * Pass a single JWK for the common one-key case, or an array to represent a key
 * set (e.g. a published JWKS) — the token's `kid` and `alg` are used to pick the
 * right one. Private JWKs are accepted too, since they contain the public part.
 */
export type VerificationKeyInput = PublicJwk | PrivateJwk | readonly (PublicJwk | PrivateJwk)[];

/**
 * Verify a compact post-quantum JWT and return its authenticated contents.
 *
 * @typeParam T - The concrete claims shape for typed access to the result.
 * @param token - The compact token string to verify.
 * @param key - The verification key or key set. See {@link VerificationKeyInput}.
 * @param options - {@link VerifyJwtOptions} to tighten algorithm and claim policy.
 * @returns The authenticated {@link DecodedToken} (`header` and `payload`).
 * @throws {TokenMalformedError} If the token is not well formed.
 * @throws {SignatureVerificationError} If the algorithm is disallowed, no key
 *   matches, or the signature does not verify.
 * @throws {TokenExpiredError} If `exp` is in the past.
 * @throws {TokenNotBeforeError} If `nbf` is in the future.
 * @throws {ClaimValidationError} If any other claim policy fails.
 *
 * @example
 * ```ts
 * const { payload } = verifyJwt(token, publicKey, {
 *   issuer: 'https://issuer.example',
 *   audience: 'https://api.example',
 *   clockTolerance: 5,
 * });
 * ```
 */
export function verifyJwt<T extends JwtClaims = JwtClaims>(
  token: string,
  key: VerificationKeyInput,
  options: VerifyJwtOptions = {},
): DecodedToken<T> {
  const parsed = parseToken<T>(token);
  const { header, payload, signingInput, signature } = parsed;

  // Step 2 — pin the algorithm before touching any key material.
  const algorithm = resolveAlgorithm(header, options);

  // Optional header `typ` check (RFC 7515 §4.1.9), if the caller requires one.
  if (options.typ !== undefined) {
    assertHeaderTyp(header, options.typ);
  }

  // Step 3 — verify the signature against every candidate key until one matches.
  const candidates = selectCandidateKeys(algorithm, header, normalizeKeys(key));
  const messageBytes = utf8ToBytes(signingInput);
  const verified = candidates.some((candidate) =>
    verifySignature(algorithm, publicKeyBytes(candidate), messageBytes, signature),
  );
  if (!verified) {
    throw new SignatureVerificationError('signature verification failed', ErrorCode.SIGNATURE_INVALID, {
      context: { alg: algorithm, kid: header.kid },
    });
  }

  // Step 4 — the payload is now authentic; apply the caller's claim policy.
  validateClaims(payload, options);

  return { header, payload };
}

/** Normalize the key input into an array of candidate JWKs. */
function normalizeKeys(key: VerificationKeyInput): readonly (PublicJwk | PrivateJwk)[] {
  if (Array.isArray(key)) {
    return key as readonly (PublicJwk | PrivateJwk)[];
  }
  return [key as PublicJwk | PrivateJwk];
}

/**
 * Validate the header `alg` and confirm it is on the allow-list.
 *
 * @throws {SignatureVerificationError} If `alg` is missing, unsupported, or not
 *   among the accepted algorithms.
 */
function resolveAlgorithm(header: JoseHeader, options: VerifyJwtOptions): SignatureAlgorithm {
  const alg = header.alg;
  if (!isSignatureAlgorithm(alg)) {
    // Covers a missing/garbage `alg` and, notably, `"none"`.
    throw new SignatureVerificationError('unsupported or missing "alg" header', ErrorCode.ALGORITHM_NOT_ALLOWED, {
      context: { alg: typeof alg === 'string' ? alg : String(alg) },
    });
  }
  const allowed = options.algorithms ?? SUPPORTED_ALGORITHMS;
  if (!allowed.includes(alg)) {
    throw new SignatureVerificationError(`algorithm "${alg}" is not accepted`, ErrorCode.ALGORITHM_NOT_ALLOWED, {
      context: { alg, allowed: allowed.join(',') },
    });
  }
  return alg;
}

/**
 * Choose the candidate keys to try, honouring the `kid` hint when present.
 *
 * @throws {SignatureVerificationError} If no key can plausibly match.
 */
function selectCandidateKeys(
  algorithm: SignatureAlgorithm,
  header: JoseHeader,
  keys: readonly (PublicJwk | PrivateJwk)[],
): readonly (PublicJwk | PrivateJwk)[] {
  const byAlg = keys.filter((k) => k.alg === algorithm);
  if (byAlg.length === 0) {
    throw new SignatureVerificationError('no verification key matches the token algorithm', ErrorCode.KEY_NOT_FOUND, {
      context: { alg: algorithm },
    });
  }

  const kid = header.kid;
  if (typeof kid !== 'string') {
    return byAlg;
  }

  // Prefer keys whose `kid` matches; otherwise fall back to keys that carry no
  // `kid` at all (a `kid` is only a hint). Keys with a *different* explicit
  // `kid` are deliberately excluded.
  const exact = byAlg.filter((k) => k.kid === kid);
  if (exact.length > 0) {
    return exact;
  }
  const anonymous = byAlg.filter((k) => k.kid === undefined);
  if (anonymous.length === 0) {
    throw new SignatureVerificationError('no verification key matches the token "kid"', ErrorCode.KEY_NOT_FOUND, {
      context: { kid },
    });
  }
  return anonymous;
}

/** Confirm the header `typ` matches the expected media type (case/prefix-insensitive). */
function assertHeaderTyp(header: JoseHeader, expected: string): void {
  const actual = header.typ;
  if (typeof actual !== 'string' || normalizeMediaType(actual) !== normalizeMediaType(expected)) {
    throw new TokenMalformedError(`unexpected "typ" header; expected "${expected}"`, ErrorCode.HEADER_INVALID, {
      context: { typ: typeof actual === 'string' ? actual : String(actual) },
    });
  }
}

/** Lower-case a media type and drop an optional `application/` prefix (RFC 7515 §4.1.9). */
function normalizeMediaType(value: string): string {
  const lower = value.toLowerCase();
  return lower.startsWith('application/') ? lower.slice('application/'.length) : lower;
}

/**
 * Apply the RFC 7519 §7.2 claim checks according to the caller's options.
 *
 * The signature has already been verified, so the payload is authentic; here we
 * decide whether an authentic token is also *acceptable* to this verifier.
 */
function validateClaims(payload: JwtClaims, options: VerifyJwtOptions): void {
  const now = nowInSeconds(options.clock);
  const tolerance = options.clockTolerance ?? 0;

  // --- Time-based claims ---------------------------------------------------
  if (payload.exp !== undefined) {
    const exp = asNumericDate(payload.exp, 'exp');
    // Expired once "now" (minus leeway) has reached the expiry instant.
    if (now - tolerance >= exp) {
      throw new TokenExpiredError(exp);
    }
  }

  if (payload.nbf !== undefined) {
    const nbf = asNumericDate(payload.nbf, 'nbf');
    // Not yet valid while "now" (plus leeway) is still before the nbf instant.
    if (nbf - tolerance > now) {
      throw new TokenNotBeforeError(nbf);
    }
  }

  if (payload.iat !== undefined) {
    asNumericDate(payload.iat, 'iat');
  }

  if (options.maxTokenAge !== undefined) {
    if (payload.iat === undefined) {
      throw new ClaimValidationError(ErrorCode.CLAIM_MISMATCH, '"iat" claim is required to enforce maxTokenAge');
    }
    const age = now - asNumericDate(payload.iat, 'iat');
    if (age - tolerance > options.maxTokenAge) {
      throw new ClaimValidationError(ErrorCode.CLAIM_MISMATCH, 'token exceeds the maximum allowed age', {
        context: { age, maxTokenAge: options.maxTokenAge },
      });
    }
  }

  // --- Identity claims -----------------------------------------------------
  if (options.issuer !== undefined) {
    const allowed = toArray(options.issuer);
    if (typeof payload.iss !== 'string' || !allowed.includes(payload.iss)) {
      throw new ClaimValidationError(ErrorCode.CLAIM_MISMATCH, 'unexpected "iss" claim', {
        context: { iss: typeof payload.iss === 'string' ? payload.iss : String(payload.iss) },
      });
    }
  }

  if (options.audience !== undefined) {
    const wanted = toArray(options.audience);
    const present = payload.aud === undefined ? [] : Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!present.some((entry) => wanted.includes(entry))) {
      throw new ClaimValidationError(ErrorCode.CLAIM_MISMATCH, 'unexpected "aud" claim');
    }
  }

  if (options.subject !== undefined && payload.sub !== options.subject) {
    throw new ClaimValidationError(ErrorCode.CLAIM_MISMATCH, 'unexpected "sub" claim');
  }

  if (options.jwtId !== undefined && payload.jti !== options.jwtId) {
    throw new ClaimValidationError(ErrorCode.CLAIM_MISMATCH, 'unexpected "jti" claim');
  }

  // --- Presence checks -----------------------------------------------------
  for (const claim of options.requiredClaims ?? []) {
    if (payload[claim] === undefined) {
      throw new ClaimValidationError(ErrorCode.CLAIM_MISMATCH, `missing required claim "${claim}"`, {
        context: { claim },
      });
    }
  }
}

/** Assert a claim value is a finite number (a NumericDate) and return it. */
function asNumericDate(value: unknown, claim: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new TokenMalformedError(`"${claim}" claim must be a NumericDate (number)`, ErrorCode.CLAIMS_INVALID, {
      context: { claim },
    });
  }
  return value;
}

/** Coerce a single value or a readonly array into a mutable array. */
function toArray<V>(value: V | readonly V[]): V[] {
  return Array.isArray(value) ? [...(value as readonly V[])] : [value as V];
}
