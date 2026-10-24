/**
 * @packageDocumentation
 * The public data model: JOSE headers, JWT Claims Sets, and the option bags for
 * signing and verifying. These mirror, member for member, the structures defined
 * in RFC 7515 (JWS) and RFC 7519 (JWT) — the only
 * difference this library makes is that `alg` is always a post-quantum ML-DSA
 * identifier.
 */

import type { SignatureAlgorithm } from './crypto/algorithms.js';
import type { Clock } from './utils/time.js';

/**
 * The **JOSE Header** of a signed JWT (RFC 7515 §4).
 *
 * It is the first segment of the token and describes how the signature was
 * produced. Because a JWT here is always a signed JWS in compact form, the whole
 * header is the "JWS Protected Header": it is integrity-protected by being fed,
 * verbatim, into the signature.
 */
export interface JoseHeader {
  /**
   * The signature algorithm (RFC 7515 §4.1.1). Always a post-quantum ML-DSA
   * identifier in this library — never `none`, never a classical algorithm.
   */
  alg: SignatureAlgorithm;
  /**
   * The media type of the complete token (RFC 7515 §4.1.9). Conventionally
   * `"JWT"`. Helps a recipient that juggles several token shapes tell them apart.
   */
  typ?: string;
  /** The media type of the payload (RFC 7515 §4.1.10), if it is not plain claims. */
  cty?: string;
  /**
   * Key ID (RFC 7515 §4.1.4): a hint identifying which key signed the token, so
   * a verifier holding several keys can pick the right one. This library sets it
   * to the RFC 7638 JWK thumbprint by default.
   */
  kid?: string;
  /** Any additional, application-specific header parameters. */
  [parameter: string]: unknown;
}

/**
 * A **JWT Claims Set** (RFC 7519 §4): the JSON object that is the token's
 * payload. The seven registered claims below are given first-class types; any
 * number of public or private custom claims may be added alongside them.
 *
 * All time claims are **NumericDate** values — integer seconds since the Unix
 * epoch (RFC 7519 §2).
 */
export interface JwtClaims {
  /** `iss` — Issuer: who minted the token (RFC 7519 §4.1.1). */
  iss?: string;
  /** `sub` — Subject: whom the token is about (RFC 7519 §4.1.2). */
  sub?: string;
  /** `aud` — Audience: who the token is intended for (RFC 7519 §4.1.3). */
  aud?: string | string[];
  /** `exp` — Expiration Time: reject at/after this instant (RFC 7519 §4.1.4). */
  exp?: number;
  /** `nbf` — Not Before: reject before this instant (RFC 7519 §4.1.5). */
  nbf?: number;
  /** `iat` — Issued At: when the token was created (RFC 7519 §4.1.6). */
  iat?: number;
  /** `jti` — JWT ID: a unique identifier, e.g. for replay detection (RFC 7519 §4.1.7). */
  jti?: string;
  /** Any additional public or private claims. */
  [claim: string]: unknown;
}

/**
 * Options for {@link signJwt}.
 *
 * Convenience options (`issuer`, `audience`, `expiresIn`, …) are a friendlier
 * way to set the corresponding registered claim; when both an option and an
 * explicit claim in the payload are present, the option wins.
 */
export interface SignJwtOptions {
  /**
   * The `typ` header value. Defaults to `"JWT"`. Pass `false` to omit the
   * header entirely (rarely needed).
   */
  typ?: string | false;
  /**
   * The `kid` header value. Defaults to the signing key's own `kid` (its JWK
   * thumbprint) when it has one. Set explicitly to override.
   */
  kid?: string;
  /** Extra protected-header parameters to merge in (cannot override `alg`). */
  header?: Readonly<Record<string, unknown>>;

  /** Sets the `iss` (Issuer) claim. */
  issuer?: string;
  /** Sets the `sub` (Subject) claim. */
  subject?: string;
  /** Sets the `aud` (Audience) claim. */
  audience?: string | string[];
  /** Sets the `jti` (JWT ID) claim. */
  jwtId?: string;

  /**
   * Sets the `exp` (Expiration) claim. A **number** is a relative lifetime in
   * **seconds** from now (e.g. `3600`); a **string** is a time span such as
   * `'1h'`, `'30m'`, or `'7d'`; a `Date` is an absolute instant.
   */
  expiresIn?: number | string | Date;
  /**
   * Sets the `nbf` (Not Before) claim. A **number** is a relative offset in
   * **seconds** from now; a **string** is a time span such as `'5m'`; a `Date`
   * is an absolute instant.
   */
  notBefore?: number | string | Date;
  /**
   * Controls the `iat` (Issued At) claim. Defaults to "now". Pass an explicit
   * `Date`/epoch-seconds to override, or `false` to omit `iat` altogether.
   */
  issuedAt?: number | Date | false;

  /**
   * Produce a deterministic ML-DSA signature instead of the default hedged
   * (randomized) one. Deterministic signing yields identical tokens for
   * identical inputs — convenient for tests, but hedged signing is recommended
   * for production.
   */
  deterministic?: boolean;

  /** Injectable clock (epoch milliseconds), primarily for deterministic tests. */
  clock?: Clock;
}

/**
 * Options for {@link verifyJwt}.
 *
 * By default the verifier accepts any supported ML-DSA algorithm and checks the
 * signature plus the time-based claims (`exp`, `nbf`). Supplying `issuer`,
 * `audience`, etc. turns on the corresponding policy checks.
 */
export interface VerifyJwtOptions {
  /**
   * The set of algorithms to accept. Defaults to **all** supported ML-DSA
   * suites. Pin this to a subset to enforce, say, category-5-only tokens. A
   * token whose header `alg` is not in this list is rejected before any
   * signature check — the well-known defence against algorithm-substitution.
   */
  algorithms?: readonly SignatureAlgorithm[];

  /** Require the `iss` claim to equal this value (or be one of these values). */
  issuer?: string | readonly string[];
  /** Require the `aud` claim to include this value (or one of these values). */
  audience?: string | readonly string[];
  /** Require the `sub` claim to equal this value. */
  subject?: string;
  /** Require the `jti` claim to equal this value. */
  jwtId?: string;
  /** Require every named claim to be present (in addition to any always-checked ones). */
  requiredClaims?: readonly string[];

  /**
   * Leeway, in **seconds**, applied when checking `exp` and `nbf` to tolerate
   * small clock skew between issuer and verifier. Defaults to `0`.
   */
  clockTolerance?: number;
  /**
   * Maximum allowed age, in **seconds**, computed from the `iat` claim. When
   * set, a token older than this is rejected even if it has not yet expired
   * (and `iat` becomes required).
   */
  maxTokenAge?: number;
  /** Expected `typ` header value; when set, the header `typ` must match it. */
  typ?: string;

  /** Injectable clock (epoch milliseconds), primarily for deterministic tests. */
  clock?: Clock;
}

/**
 * The result of decoding or verifying a token: its header and its claims.
 *
 * @typeParam T - The concrete claims shape, so callers can get typed access to
 *   their own custom claims.
 */
export interface DecodedToken<T extends JwtClaims = JwtClaims> {
  /** The decoded JOSE header. */
  readonly header: JoseHeader;
  /** The decoded JWT Claims Set. */
  readonly payload: T;
}
