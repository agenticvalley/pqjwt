/**
 * @packageDocumentation
 * Typed error hierarchy.
 *
 * Every failure this library raises is a {@link PqJwtError} carrying a stable,
 * machine-readable {@link ErrorCode}. Consumers can branch on `.code` instead of
 * parsing message strings, and transport layers (HTTP, gRPC) can map codes to
 * status responses deterministically.
 *
 * The design reflects a common operational need: a caller
 * usually needs to distinguish "the token is cryptographically forged/altered"
 * (a security event) from "the token is simply expired" (an ordinary,
 * expected condition that warrants a token refresh rather than an alert).
 */

/**
 * Stable, machine-readable error codes.
 *
 * Codes are grouped by layer. Never renumber or repurpose an existing value —
 * only append — because downstream systems may switch on them.
 */
export enum ErrorCode {
  // --- Generic / input (1xxx) ----------------------------------------------
  /** A supplied argument was structurally invalid (wrong type, empty, etc.). */
  INVALID_ARGUMENT = 'E1000_INVALID_ARGUMENT',
  /** A requested feature or option is not supported. */
  UNSUPPORTED = 'E1001_UNSUPPORTED',
  /** A base64url / UTF-8 / JSON (de)serialization step failed. */
  ENCODING = 'E1002_ENCODING',

  // --- Cryptography (2xxx) -------------------------------------------------
  /** The `alg` is not a supported post-quantum signature algorithm. */
  UNSUPPORTED_ALGORITHM = 'E2000_UNSUPPORTED_ALGORITHM',
  /** A key was malformed, the wrong length, or otherwise unusable. */
  INVALID_KEY = 'E2001_INVALID_KEY',

  // --- Token structure (3xxx) ----------------------------------------------
  /** The compact serialization is not a well-formed `header.payload.signature`. */
  TOKEN_MALFORMED = 'E3000_TOKEN_MALFORMED',
  /** The JOSE header is present but semantically invalid (e.g. missing `alg`). */
  HEADER_INVALID = 'E3001_HEADER_INVALID',
  /** The JWT Claims Set is present but semantically invalid. */
  CLAIMS_INVALID = 'E3002_CLAIMS_INVALID',

  // --- Verification (4xxx) -------------------------------------------------
  /** The ML-DSA signature did not verify against the signing input. */
  SIGNATURE_INVALID = 'E4000_SIGNATURE_INVALID',
  /** The header `alg` was not among the caller's list of accepted algorithms. */
  ALGORITHM_NOT_ALLOWED = 'E4001_ALGORITHM_NOT_ALLOWED',
  /** No key matched the token's `kid` / algorithm. */
  KEY_NOT_FOUND = 'E4002_KEY_NOT_FOUND',

  // --- Claim policy (5xxx) -------------------------------------------------
  /** The `exp` claim is in the past: the token has expired. */
  TOKEN_EXPIRED = 'E5000_TOKEN_EXPIRED',
  /** The `nbf` claim is in the future: the token is not valid yet. */
  TOKEN_NOT_YET_VALID = 'E5001_TOKEN_NOT_YET_VALID',
  /** A registered claim (`iss`, `aud`, `sub`, `jti`, `iat`) failed a policy check. */
  CLAIM_MISMATCH = 'E5002_CLAIM_MISMATCH',
}

/** Structured, JSON-safe context attached to an error. */
export type ErrorContext = Record<string, string | number | boolean | null | undefined>;

/** Options accepted by every {@link PqJwtError} constructor. */
export interface PqJwtErrorOptions {
  /** Structured, JSON-safe context to aid debugging and logging. */
  readonly context?: ErrorContext;
  /** The underlying error that triggered this one, preserved for stack traces. */
  readonly cause?: unknown;
}

/**
 * Base class for every error raised by `@agenticvalley/pqjwt`.
 *
 * @example Branch on a stable code
 * ```ts
 * try {
 *   verifyJwt(token, publicKey);
 * } catch (err) {
 *   if (err instanceof PqJwtError && err.code === ErrorCode.TOKEN_EXPIRED) {
 *     // expected: prompt the client to refresh, don't page anyone
 *   }
 * }
 * ```
 */
export class PqJwtError extends Error {
  /** Stable, machine-readable classification of this error. */
  public readonly code: ErrorCode;
  /** Structured, JSON-safe context to aid debugging and logging. */
  public readonly context: ErrorContext | undefined;

  public constructor(code: ErrorCode, message: string, options: PqJwtErrorOptions = {}) {
    // `cause` is passed through to `Error` so the original stack is retained.
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = new.target.name;
    this.code = code;
    this.context = options.context;
    // Restore the prototype chain when compiled down to ES5-style targets.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** A caller passed a structurally invalid argument. */
export class InvalidArgumentError extends PqJwtError {
  public constructor(message: string, options?: PqJwtErrorOptions) {
    super(ErrorCode.INVALID_ARGUMENT, message, options);
  }
}

/** The requested signature algorithm is not a supported post-quantum suite. */
export class UnsupportedAlgorithmError extends PqJwtError {
  public constructor(message: string, options?: PqJwtErrorOptions) {
    super(ErrorCode.UNSUPPORTED_ALGORITHM, message, options);
  }
}

/** A key (JWK or raw bytes) was malformed, the wrong length, or unusable. */
export class InvalidKeyError extends PqJwtError {
  public constructor(message: string, options?: PqJwtErrorOptions) {
    super(ErrorCode.INVALID_KEY, message, options);
  }
}

/**
 * The token could not be parsed into its constituent parts, or one of those
 * parts was not valid base64url / UTF-8 / JSON.
 *
 * Carries a specific {@link ErrorCode} so callers can distinguish a malformed
 * compact serialization from an invalid header or claims set.
 */
export class TokenMalformedError extends PqJwtError {
  public constructor(
    message: string,
    code: ErrorCode.TOKEN_MALFORMED | ErrorCode.HEADER_INVALID | ErrorCode.CLAIMS_INVALID = ErrorCode.TOKEN_MALFORMED,
    options?: PqJwtErrorOptions,
  ) {
    super(code, message, options);
  }
}

/**
 * The cryptographic signature did not verify.
 *
 * This is the security-critical failure: the token was altered in transit, was
 * signed by the wrong key, or was never legitimately issued at all.
 */
export class SignatureVerificationError extends PqJwtError {
  public constructor(
    message: string,
    code:
      | ErrorCode.SIGNATURE_INVALID
      | ErrorCode.ALGORITHM_NOT_ALLOWED
      | ErrorCode.KEY_NOT_FOUND = ErrorCode.SIGNATURE_INVALID,
    options?: PqJwtErrorOptions,
  ) {
    super(code, message, options);
  }
}

/**
 * A registered claim failed a policy check.
 *
 * The signature was valid — the token is authentic — but its contents do not
 * satisfy the verifier's policy (wrong issuer/audience, replayed after expiry,
 * used before its `nbf`, etc.).
 */
export class ClaimValidationError extends PqJwtError {
  public constructor(
    code: ErrorCode.TOKEN_EXPIRED | ErrorCode.TOKEN_NOT_YET_VALID | ErrorCode.CLAIM_MISMATCH,
    message: string,
    options?: PqJwtErrorOptions,
  ) {
    super(code, message, options);
  }
}

/**
 * Specialization of {@link ClaimValidationError} for an expired `exp` claim.
 * Exposes the exact expiry instant so callers can log or surface it.
 */
export class TokenExpiredError extends ClaimValidationError {
  /** The instant (epoch seconds) at which the token expired. */
  public readonly expiredAt: number;

  public constructor(expiredAt: number, options?: PqJwtErrorOptions) {
    super(ErrorCode.TOKEN_EXPIRED, `token expired at ${new Date(expiredAt * 1000).toISOString()}`, options);
    this.expiredAt = expiredAt;
  }
}

/**
 * Specialization of {@link ClaimValidationError} for a token used before its
 * `nbf` (not-before) instant.
 */
export class TokenNotBeforeError extends ClaimValidationError {
  /** The instant (epoch seconds) before which the token must not be accepted. */
  public readonly notBefore: number;

  public constructor(notBefore: number, options?: PqJwtErrorOptions) {
    super(ErrorCode.TOKEN_NOT_YET_VALID, `token not valid before ${new Date(notBefore * 1000).toISOString()}`, options);
    this.notBefore = notBefore;
  }
}
