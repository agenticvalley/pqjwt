/**
 * @packageDocumentation
 * The **only** module that talks directly to the concrete ML-DSA primitive.
 * Everything else in the library refers to algorithms by their
 * {@link SignatureAlgorithm} identifier and calls the small, stable surface
 * defined here, so the argument-order conventions and sizing details of the
 * underlying primitive are contained in one place.
 *
 * ## Seed-based keys (RFC 9964 §4)
 *
 * FIPS-204 defines two representations of an ML-DSA private key: a compact
 * 32-byte **seed**, and the larger **expanded** secret key derived from it.
 * RFC 9964 mandates the seed form for JOSE. We honour that: a private key is
 * *stored* and *moved around* as its 32-byte seed, and the expanded secret key
 * is re-derived transiently (via `keygen`) only for the instant it takes to
 * produce a signature. That keeps key material small and interoperable, and
 * means the expanded secret never has to be persisted.
 *
 * ## Hedged vs. deterministic signing
 *
 * FIPS-204's default ("hedged") signing mixes fresh randomness into each
 * signature, which hardens the private key against certain fault and
 * side-channel attacks. We default to hedged and expose a `deterministic`
 * opt-out for reproducible test vectors. Either variant is verified by the same
 * `verify` routine.
 */

import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { InvalidKeyError } from '../errors.js';
import { randomBytes } from '../utils/bytes.js';
import { SignatureAlgorithm, getSignatureAlgorithmInfo } from './algorithms.js';

/**
 * The ML-DSA signing **context** string.
 *
 * FIPS-204 signatures are bound to an optional application context. RFC 9964 §5
 * requires this context to be the **empty string** for `ML-DSA-44`, `ML-DSA-65`,
 * and `ML-DSA-87`, so we always pass an empty context on both the signing and
 * verifying side. (Passing a non-empty context here would silently break
 * interoperability, since the verifier must supply the identical context.)
 */
const EMPTY_CONTEXT = new Uint8Array(0);

/**
 * Structural view of the ML-DSA signer we depend on.
 *
 * In the pinned version the public calling convention is:
 * - `keygen(seed)` → `{ publicKey, secretKey }` (secretKey is the *expanded* key),
 * - `sign(secretKey, message, context, random?)` → signature bytes
 *   (omitting `random` yields the deterministic variant; supplying it hedges), and
 * - `verify(publicKey, message, signature, context)` → boolean.
 *
 * The `context` argument is the FIPS-204 context string — **not** randomness —
 * and must be identical on both sides; we always pass {@link EMPTY_CONTEXT}.
 * `signRandBytes` is the exact length of randomness a hedged signature consumes.
 */
interface MlDsaScheme {
  readonly signRandBytes: number;
  keygen(seed: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  sign(secretKey: Uint8Array, message: Uint8Array, context?: Uint8Array, random?: Uint8Array): Uint8Array;
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array, context?: Uint8Array): boolean;
}

/** Maps each supported algorithm to its concrete implementation. */
const ML_DSA_SCHEMES: Readonly<Record<SignatureAlgorithm, MlDsaScheme>> = {
  [SignatureAlgorithm.ML_DSA_44]: ml_dsa44,
  [SignatureAlgorithm.ML_DSA_65]: ml_dsa65,
  [SignatureAlgorithm.ML_DSA_87]: ml_dsa87,
};

/**
 * Generate a fresh, cryptographically random 32-byte ML-DSA seed.
 *
 * This seed **is** the private key (RFC 9964 §4); guard it with the same care as
 * any signing secret.
 *
 * @returns 32 bytes of CSPRNG output.
 */
export function generateSeed(): Uint8Array {
  return randomBytes(32);
}

/**
 * Validate that a seed is exactly 32 bytes, throwing a typed error otherwise.
 *
 * @param algorithm - The algorithm the seed is intended for (for the error context).
 * @param seed - The seed bytes to validate.
 * @throws {InvalidKeyError} If the seed is not exactly 32 bytes.
 */
function assertSeedLength(algorithm: SignatureAlgorithm, seed: Uint8Array): void {
  const { seedLength } = getSignatureAlgorithmInfo(algorithm);
  if (seed.length !== seedLength) {
    throw new InvalidKeyError(`ML-DSA seed must be exactly ${seedLength} bytes`, {
      context: { algorithm, expected: seedLength, actual: seed.length },
    });
  }
}

/**
 * Deterministically derive the public key for a given seed.
 *
 * @param algorithm - The ML-DSA parameter set.
 * @param seed - The 32-byte private seed.
 * @returns The corresponding public key bytes.
 * @throws {InvalidKeyError} If the seed is not 32 bytes.
 */
export function derivePublicKey(algorithm: SignatureAlgorithm, seed: Uint8Array): Uint8Array {
  assertSeedLength(algorithm, seed);
  return ML_DSA_SCHEMES[algorithm].keygen(seed).publicKey;
}

/** Options controlling how a signature is produced. */
export interface SignOptions {
  /**
   * When `true`, omit fresh randomness and produce the deterministic FIPS-204
   * signature (useful for reproducible test vectors). Defaults to `false`
   * (hedged), which is the FIPS-204-recommended mode.
   */
  readonly deterministic?: boolean;
}

/**
 * Produce a detached ML-DSA signature over `message` using a seed-form key.
 *
 * The expanded secret key is derived from the seed here and used only for this
 * call; it is never returned or retained.
 *
 * @param algorithm - The ML-DSA parameter set.
 * @param seed - The 32-byte private seed.
 * @param message - The exact bytes to sign (for a JWT, the signing input).
 * @param options - {@link SignOptions}.
 * @returns The signature bytes.
 * @throws {InvalidKeyError} If the seed is not 32 bytes.
 */
export function signWithSeed(
  algorithm: SignatureAlgorithm,
  seed: Uint8Array,
  message: Uint8Array,
  options: SignOptions = {},
): Uint8Array {
  assertSeedLength(algorithm, seed);
  const scheme = ML_DSA_SCHEMES[algorithm];
  const { secretKey } = scheme.keygen(seed);
  if (options.deterministic === true) {
    // Omitting the random argument selects the deterministic FIPS-204 variant.
    return scheme.sign(secretKey, message, EMPTY_CONTEXT);
  }
  // Hedged signing: empty context (RFC 9964) plus fresh randomness of the
  // primitive's required length.
  return scheme.sign(secretKey, message, EMPTY_CONTEXT, randomBytes(scheme.signRandBytes));
}

/**
 * Verify a detached ML-DSA signature over `message`.
 *
 * Returns `false` for a well-formed-but-invalid signature (the ordinary
 * "signature doesn't match" case, including a wrong-length signature that could
 * never be valid) and throws only for a structurally impossible input such as a
 * wrong-length public key, so callers can distinguish "forged/altered token"
 * from "misconfigured key".
 *
 * @param algorithm - The ML-DSA parameter set.
 * @param publicKey - The signer's public key bytes.
 * @param message - The bytes that were signed (the signing input).
 * @param signature - The signature bytes to check.
 * @returns `true` iff the signature is valid for `message` under `publicKey`.
 * @throws {InvalidKeyError} If the public key is the wrong length for `algorithm`.
 */
export function verifySignature(
  algorithm: SignatureAlgorithm,
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  const info = getSignatureAlgorithmInfo(algorithm);
  if (publicKey.length !== info.publicKeyLength) {
    throw new InvalidKeyError(`ML-DSA public key length mismatch for ${algorithm}`, {
      context: { algorithm, expected: info.publicKeyLength, actual: publicKey.length },
    });
  }
  // A signature of the wrong length can never be valid; treat as a soft failure
  // rather than letting it reach the primitive.
  if (signature.length !== info.signatureLength) {
    return false;
  }
  // Verify under the same empty context used when signing (RFC 9964 §5).
  return ML_DSA_SCHEMES[algorithm].verify(publicKey, message, signature, EMPTY_CONTEXT);
}
