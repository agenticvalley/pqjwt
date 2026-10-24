/**
 * @packageDocumentation
 * JSON Web Keys for post-quantum signatures — the **AKP** key type.
 *
 * RFC 9964 introduces a new JWK
 * `kty` called **AKP** ("Algorithm Key Pair") to carry ML-DSA (and, in general,
 * other "just a public/private byte string" post-quantum) keys. An AKP JWK looks
 * like this:
 *
 * ```json
 * {
 *   "kty": "AKP",
 *   "alg": "ML-DSA-65",
 *   "pub": "Qksv...db0d",                // base64url public key  (REQUIRED)
 *   "priv": "AAAA...AAA",                // base64url 32-byte seed (private keys only)
 *   "kid": "Suiu29qbfuaBaR4Ats-c6X..."   // JWK thumbprint         (OPTIONAL)
 * }
 * ```
 *
 * Key facts this module encodes:
 * - `pub` is the raw public key, base64url-encoded (RFC 9964 §5).
 * - `priv` is the **32-byte seed**, base64url-encoded, and MUST NOT appear in a
 *   public JWK (RFC 9964 §4).
 * - `kid`, when present, is the JWK Thumbprint
 *   (RFC 7638) computed over the
 *   required members `alg`, `kty`, `pub` in lexicographic order (RFC 9964 §6).
 */

import { sha256 } from '@noble/hashes/sha2';
import {
  DEFAULT_SIGNATURE_ALGORITHM,
  type SignatureAlgorithm,
  getSignatureAlgorithmInfo,
  isSignatureAlgorithm,
} from './crypto/algorithms.js';
import { derivePublicKey, generateSeed } from './crypto/mldsa.js';
import { InvalidKeyError } from './errors.js';
import { base64UrlDecode, base64UrlEncode, canonicalJson } from './utils/index.js';

/** The JWK key-type value for post-quantum Algorithm Key Pairs (RFC 9964). */
export const AKP_KEY_TYPE = 'AKP';

/**
 * A **public** AKP JSON Web Key: everything needed to *verify* a token, and
 * nothing that could *sign* one.
 */
export interface PublicJwk {
  /** Key type. Always the literal `"AKP"` for post-quantum keys (RFC 9964). */
  readonly kty: typeof AKP_KEY_TYPE;
  /** The ML-DSA parameter set this key is bound to (also the JWS `alg`). */
  readonly alg: SignatureAlgorithm;
  /** The raw public key, base64url-encoded. */
  readonly pub: string;
  /** Optional key id; when set by this library it is the RFC 7638 JWK thumbprint. */
  readonly kid?: string;
  /** Optional intended use. For signing keys this is `"sig"`. */
  readonly use?: 'sig';
  /** Optional permitted key operations, per RFC 7517. */
  readonly key_ops?: readonly ('sign' | 'verify')[];
}

/**
 * A **private** AKP JSON Web Key: a {@link PublicJwk} plus the secret `priv`
 * seed. Treat the whole object as sensitive.
 */
export interface PrivateJwk extends PublicJwk {
  /** The 32-byte ML-DSA seed (the private key), base64url-encoded (RFC 9964 §4). */
  readonly priv: string;
}

/** A generated key pair: the private JWK to keep, and the public JWK to publish. */
export interface JwkKeyPair {
  /** The private JWK — store this in your KMS/HSM; it can mint tokens. */
  readonly privateKey: PrivateJwk;
  /** The public JWK — publish this so others can verify your tokens. */
  readonly publicKey: PublicJwk;
}

/** Options for {@link generateKeyPair}. */
export interface GenerateKeyPairOptions {
  /**
   * A specific 32-byte seed to use instead of fresh randomness.
   *
   * Intended for reproducible tests and deterministic key-derivation flows only
   * — never reuse a seed across distinct keys in production.
   */
  readonly seed?: Uint8Array;
  /**
   * Whether to compute and attach the RFC 7638 JWK thumbprint as `kid`.
   * Defaults to `true`, since a stable `kid` is what lets a verifier select the
   * right key from a set.
   */
  readonly includeKid?: boolean;
}

/**
 * Generate a fresh post-quantum signing key pair as AKP JWKs.
 *
 * @param algorithm - The ML-DSA parameter set. Defaults to
 *   {@link DEFAULT_SIGNATURE_ALGORITHM} (ML-DSA-65).
 * @param options - {@link GenerateKeyPairOptions}.
 * @returns A {@link JwkKeyPair}. Persist `privateKey` somewhere trusted; share
 *   `publicKey`.
 * @throws {InvalidKeyError} If a supplied `seed` is not exactly 32 bytes.
 *
 * @example
 * ```ts
 * const { privateKey, publicKey } = generateKeyPair();
 * // privateKey.priv → keep secret;  publicKey → publish (e.g. in a JWKS)
 * ```
 */
export function generateKeyPair(
  algorithm: SignatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM,
  options: GenerateKeyPairOptions = {},
): JwkKeyPair {
  const seed = options.seed ?? generateSeed();
  // `derivePublicKey` validates the seed length for us and throws if it's wrong.
  const publicKeyBytes = derivePublicKey(algorithm, seed);

  const pub = base64UrlEncode(publicKeyBytes);
  const priv = base64UrlEncode(seed);

  // The thumbprint depends only on `alg`, `kty`, and `pub`, so it is identical
  // for the public and private JWKs of a pair.
  const kid = options.includeKid === false ? undefined : jwkThumbprint({ kty: AKP_KEY_TYPE, alg: algorithm, pub });

  const publicKey: PublicJwk = {
    kty: AKP_KEY_TYPE,
    alg: algorithm,
    pub,
    use: 'sig',
    ...(kid === undefined ? {} : { kid }),
  };

  const privateKey: PrivateJwk = {
    ...publicKey,
    priv,
  };

  return { privateKey, publicKey };
}

/**
 * Compute the RFC 7638 JWK Thumbprint of an AKP key, returned as base64url.
 *
 * Per RFC 9964 §6, the thumbprint is taken over exactly the required members
 * `alg`, `kty`, and `pub`, serialized as canonical JSON (keys sorted
 * lexicographically, no whitespace) and hashed with SHA-256. The result is the
 * conventional value for a key's `kid`.
 *
 * @param jwk - Any AKP JWK (public or private); only `alg`, `kty`, `pub` are used.
 * @returns The base64url-encoded SHA-256 thumbprint.
 */
export function jwkThumbprint(jwk: Pick<PublicJwk, 'kty' | 'alg' | 'pub'>): string {
  // Only the three required members participate, in lexicographic key order:
  // "alg" < "kty" < "pub". `canonicalJson` performs the sort.
  const canonical = canonicalJson({ alg: jwk.alg, kty: jwk.kty, pub: jwk.pub });
  return base64UrlEncode(sha256(new TextEncoder().encode(canonical)));
}

/**
 * Strip the secret `priv` member from a private JWK, yielding a shareable public
 * JWK. Useful right before publishing a key you generated.
 *
 * @param jwk - The private JWK.
 * @returns The corresponding public JWK, with `priv` removed.
 */
export function toPublicJwk(jwk: PrivateJwk): PublicJwk {
  const { priv: _priv, ...publicJwk } = jwk;
  return publicJwk;
}

/**
 * Validate the shape of a public AKP JWK and return it narrowed.
 *
 * @param jwk - An untrusted value that should be a public AKP JWK.
 * @returns The same object, typed as {@link PublicJwk}.
 * @throws {InvalidKeyError} If any required member is missing or malformed.
 */
export function assertPublicJwk(jwk: unknown): PublicJwk {
  if (typeof jwk !== 'object' || jwk === null) {
    throw new InvalidKeyError('JWK must be an object');
  }
  const candidate = jwk as Record<string, unknown>;

  if (candidate['kty'] !== AKP_KEY_TYPE) {
    throw new InvalidKeyError(`JWK "kty" must be "${AKP_KEY_TYPE}"`, { context: { kty: String(candidate['kty']) } });
  }
  if (!isSignatureAlgorithm(candidate['alg'])) {
    throw new InvalidKeyError('JWK "alg" is not a supported ML-DSA algorithm', {
      context: { alg: String(candidate['alg']) },
    });
  }
  if (typeof candidate['pub'] !== 'string' || candidate['pub'].length === 0) {
    throw new InvalidKeyError('JWK "pub" must be a non-empty base64url string');
  }

  // Cross-check that the decoded public key is the exact size the algorithm
  // mandates — a mismatch means a corrupted or mislabelled key.
  const info = getSignatureAlgorithmInfo(candidate['alg']);
  const pubBytes = base64UrlDecode(candidate['pub']);
  if (pubBytes.length !== info.publicKeyLength) {
    throw new InvalidKeyError(`JWK "pub" has the wrong length for ${candidate['alg']}`, {
      context: { alg: candidate['alg'], expected: info.publicKeyLength, actual: pubBytes.length },
    });
  }

  return jwk as PublicJwk;
}

/**
 * Validate the shape of a private AKP JWK and return it narrowed.
 *
 * @param jwk - An untrusted value that should be a private AKP JWK.
 * @returns The same object, typed as {@link PrivateJwk}.
 * @throws {InvalidKeyError} If any required member is missing or malformed, or
 *   if the `priv` seed is not 32 bytes.
 */
export function assertPrivateJwk(jwk: unknown): PrivateJwk {
  const publicPart = assertPublicJwk(jwk);
  const candidate = jwk as Record<string, unknown>;

  if (typeof candidate['priv'] !== 'string' || candidate['priv'].length === 0) {
    throw new InvalidKeyError('private JWK "priv" must be a non-empty base64url string');
  }
  const seedBytes = base64UrlDecode(candidate['priv']);
  const info = getSignatureAlgorithmInfo(publicPart.alg);
  if (seedBytes.length !== info.seedLength) {
    throw new InvalidKeyError(`private JWK "priv" (seed) must be ${info.seedLength} bytes`, {
      context: { alg: publicPart.alg, expected: info.seedLength, actual: seedBytes.length },
    });
  }

  return jwk as PrivateJwk;
}

/**
 * Decode and validate the public-key bytes carried by a public (or private) JWK.
 *
 * @param jwk - The JWK to read `pub` from.
 * @returns The raw public-key bytes.
 * @throws {InvalidKeyError} If the JWK or its `pub` member is malformed.
 */
export function publicKeyBytes(jwk: PublicJwk): Uint8Array {
  const valid = assertPublicJwk(jwk);
  return base64UrlDecode(valid.pub);
}

/**
 * Decode and validate the 32-byte seed carried by a private JWK.
 *
 * @param jwk - The private JWK to read `priv` from.
 * @returns The raw seed bytes.
 * @throws {InvalidKeyError} If the JWK or its `priv` member is malformed.
 */
export function seedBytes(jwk: PrivateJwk): Uint8Array {
  const valid = assertPrivateJwk(jwk);
  return base64UrlDecode(valid.priv);
}
