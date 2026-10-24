/**
 * @packageDocumentation
 * The algorithm registry: the single source of truth for every signature suite
 * this library supports.
 *
 * ## Post-quantum only — by design
 *
 * This library deliberately supports **only** the NIST-standardized
 * Module-Lattice Digital Signature Algorithm, **ML-DSA** (FIPS-204, the
 * standardized form of CRYSTALS-Dilithium). There is:
 *
 * - **no** classical algorithm (no RS256/ES256/EdDSA), and
 * - **no** hybrid suite (no "classical + PQC" belt-and-braces mode).
 *
 * That is the whole point: a token minted here is unforgeable even by an
 * adversary holding a cryptographically-relevant quantum computer, with no
 * classical component that such an adversary could instead attack.
 *
 * The three parameter sets map to the three JOSE `alg` identifiers registered by
 * RFC 9964 ("ML-DSA for JOSE and COSE"). The exact key and signature sizes below
 * are taken from Table 1 of RFC 9964 / Table 2 of FIPS-204 and are fixed for each
 * parameter set.
 */

/**
 * The post-quantum signature algorithms usable as a JWS `alg` header value.
 *
 * The string values are the canonical JOSE identifiers from RFC 9964 and are
 * what actually appears, verbatim, inside a token's protected header.
 */
export enum SignatureAlgorithm {
  /** ML-DSA-44 — NIST security category 2 (~AES-128). FIPS-204 / RFC 9964. */
  ML_DSA_44 = 'ML-DSA-44',
  /** ML-DSA-65 — NIST security category 3 (~AES-192). FIPS-204 / RFC 9964. Recommended default. */
  ML_DSA_65 = 'ML-DSA-65',
  /** ML-DSA-87 — NIST security category 5 (~AES-256). FIPS-204 / RFC 9964. */
  ML_DSA_87 = 'ML-DSA-87',
}

/**
 * The recommended default suite.
 *
 * ML-DSA-65 (category 3, ~192-bit) is the balanced choice: comfortably beyond
 * the reach of foreseeable classical and quantum attacks, while keeping tokens
 * meaningfully smaller than ML-DSA-87.
 */
export const DEFAULT_SIGNATURE_ALGORITHM = SignatureAlgorithm.ML_DSA_65;

/**
 * NIST post-quantum "security category" — the work factor a scheme targets,
 * benchmarked against the cost of breaking AES/SHA at a given strength.
 */
export type SecurityCategory = 2 | 3 | 5;

/** Immutable metadata describing an ML-DSA parameter set. */
export interface SignatureAlgorithmInfo {
  /** Canonical JOSE identifier (also the JWS `alg` value). */
  readonly id: SignatureAlgorithm;
  /** Targeted NIST security category. */
  readonly securityCategory: SecurityCategory;
  /** Human-readable reference to the governing standard(s). */
  readonly standard: string;
  /**
   * Length in bytes of the private-key **seed**.
   *
   * RFC 9964 §4 mandates that an ML-DSA private key be represented as its
   * 32-byte seed (never the expanded secret key). This is what a JWK's `priv`
   * member carries, and what is expanded on demand to actually sign.
   */
  readonly seedLength: 32;
  /** Exact public-key length in bytes (FIPS-204 Table 2). */
  readonly publicKeyLength: number;
  /** Exact expanded secret-key length in bytes (derived from the seed to sign). */
  readonly secretKeyLength: number;
  /** Exact signature length in bytes (FIPS-204 Table 2). */
  readonly signatureLength: number;
}

/**
 * Registry of every supported ML-DSA parameter set.
 *
 * Sizes are the fixed values from RFC 9964 Table 1 / FIPS-204 Table 2. They are
 * asserted at runtime against the underlying primitive in the test suite, so a
 * dependency bump that silently changed a size could not go unnoticed.
 */
export const SIGNATURE_ALGORITHMS: Readonly<Record<SignatureAlgorithm, SignatureAlgorithmInfo>> = {
  [SignatureAlgorithm.ML_DSA_44]: {
    id: SignatureAlgorithm.ML_DSA_44,
    securityCategory: 2,
    standard: 'NIST FIPS-204 (ML-DSA) / RFC 9964',
    seedLength: 32,
    publicKeyLength: 1312,
    secretKeyLength: 2560,
    signatureLength: 2420,
  },
  [SignatureAlgorithm.ML_DSA_65]: {
    id: SignatureAlgorithm.ML_DSA_65,
    securityCategory: 3,
    standard: 'NIST FIPS-204 (ML-DSA) / RFC 9964',
    seedLength: 32,
    publicKeyLength: 1952,
    secretKeyLength: 4032,
    signatureLength: 3309,
  },
  [SignatureAlgorithm.ML_DSA_87]: {
    id: SignatureAlgorithm.ML_DSA_87,
    securityCategory: 5,
    standard: 'NIST FIPS-204 (ML-DSA) / RFC 9964',
    seedLength: 32,
    publicKeyLength: 2592,
    secretKeyLength: 4896,
    signatureLength: 4627,
  },
};

/** Every supported algorithm identifier, handy for iteration and validation. */
export const SUPPORTED_ALGORITHMS: readonly SignatureAlgorithm[] = Object.freeze(Object.values(SignatureAlgorithm));

/**
 * Type guard: is `value` one of the supported ML-DSA `alg` identifiers?
 *
 * @param value - Any value, typically an untrusted `alg` read from a token header.
 * @returns `true` if `value` is a supported {@link SignatureAlgorithm}.
 */
export function isSignatureAlgorithm(value: unknown): value is SignatureAlgorithm {
  return typeof value === 'string' && Object.prototype.hasOwnProperty.call(SIGNATURE_ALGORITHMS, value);
}

/**
 * Look up the immutable metadata for a supported algorithm.
 *
 * @param algorithm - A supported {@link SignatureAlgorithm}.
 * @returns The algorithm's {@link SignatureAlgorithmInfo}.
 */
export function getSignatureAlgorithmInfo(algorithm: SignatureAlgorithm): SignatureAlgorithmInfo {
  return SIGNATURE_ALGORITHMS[algorithm];
}
