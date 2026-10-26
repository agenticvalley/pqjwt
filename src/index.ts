/**
 * @packageDocumentation
 * # @agenticvalley/pqjwt
 *
 * **Post-quantum-only JSON Web Tokens.** The JWT you already know — the same
 * `header.payload.signature` compact tokens, the same registered claims, the
 * same mental model — but signed exclusively with the NIST post-quantum
 * signature standard **ML-DSA** (FIPS-204), per RFC 9964.
 *
 * There is **no classical fallback and no hybrid mode**: no RSA, no ECDSA, no
 * EdDSA, and crucially no `alg: none`. A token minted here cannot be forged by
 * an adversary with a large-scale quantum computer, and offers such an adversary
 * no weaker classical component to attack instead.
 *
 * ## How a token is built (the JWT internals, unchanged)
 *
 * A signed JWT is a JWS in *compact serialization* (RFC 7515):
 *
 * ```text
 *   BASE64URL(UTF8(JOSE Header))  ‖ '.' ‖
 *   BASE64URL(UTF8(JWT Claims))   ‖ '.' ‖
 *   BASE64URL(ML-DSA-Signature over the first two segments)
 * ```
 *
 * - **Header** — `{ "alg": "ML-DSA-65", "typ": "JWT", "kid": "…" }`.
 * - **Claims** — the RFC 7519 payload: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`,
 *   `jti`, plus your own.
 * - **Signature** — ML-DSA over `header.payload`, the exact procedure of any
 *   JWS; only the signature algorithm is post-quantum.
 *
 * Keys are expressed as **AKP** JSON Web Keys (RFC 9964): `{ "kty": "AKP",
 * "alg": "ML-DSA-65", "pub": "…", "priv": "…" }`, where `priv` is the 32-byte
 * seed and `kid` is the RFC 7638 JWK thumbprint.
 *
 * ## Statelessness
 *
 * This library never persists anything. You keep private keys wherever you trust
 * (an HSM/KMS or secure host) and publish public JWKs however you like (e.g. a
 * JWKS endpoint). Sign with the private JWK; verify with the public one.
 *
 * @example End to end
 * ```ts
 * import { generateKeyPair, signJwt, verifyJwt } from '@agenticvalley/pqjwt';
 *
 * // 1. Create a post-quantum key pair (defaults to ML-DSA-65).
 * const { privateKey, publicKey } = generateKeyPair();
 *
 * // 2. Sign some claims.
 * const token = signJwt(
 *   { sub: 'agent-42', scope: 'read:things' },
 *   privateKey,
 *   { issuer: 'https://issuer.example', audience: 'https://api.example', expiresIn: 3600 },
 * );
 *
 * // 3. Verify + validate on the other side.
 * const { payload } = verifyJwt(token, publicKey, {
 *   issuer: 'https://issuer.example',
 *   audience: 'https://api.example',
 * });
 * console.log(payload.sub); // 'agent-42'
 * ```
 *
 * @example Single-import, familiar `sign` / `verify` style
 * ```ts
 * import pqjwt from '@agenticvalley/pqjwt';
 *
 * const { privateKey, publicKey } = pqjwt.generateKeyPair();
 * const token = pqjwt.sign({ sub: 'agent-42' }, privateKey, { expiresIn: '1h' });
 *
 * // Express middleware — the callback form never throws:
 * pqjwt.verify(token, publicKey, (err, user) => {
 *   if (err) return res.sendStatus(403);
 *   req.user = user;
 *   next();
 * });
 * ```
 */

import {
  DEFAULT_SIGNATURE_ALGORITHM,
  SIGNATURE_ALGORITHMS,
  SUPPORTED_ALGORITHMS,
  SignatureAlgorithm,
  getSignatureAlgorithmInfo,
  isSignatureAlgorithm,
} from './crypto/algorithms.js';
import { derivePublicKey, generateSeed, signWithSeed, verifySignature } from './crypto/mldsa.js';
import { decodeJwt, decodeProtectedHeader, parseToken } from './decode.js';
import {
  ClaimValidationError,
  ErrorCode,
  InvalidArgumentError,
  InvalidKeyError,
  PqJwtError,
  SignatureVerificationError,
  TokenExpiredError,
  TokenMalformedError,
  TokenNotBeforeError,
  UnsupportedAlgorithmError,
} from './errors.js';
import {
  AKP_KEY_TYPE,
  assertPrivateJwk,
  assertPublicJwk,
  generateKeyPair,
  jwkThumbprint,
  publicKeyBytes,
  seedBytes,
  toPublicJwk,
} from './jwk.js';
import { decode, sign, verify } from './jwt.js';
import { signJwt } from './sign.js';
import { base64UrlDecode, base64UrlEncode } from './utils/base64url.js';
import { verifyJwt } from './verify.js';

// --- Core API ---------------------------------------------------------------
// `sign` / `verify` / `decode` are the familiar single-namespace facade; `signJwt` /
// `verifyJwt` / `decodeJwt` are the fuller forms that also expose the header.
export { sign, verify, decode, type VerifyCallback, type DecodeOptions } from './jwt.js';
export { signJwt } from './sign.js';
export { verifyJwt, type VerificationKeyInput } from './verify.js';
export { decodeJwt, decodeProtectedHeader, parseToken, type ParsedToken } from './decode.js';

// --- Keys (AKP JWKs) --------------------------------------------------------
export {
  AKP_KEY_TYPE,
  generateKeyPair,
  jwkThumbprint,
  toPublicJwk,
  assertPublicJwk,
  assertPrivateJwk,
  publicKeyBytes,
  seedBytes,
  type PublicJwk,
  type PrivateJwk,
  type JwkKeyPair,
  type GenerateKeyPairOptions,
} from './jwk.js';

// --- Data model -------------------------------------------------------------
export type { JoseHeader, JwtClaims, SignJwtOptions, VerifyJwtOptions, DecodedToken } from './types.js';

// --- Algorithm registry + low-level ML-DSA primitives -----------------------
export {
  SignatureAlgorithm,
  DEFAULT_SIGNATURE_ALGORITHM,
  SIGNATURE_ALGORITHMS,
  SUPPORTED_ALGORITHMS,
  getSignatureAlgorithmInfo,
  isSignatureAlgorithm,
  type SecurityCategory,
  type SignatureAlgorithmInfo,
} from './crypto/algorithms.js';
export { generateSeed, derivePublicKey, signWithSeed, verifySignature, type SignOptions } from './crypto/mldsa.js';

// --- Errors -----------------------------------------------------------------
export {
  ErrorCode,
  PqJwtError,
  InvalidArgumentError,
  UnsupportedAlgorithmError,
  InvalidKeyError,
  TokenMalformedError,
  SignatureVerificationError,
  ClaimValidationError,
  TokenExpiredError,
  TokenNotBeforeError,
  type ErrorContext,
  type PqJwtErrorOptions,
} from './errors.js';

// --- Selected utilities (handy for advanced callers) ------------------------
export { base64UrlEncode, base64UrlDecode } from './utils/base64url.js';
export type { Clock } from './utils/time.js';

// --- Default (namespace) export ---------------------------------------------
/**
 * Everything bundled as one object, so you can `import pqjwt from
 * '@agenticvalley/pqjwt'` and call `pqjwt.sign(...)`, `pqjwt.verify(...)`,
 * `pqjwt.generateKeyPair(...)`, `pqjwt.ErrorCode.TOKEN_EXPIRED`, and so on — no
 * named imports required.
 */
const pqjwt = {
  // Tokens
  sign,
  verify,
  decode,
  signJwt,
  verifyJwt,
  decodeJwt,
  decodeProtectedHeader,
  parseToken,
  // Keys
  generateKeyPair,
  generateSeed,
  derivePublicKey,
  jwkThumbprint,
  toPublicJwk,
  assertPublicJwk,
  assertPrivateJwk,
  publicKeyBytes,
  seedBytes,
  // Low-level signing
  signWithSeed,
  verifySignature,
  // Algorithms & encoding
  SignatureAlgorithm,
  DEFAULT_SIGNATURE_ALGORITHM,
  SUPPORTED_ALGORITHMS,
  SIGNATURE_ALGORITHMS,
  getSignatureAlgorithmInfo,
  isSignatureAlgorithm,
  AKP_KEY_TYPE,
  base64UrlEncode,
  base64UrlDecode,
  // Errors (enum + classes)
  ErrorCode,
  PqJwtError,
  InvalidArgumentError,
  UnsupportedAlgorithmError,
  InvalidKeyError,
  TokenMalformedError,
  SignatureVerificationError,
  ClaimValidationError,
  TokenExpiredError,
  TokenNotBeforeError,
};

export default pqjwt;
