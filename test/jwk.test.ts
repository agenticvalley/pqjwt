import { describe, expect, it } from 'vitest';
import {
  InvalidKeyError,
  SignatureAlgorithm,
  assertPrivateJwk,
  assertPublicJwk,
  base64UrlDecode,
  generateKeyPair,
  getSignatureAlgorithmInfo,
  jwkThumbprint,
  toPublicJwk,
} from '../src/index.js';

describe('generateKeyPair', () => {
  it('produces correctly-sized AKP JWKs for every algorithm', () => {
    for (const algorithm of [
      SignatureAlgorithm.ML_DSA_44,
      SignatureAlgorithm.ML_DSA_65,
      SignatureAlgorithm.ML_DSA_87,
    ]) {
      const info = getSignatureAlgorithmInfo(algorithm);
      const { privateKey, publicKey } = generateKeyPair(algorithm);

      expect(publicKey.kty).toBe('AKP');
      expect(publicKey.alg).toBe(algorithm);
      expect(publicKey.use).toBe('sig');
      expect(base64UrlDecode(publicKey.pub)).toHaveLength(info.publicKeyLength);
      expect(base64UrlDecode(privateKey.priv)).toHaveLength(info.seedLength);
      // The thumbprint is stable across the public and private views of the pair.
      expect(privateKey.kid).toBe(publicKey.kid);
    }
  });

  it('omits the kid when includeKid is false', () => {
    const { publicKey } = generateKeyPair(SignatureAlgorithm.ML_DSA_65, { includeKid: false });
    expect(publicKey.kid).toBeUndefined();
  });

  it('toPublicJwk strips the secret seed', () => {
    const { privateKey } = generateKeyPair();
    const pub = toPublicJwk(privateKey);
    expect('priv' in pub).toBe(false);
    expect(pub.pub).toBe(privateKey.pub);
  });
});

/**
 * Known-answer test against RFC 9964 Appendix A.1 (JOSE examples), which fix the
 * private seed to all-zero bytes and publish the resulting `pub` and `kid`.
 *
 * If ML-DSA key generation and the RFC 7638 JWK thumbprint are both implemented
 * correctly, deriving a key from a 32-byte all-zero seed reproduces the exact
 * `kid` from the RFC — a stringent, standards-anchored check of the whole stack.
 */
describe('RFC 9964 all-zeros known-answer vectors', () => {
  const ZERO_SEED = new Uint8Array(32);
  const EXPECTED_ZERO_PRIV = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

  const vectors: readonly { algorithm: SignatureAlgorithm; kid: string; pubPrefix: string }[] = [
    {
      algorithm: SignatureAlgorithm.ML_DSA_44,
      kid: 'T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o',
      pubPrefix: 'unH59k4Ru',
    },
    {
      algorithm: SignatureAlgorithm.ML_DSA_65,
      kid: 'Suiu29qbfuaBaR4Ats-c6XQBePB_OpAxAwcTR_0KXVM',
      pubPrefix: 'QksvJn5Y1bO0',
    },
    {
      algorithm: SignatureAlgorithm.ML_DSA_87,
      kid: 'tRn1JNIkgMsABVQBlXeDHxAIcclh-2IX0UdDEzPt5XU',
      pubPrefix: '5F_8jMc9uIX',
    },
  ];

  it.each(vectors)('matches the published kid and pub for $algorithm', ({ algorithm, kid, pubPrefix }) => {
    const { privateKey, publicKey } = generateKeyPair(algorithm, { seed: ZERO_SEED });
    expect(privateKey.priv).toBe(EXPECTED_ZERO_PRIV);
    expect(publicKey.pub.startsWith(pubPrefix)).toBe(true);
    expect(publicKey.kid).toBe(kid);
    // `jwkThumbprint` must agree with the kid generateKeyPair attached.
    expect(jwkThumbprint(publicKey)).toBe(kid);
  });
});

describe('JWK validation', () => {
  it('accepts well-formed public and private JWKs', () => {
    const { privateKey, publicKey } = generateKeyPair();
    expect(() => assertPublicJwk(publicKey)).not.toThrow();
    expect(() => assertPrivateJwk(privateKey)).not.toThrow();
  });

  it('rejects a wrong kty', () => {
    const { publicKey } = generateKeyPair();
    expect(() => assertPublicJwk({ ...publicKey, kty: 'OKP' })).toThrow(InvalidKeyError);
  });

  it('rejects an unsupported alg', () => {
    const { publicKey } = generateKeyPair();
    expect(() => assertPublicJwk({ ...publicKey, alg: 'EdDSA' })).toThrow(InvalidKeyError);
  });

  it('rejects a pub of the wrong length', () => {
    const { publicKey } = generateKeyPair();
    expect(() => assertPublicJwk({ ...publicKey, pub: 'AAAA' })).toThrow(InvalidKeyError);
  });

  it('rejects a private JWK whose seed is the wrong length', () => {
    const { privateKey } = generateKeyPair();
    expect(() => assertPrivateJwk({ ...privateKey, priv: 'AAAA' })).toThrow(InvalidKeyError);
  });
});
