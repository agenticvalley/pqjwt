import { describe, expect, it } from 'vitest';
import {
  DEFAULT_SIGNATURE_ALGORITHM,
  InvalidKeyError,
  SUPPORTED_ALGORITHMS,
  SignatureAlgorithm,
  derivePublicKey,
  generateSeed,
  getSignatureAlgorithmInfo,
  signWithSeed,
  verifySignature,
} from '../src/index.js';

const message = new TextEncoder().encode('the quick brown fox');

describe('algorithm registry', () => {
  it('defaults to ML-DSA-65', () => {
    expect(DEFAULT_SIGNATURE_ALGORITHM).toBe(SignatureAlgorithm.ML_DSA_65);
  });

  it('lists exactly the three ML-DSA parameter sets — no classical, no hybrid', () => {
    expect([...SUPPORTED_ALGORITHMS].sort()).toEqual(
      [SignatureAlgorithm.ML_DSA_44, SignatureAlgorithm.ML_DSA_65, SignatureAlgorithm.ML_DSA_87].sort(),
    );
  });

  it.each(SUPPORTED_ALGORITHMS)('registry sizes for %s match the live primitive', (algorithm) => {
    const info = getSignatureAlgorithmInfo(algorithm);
    const seed = generateSeed();
    const publicKey = derivePublicKey(algorithm, seed);
    const signature = signWithSeed(algorithm, seed, message);

    expect(seed).toHaveLength(info.seedLength);
    expect(publicKey).toHaveLength(info.publicKeyLength);
    expect(signature).toHaveLength(info.signatureLength);
  });
});

describe('ML-DSA sign / verify', () => {
  it.each(SUPPORTED_ALGORITHMS)('signs and verifies with %s', (algorithm) => {
    const seed = generateSeed();
    const publicKey = derivePublicKey(algorithm, seed);
    const signature = signWithSeed(algorithm, seed, message);
    expect(verifySignature(algorithm, publicKey, message, signature)).toBe(true);
  });

  it.each(SUPPORTED_ALGORITHMS)('rejects a tampered message for %s', (algorithm) => {
    const seed = generateSeed();
    const publicKey = derivePublicKey(algorithm, seed);
    const signature = signWithSeed(algorithm, seed, message);
    const tampered = new TextEncoder().encode('the quick brown FOX');
    expect(verifySignature(algorithm, publicKey, tampered, signature)).toBe(false);
  });

  it('deterministic signing is reproducible; hedged signing is not — both verify', () => {
    const algorithm = SignatureAlgorithm.ML_DSA_65;
    const seed = generateSeed();
    const publicKey = derivePublicKey(algorithm, seed);

    const d1 = signWithSeed(algorithm, seed, message, { deterministic: true });
    const d2 = signWithSeed(algorithm, seed, message, { deterministic: true });
    expect(d1).toEqual(d2); // deterministic → identical bytes

    const h1 = signWithSeed(algorithm, seed, message);
    const h2 = signWithSeed(algorithm, seed, message);
    expect(h1).not.toEqual(h2); // hedged → fresh randomness each time

    for (const sig of [d1, h1, h2]) {
      expect(verifySignature(algorithm, publicKey, message, sig)).toBe(true);
    }
  });

  it('treats a wrong-length signature as invalid rather than throwing', () => {
    const algorithm = SignatureAlgorithm.ML_DSA_65;
    const seed = generateSeed();
    const publicKey = derivePublicKey(algorithm, seed);
    expect(verifySignature(algorithm, publicKey, message, new Uint8Array(10))).toBe(false);
  });

  it('throws on a wrong-length public key', () => {
    expect(() =>
      verifySignature(SignatureAlgorithm.ML_DSA_65, new Uint8Array(3), message, new Uint8Array(3309)),
    ).toThrow(InvalidKeyError);
  });

  it('throws on a wrong-length seed', () => {
    expect(() => signWithSeed(SignatureAlgorithm.ML_DSA_65, new Uint8Array(31), message)).toThrow(InvalidKeyError);
  });
});
