import { describe, expect, it } from 'vitest';
import {
  ClaimValidationError,
  ErrorCode,
  type PqJwtError,
  SignatureAlgorithm,
  SignatureVerificationError,
  TokenExpiredError,
  TokenMalformedError,
  TokenNotBeforeError,
  base64UrlEncode,
  decodeJwt,
  generateKeyPair,
  signJwt,
  verifyJwt,
} from '../src/index.js';

// A fixed clock makes every time-based assertion deterministic.
const FIXED_MS = 1_700_000_000_000;
const NOW = Math.floor(FIXED_MS / 1000);
const clock = () => FIXED_MS;

const enc = (value: unknown): string => base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));

describe('signJwt / verifyJwt — happy path', () => {
  it('round-trips claims and populates registered claims from options', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const token = signJwt({ sub: 'agent-42', foo: 'bar' }, privateKey, {
      issuer: 'https://issuer.example',
      audience: 'https://api.example',
      jwtId: 'id-1',
      expiresIn: 60,
      notBefore: 0,
      clock,
    });

    const { header, payload } = verifyJwt(token, publicKey, {
      issuer: 'https://issuer.example',
      audience: 'https://api.example',
      clock,
    });

    expect(header.alg).toBe(publicKey.alg);
    expect(header.typ).toBe('JWT');
    expect(header.kid).toBe(publicKey.kid);

    expect(payload.sub).toBe('agent-42');
    expect(payload.foo).toBe('bar');
    expect(payload.iss).toBe('https://issuer.example');
    expect(payload.aud).toBe('https://api.example');
    expect(payload.jti).toBe('id-1');
    expect(payload.iat).toBe(NOW);
    expect(payload.nbf).toBe(NOW);
    expect(payload.exp).toBe(NOW + 60);
  });

  it('is a three-segment compact token', () => {
    const { privateKey } = generateKeyPair();
    const token = signJwt({ sub: 'x' }, privateKey, { clock });
    expect(token.split('.')).toHaveLength(3);
  });
});

describe('time-based claims', () => {
  it('rejects an expired token, but honours clockTolerance', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const token = signJwt({ sub: 'x' }, privateKey, { expiresIn: -1, clock });

    expect(() => verifyJwt(token, publicKey, { clock })).toThrow(TokenExpiredError);
    // Within a 5s tolerance the 1s-expired token is still accepted.
    expect(() => verifyJwt(token, publicKey, { clock, clockTolerance: 5 })).not.toThrow();
  });

  it('rejects a not-yet-valid token, but honours clockTolerance', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const token = signJwt({ sub: 'x' }, privateKey, { notBefore: 60, clock });

    expect(() => verifyJwt(token, publicKey, { clock })).toThrow(TokenNotBeforeError);
    expect(() => verifyJwt(token, publicKey, { clock, clockTolerance: 120 })).not.toThrow();
  });

  it('enforces maxTokenAge from iat', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const token = signJwt({ sub: 'x' }, privateKey, { clock });
    const later = () => FIXED_MS + 100_000; // 100s later

    expect(() => verifyJwt(token, publicKey, { clock: later, maxTokenAge: 200 })).not.toThrow();
    expect(() => verifyJwt(token, publicKey, { clock: later, maxTokenAge: 50 })).toThrow(ClaimValidationError);
  });

  it('requires iat when maxTokenAge is set', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const token = signJwt({ sub: 'x' }, privateKey, { issuedAt: false, clock });
    expect(() => verifyJwt(token, publicKey, { clock, maxTokenAge: 100 })).toThrow(ClaimValidationError);
  });
});

describe('identity claims', () => {
  it('checks iss, aud, sub, jti and required claims', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const token = signJwt({ sub: 'agent-42', jti: 'id-1' }, privateKey, {
      issuer: 'iss',
      audience: ['aud-1', 'aud-2'],
      clock,
    });

    // Matching policy passes.
    expect(() =>
      verifyJwt(token, publicKey, { issuer: 'iss', audience: 'aud-2', subject: 'agent-42', jwtId: 'id-1', clock }),
    ).not.toThrow();

    // Each individual mismatch is rejected.
    expect(() => verifyJwt(token, publicKey, { issuer: 'other', clock })).toThrow(ClaimValidationError);
    expect(() => verifyJwt(token, publicKey, { audience: 'aud-3', clock })).toThrow(ClaimValidationError);
    expect(() => verifyJwt(token, publicKey, { subject: 'someone-else', clock })).toThrow(ClaimValidationError);
    expect(() => verifyJwt(token, publicKey, { jwtId: 'id-2', clock })).toThrow(ClaimValidationError);
    expect(() => verifyJwt(token, publicKey, { requiredClaims: ['email'], clock })).toThrow(ClaimValidationError);
  });
});

describe('algorithm pinning & tamper resistance', () => {
  it('rejects a token whose alg is not on the allow-list', () => {
    const { privateKey, publicKey } = generateKeyPair(SignatureAlgorithm.ML_DSA_44);
    const token = signJwt({ sub: 'x' }, privateKey, { clock });

    try {
      verifyJwt(token, publicKey, { clock, algorithms: [SignatureAlgorithm.ML_DSA_87] });
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(SignatureVerificationError);
      expect((err as PqJwtError).code).toBe(ErrorCode.ALGORITHM_NOT_ALLOWED);
    }
  });

  it('rejects an "alg": "none" token outright', () => {
    const { publicKey } = generateKeyPair();
    const noneToken = `${enc({ alg: 'none', typ: 'JWT' })}.${enc({ sub: 'mallory' })}.AAAA`;
    try {
      verifyJwt(noneToken, publicKey, { clock });
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(SignatureVerificationError);
      expect((err as PqJwtError).code).toBe(ErrorCode.ALGORITHM_NOT_ALLOWED);
    }
  });

  it('rejects a token whose payload was tampered with', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const token = signJwt({ sub: 'agent-42' }, privateKey, { clock });
    const [header, , signature] = token.split('.');
    const forged = `${header}.${enc({ sub: 'evil' })}.${signature}`;

    expect(() => verifyJwt(forged, publicKey, { clock })).toThrow(SignatureVerificationError);
  });

  it('rejects malformed tokens', () => {
    const { publicKey } = generateKeyPair();
    expect(() => verifyJwt('not-a-token', publicKey, { clock })).toThrow(TokenMalformedError);
    expect(() => verifyJwt('only.two', publicKey, { clock })).toThrow(TokenMalformedError);
  });

  it('enforces an expected typ header', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const token = signJwt({ sub: 'x' }, privateKey, { clock });
    expect(() => verifyJwt(token, publicKey, { clock, typ: 'JWT' })).not.toThrow();
    expect(() => verifyJwt(token, publicKey, { clock, typ: 'at+jwt' })).toThrow(TokenMalformedError);
  });
});

describe('key sets & determinism', () => {
  it('selects the right key from a set by kid', () => {
    const issuerA = generateKeyPair();
    const issuerB = generateKeyPair();
    const token = signJwt({ sub: 'x' }, issuerB.privateKey, { clock });

    const { payload } = verifyJwt(token, [issuerA.publicKey, issuerB.publicKey], { clock });
    expect(payload.sub).toBe('x');
  });

  it('fails closed when no key in the set signed the token', () => {
    const inSet = generateKeyPair();
    const outsider = generateKeyPair();
    const token = signJwt({ sub: 'x' }, outsider.privateKey, { clock });
    expect(() => verifyJwt(token, [inSet.publicKey], { clock })).toThrow(SignatureVerificationError);
  });

  it('produces identical tokens under deterministic signing', () => {
    const { privateKey } = generateKeyPair();
    const a = signJwt({ sub: 'x' }, privateKey, { clock, deterministic: true });
    const b = signJwt({ sub: 'x' }, privateKey, { clock, deterministic: true });
    const hedged = signJwt({ sub: 'x' }, privateKey, { clock });

    expect(a).toBe(b);
    expect(hedged).not.toBe(a);
  });
});

describe('decodeJwt', () => {
  it('reads claims without verifying — and does not authenticate them', () => {
    const { privateKey } = generateKeyPair();
    const token = signJwt({ sub: 'agent-42' }, privateKey, { clock });

    expect(decodeJwt(token).payload.sub).toBe('agent-42');

    // Decoding a forged token still "succeeds" — proof that decode ≠ verify.
    const [header, , signature] = token.split('.');
    const forged = `${header}.${enc({ sub: 'evil' })}.${signature}`;
    expect(decodeJwt(forged).payload.sub).toBe('evil');
  });
});
