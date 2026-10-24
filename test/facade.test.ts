import { describe, expect, it } from 'vitest';
import pqjwt, {
  SignatureVerificationError,
  base64UrlEncode,
  decode,
  generateKeyPair,
  sign,
  verify,
} from '../src/index.js';

const FIXED_MS = 1_700_000_000_000;
const NOW = Math.floor(FIXED_MS / 1000);
const clock = () => FIXED_MS;

describe('default (namespace) export', () => {
  it('exposes sign/verify/generateKeyPair on a single object', () => {
    const { privateKey, publicKey } = pqjwt.generateKeyPair();
    const token = pqjwt.sign({ sub: 'agent-42' }, privateKey, { clock });
    const claims = pqjwt.verify(token, publicKey, { clock });
    expect(claims.sub).toBe('agent-42');
  });
});

describe('sign — string durations', () => {
  it('accepts human-friendly expiresIn like "1h", "30m", "2d"', () => {
    const { privateKey, publicKey } = generateKeyPair();

    for (const [span, seconds] of [
      ['1h', 3600],
      ['30m', 1800],
      ['2d', 172_800],
      ['10s', 10],
    ] as const) {
      const token = sign({ sub: 'x' }, privateKey, { expiresIn: span, clock });
      const claims = verify(token, publicKey, { clock });
      expect(claims.exp).toBe(NOW + seconds);
    }
  });
});

describe('verify — jsonwebtoken shape', () => {
  it('returns the claims directly (not { header, payload })', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const token = sign({ sub: 'agent-42', role: 'reader' }, privateKey, { clock });

    const claims = verify(token, publicKey, { clock });
    expect(claims.sub).toBe('agent-42');
    expect(claims.role).toBe('reader');
    expect((claims as Record<string, unknown>).payload).toBeUndefined();
  });

  it('supports the Express-style callback form on success', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const token = sign({ sub: 'agent-42' }, privateKey, { clock });

    let error: Error | null = new Error('unset');
    let user: unknown;
    verify(token, publicKey, { clock }, (err, decoded) => {
      error = err;
      user = decoded;
    });

    expect(error).toBeNull();
    expect((user as { sub?: string }).sub).toBe('agent-42');
  });

  it('routes failures to the callback instead of throwing', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const token = sign({ sub: 'agent-42' }, privateKey, { clock });
    const [header, , signature] = token.split('.');
    const forged = `${header}.${base64UrlEncode(new TextEncoder().encode(JSON.stringify({ sub: 'evil' })))}.${signature}`;

    let captured: Error | null = null;
    expect(() => {
      verify(forged, publicKey, (err) => {
        captured = err;
      });
    }).not.toThrow();
    expect(captured).toBeInstanceOf(SignatureVerificationError);
  });
});

describe('decode — jsonwebtoken shape', () => {
  it('returns claims by default, the full token with complete, and null on garbage', () => {
    const { privateKey, publicKey } = generateKeyPair();
    const token = sign({ sub: 'agent-42' }, privateKey, { clock });

    expect(decode(token)?.sub).toBe('agent-42');
    expect(decode(token, { complete: true })?.header.alg).toBe(publicKey.alg);
    expect(decode('not-a-token')).toBeNull();
  });
});
