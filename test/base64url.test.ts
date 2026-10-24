import { describe, expect, it } from 'vitest';
import { base64UrlDecode, base64UrlEncode, PqJwtError } from '../src/index.js';

describe('base64url', () => {
  it('round-trips arbitrary bytes', () => {
    for (let length = 0; length < 300; length += 7) {
      const bytes = new Uint8Array(length).map((_, i) => (i * 31 + 7) & 0xff);
      const encoded = base64UrlEncode(bytes);
      expect(base64UrlDecode(encoded)).toEqual(bytes);
    }
  });

  it('produces URL-safe, unpadded output (no +, /, or =)', () => {
    // Bytes chosen so that standard base64 would contain both '+' and '/'.
    const bytes = new Uint8Array([0xfb, 0xff, 0xbf, 0x00, 0x10, 0x83]);
    const encoded = base64UrlEncode(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
  });

  it('rejects input outside the base64url alphabet', () => {
    // '+' and '=' are not valid in unpadded base64url.
    expect(() => base64UrlDecode('abc+def')).toThrow(PqJwtError);
    expect(() => base64UrlDecode('abcd====')).toThrow(PqJwtError);
  });
});
