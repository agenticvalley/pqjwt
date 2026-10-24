/**
 * @packageDocumentation
 * Token **inspection without verification**.
 *
 * {@link decodeJwt} splits a compact token and parses its header and claims, but
 * performs **no** cryptographic check. It is the equivalent of "read the
 * envelope without checking the wax seal": handy for reading a `kid` to select a
 * key, for debugging, or for logging — but its output must **never** be trusted
 * for an authorization decision. Use {@link verifyJwt} for anything security
 * relevant.
 */

import { TokenMalformedError, ErrorCode } from './errors.js';
import type { DecodedToken, JoseHeader, JwtClaims } from './types.js';
import { base64UrlDecode, base64UrlDecodeToString, parseJsonObject } from './utils/index.js';

/**
 * A fully parsed compact token, including the raw pieces needed to verify it.
 *
 * @typeParam T - The concrete claims shape.
 */
export interface ParsedToken<T extends JwtClaims = JwtClaims> extends DecodedToken<T> {
  /** The exact ASCII Signing Input (`header.payload`) that the signature covers. */
  readonly signingInput: string;
  /** The decoded signature bytes. */
  readonly signature: Uint8Array;
}

/**
 * Split a compact serialization into its three segments and parse each one.
 *
 * This is the shared workhorse behind both {@link decodeJwt} and
 * {@link verifyJwt}; it validates structure only, never the signature.
 *
 * @param token - The compact token string.
 * @returns The parsed header, payload, Signing Input, and signature bytes.
 * @throws {TokenMalformedError} If the token is not a well-formed
 *   `header.payload.signature` triple, or any segment is not valid
 *   base64url/UTF-8/JSON.
 */
export function parseToken<T extends JwtClaims = JwtClaims>(token: string): ParsedToken<T> {
  if (typeof token !== 'string' || token.length === 0) {
    throw new TokenMalformedError('token must be a non-empty string');
  }

  const segments = token.split('.');
  if (segments.length !== 3) {
    throw new TokenMalformedError(
      'compact JWT must have exactly three dot-separated segments',
      ErrorCode.TOKEN_MALFORMED,
      {
        context: { segments: segments.length },
      },
    );
  }

  const [encodedHeader, encodedPayload, encodedSignature] = segments as [string, string, string];
  if (encodedHeader.length === 0 || encodedPayload.length === 0 || encodedSignature.length === 0) {
    throw new TokenMalformedError('compact JWT segments must all be non-empty');
  }

  const header = parseJsonObject(base64UrlDecodeToString(encodedHeader), ErrorCode.HEADER_INVALID) as JoseHeader;
  const payload = parseJsonObject(base64UrlDecodeToString(encodedPayload), ErrorCode.CLAIMS_INVALID) as T;
  const signature = base64UrlDecode(encodedSignature);

  return {
    header,
    payload,
    // The signature covers only the first two segments, joined by a dot.
    signingInput: `${encodedHeader}.${encodedPayload}`,
    signature,
  };
}

/**
 * Decode a token's header and claims **without verifying** its signature.
 *
 * @typeParam T - The concrete claims shape for typed access.
 * @param token - The compact token string.
 * @returns The decoded {@link DecodedToken} (`header` and `payload`).
 * @throws {TokenMalformedError} If the token cannot be parsed.
 *
 * @remarks Never make trust decisions on this output — the contents are
 * unauthenticated until {@link verifyJwt} succeeds.
 */
export function decodeJwt<T extends JwtClaims = JwtClaims>(token: string): DecodedToken<T> {
  const { header, payload } = parseToken<T>(token);
  return { header, payload };
}

/**
 * Decode just the protected JOSE header — typically to read the `kid` or `alg`
 * so you can choose the correct verification key.
 *
 * @param token - The compact token string.
 * @returns The decoded {@link JoseHeader}.
 * @throws {TokenMalformedError} If the header cannot be parsed.
 */
export function decodeProtectedHeader(token: string): JoseHeader {
  return parseToken(token).header;
}
