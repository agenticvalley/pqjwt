/**
 * @packageDocumentation
 * Base64url (RFC 4648 §5) encoding helpers — the alphabet that makes JWTs URL-safe.
 *
 * Every segment of a JWT (the header, the payload, and the signature) is
 * `BASE64URL(UTF8(...))`. JOSE deliberately uses the **URL- and filename-safe**
 * variant of Base64 with the trailing `=` padding **removed**
 * (RFC 7515 Appendix C),
 * so a token can travel unescaped in a URL query parameter, an HTTP header, or a
 * form field. Concretely, versus standard Base64:
 *
 * - `+` becomes `-`
 * - `/` becomes `_`
 * - trailing `=` padding is omitted
 *
 * All encoding in this library funnels through here so the behaviour is
 * consistent and swappable. We delegate to an audited encoding implementation
 * rather than hand-rolling the bit-twiddling.
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCode, TokenMalformedError } from '../errors.js';

/**
 * Encode raw bytes as unpadded base64url.
 *
 * @param bytes - The bytes to encode (e.g. a signature, or UTF-8 JSON).
 * @returns The base64url string, without `=` padding.
 */
export function base64UrlEncode(bytes: Uint8Array): string {
  return base64urlnopad.encode(bytes);
}

/**
 * Decode an unpadded base64url string back into raw bytes.
 *
 * @param text - The base64url text to decode.
 * @returns The decoded bytes.
 * @throws {TokenMalformedError} If `text` contains characters outside the
 *   base64url alphabet or is otherwise not decodable — which, for a token, means
 *   it was truncated or tampered with.
 */
export function base64UrlDecode(text: string): Uint8Array {
  try {
    return base64urlnopad.decode(text);
  } catch (cause) {
    throw new TokenMalformedError('segment is not valid base64url', ErrorCode.TOKEN_MALFORMED, { cause });
  }
}

/**
 * Encode a string as unpadded base64url via its UTF-8 representation.
 *
 * @param text - The string to encode.
 * @returns The base64url string.
 */
export function base64UrlEncodeString(text: string): string {
  return base64UrlEncode(new TextEncoder().encode(text));
}

/**
 * Decode an unpadded base64url string into a UTF-8 string.
 *
 * @param text - The base64url text to decode.
 * @returns The decoded UTF-8 string.
 * @throws {TokenMalformedError} If the input is not valid base64url or the bytes
 *   are not valid UTF-8.
 */
export function base64UrlDecodeToString(text: string): string {
  const bytes = base64UrlDecode(text);
  try {
    // `fatal: true` rejects malformed UTF-8 rather than silently substituting
    // the replacement character — important when the bytes are attacker-controlled.
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (cause) {
    throw new TokenMalformedError('segment is not valid UTF-8', ErrorCode.TOKEN_MALFORMED, { cause });
  }
}
