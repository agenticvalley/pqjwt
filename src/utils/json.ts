/**
 * @packageDocumentation
 * JSON helpers tuned for the two very different ways JOSE serializes JSON.
 *
 * 1. **Token segments** — the JOSE header and the JWT Claims Set are ordinary
 *    compact JSON. Order does not matter because the exact bytes are captured by
 *    the base64url encoding that is fed into the signature.
 *
 * 2. **JWK thumbprints** — RFC 7638
 *    requires a **canonical** form: only the required members, sorted by
 *    lexicographic (Unicode code point) order, with no insignificant whitespace.
 *    {@link canonicalJson} produces exactly that.
 */

import { ErrorCode, TokenMalformedError } from '../errors.js';

/** A parsed JSON object with string keys and unknown values. */
export type JsonObject = Record<string, unknown>;

/**
 * Serialize a value to compact JSON (no extra whitespace).
 *
 * @param value - The value to serialize.
 * @returns The JSON string.
 */
export function stringifyJson(value: unknown): string {
  return JSON.stringify(value);
}

/**
 * Parse JSON that originated from a token segment, guaranteeing the result is a
 * plain object.
 *
 * JOSE headers and JWT Claims Sets are always JSON **objects**; a bare array,
 * string, or number is not a valid header or claims set, so we reject it here
 * rather than letting a malformed token flow deeper into the library.
 *
 * @param text - The JSON text to parse.
 * @param code - The error code to raise on failure, so the caller can attribute
 *   the fault to the header or the claims set specifically.
 * @returns The parsed object.
 * @throws {TokenMalformedError} If the text is not valid JSON or is not an object.
 */
export function parseJsonObject(
  text: string,
  code: ErrorCode.HEADER_INVALID | ErrorCode.CLAIMS_INVALID | ErrorCode.TOKEN_MALFORMED = ErrorCode.TOKEN_MALFORMED,
): JsonObject {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (cause) {
    throw new TokenMalformedError('segment is not valid JSON', code, { cause });
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new TokenMalformedError('segment JSON is not an object', code);
  }
  return parsed as JsonObject;
}

/**
 * Produce the canonical JSON string for a flat object as required by RFC 7638
 * JWK thumbprints: keys sorted lexicographically, values assumed to be strings,
 * and no insignificant whitespace.
 *
 * The inputs here are always small, flat maps of the required JWK members, so a
 * shallow key sort is sufficient (and matches the RFC, which only ever
 * canonicalizes such a map).
 *
 * @param object - A flat record of string values (the required JWK members).
 * @returns The canonical, minified JSON string.
 */
export function canonicalJson(object: Record<string, string>): string {
  const sortedKeys = Object.keys(object).sort();
  const members = sortedKeys.map((key) => `${JSON.stringify(key)}:${JSON.stringify(object[key])}`);
  return `{${members.join(',')}}`;
}
