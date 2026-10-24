/**
 * @packageDocumentation
 * A familiar, single-namespace facade over the library, styled after the classic
 * `sign` / `verify` / `decode` shape so existing token code ports with almost no
 * change. Import the whole thing as one object and call methods on it:
 *
 * @example
 * ```ts
 * import pqjwt from '@agenticvalley/pqjwt';
 *
 * const { privateKey, publicKey } = pqjwt.generateKeyPair();
 * const token = pqjwt.sign({ sub: 'agent-42' }, privateKey, { expiresIn: '1h' });
 *
 * // Express-style middleware — the callback form never throws:
 * pqjwt.verify(token, publicKey, (err, user) => {
 *   if (err) return res.sendStatus(403);
 *   req.user = user;
 *   next();
 * });
 * ```
 */

import { decodeJwt } from './decode.js';
import type { PrivateJwk } from './jwk.js';
import { signJwt } from './sign.js';
import type { DecodedToken, JwtClaims, SignJwtOptions, VerifyJwtOptions } from './types.js';
import { verifyJwt, type VerificationKeyInput } from './verify.js';

/**
 * Sign a claims set into a compact token — the ergonomic alias of {@link signJwt}.
 * Accepts human-friendly lifetimes such as `{ expiresIn: '1h' }`.
 *
 * @param payload - The claims to embed.
 * @param privateKey - The signer's private AKP JWK.
 * @param options - {@link SignJwtOptions}.
 * @returns The signed compact token.
 */
export function sign(payload: JwtClaims, privateKey: PrivateJwk, options?: SignJwtOptions): string {
  return signJwt(payload, privateKey, options);
}

/** Node-style callback used by the callback form of {@link verify}. */
export type VerifyCallback<T extends JwtClaims = JwtClaims> = (error: Error | null, payload?: T) => void;

export function verify<T extends JwtClaims = JwtClaims>(
  token: string,
  key: VerificationKeyInput,
  options?: VerifyJwtOptions,
): T;
export function verify<T extends JwtClaims = JwtClaims>(
  token: string,
  key: VerificationKeyInput,
  callback: VerifyCallback<T>,
): void;
export function verify<T extends JwtClaims = JwtClaims>(
  token: string,
  key: VerificationKeyInput,
  options: VerifyJwtOptions,
  callback: VerifyCallback<T>,
): void;
/**
 * Verify a token and return its **claims** (the payload), mirroring the classic
 * `verify` shape. Two call styles are supported:
 *
 * - **Synchronous** — `const claims = verify(token, key, options?)`. Throws a
 *   typed error on any failure.
 * - **Callback** — `verify(token, key, [options,] (err, claims) => { … })`. The
 *   callback receives the error *or* the claims and never throws, which suits
 *   Express-style middleware.
 *
 * Unlike {@link verifyJwt}, this returns just the claims, not `{ header, payload }`.
 *
 * @param token - The compact token to verify.
 * @param key - The verification key or key set.
 * @param optionsOrCallback - {@link VerifyJwtOptions}, or the callback.
 * @param maybeCallback - The callback, when options were also supplied.
 * @returns The verified claims (synchronous form), or `void` (callback form).
 */
export function verify<T extends JwtClaims = JwtClaims>(
  token: string,
  key: VerificationKeyInput,
  optionsOrCallback?: VerifyJwtOptions | VerifyCallback<T>,
  maybeCallback?: VerifyCallback<T>,
): T | void {
  const options: VerifyJwtOptions = typeof optionsOrCallback === 'function' ? {} : (optionsOrCallback ?? {});
  const callback = typeof optionsOrCallback === 'function' ? optionsOrCallback : maybeCallback;

  if (callback === undefined) {
    return verifyJwt<T>(token, key, options).payload;
  }

  try {
    const { payload } = verifyJwt<T>(token, key, options);
    callback(null, payload);
  } catch (error) {
    callback(
      error instanceof Error ? error : new Error(typeof error === 'string' ? error : 'token verification failed'),
    );
  }
}

/** Options for {@link decode}. */
export interface DecodeOptions {
  /** Return `{ header, payload }` instead of just the claims. */
  readonly complete?: boolean;
}

export function decode<T extends JwtClaims = JwtClaims>(token: string, options?: { complete?: false }): T | null;
export function decode<T extends JwtClaims = JwtClaims>(
  token: string,
  options: { complete: true },
): DecodedToken<T> | null;
/**
 * Decode a token **without verifying** it, returning its claims (or, with
 * `{ complete: true }`, the full `{ header, payload }`). Mirrors the classic
 * `decode`: on a malformed token it returns `null` rather than throwing.
 *
 * Never trust this output for authorization — use {@link verify} for that.
 *
 * @param token - The compact token to read.
 * @param options - {@link DecodeOptions}.
 * @returns The claims, the full decoded token, or `null` if it cannot be parsed.
 */
export function decode<T extends JwtClaims = JwtClaims>(
  token: string,
  options: DecodeOptions = {},
): T | DecodedToken<T> | null {
  try {
    const decoded = decodeJwt<T>(token);
    return options.complete === true ? decoded : decoded.payload;
  } catch {
    return null;
  }
}
