/**
 * @packageDocumentation
 * Byte helpers.
 *
 * A thin, centralized seam over the low-level primitives shipped by the audited
 * cryptography dependencies. Keeping them here makes it trivial to swap an
 * implementation without touching call sites, and gives every consumer one
 * obvious place to find "how do I get secure random bytes / compare two arrays".
 */

import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import { equalBytes, randomBytes } from '@noble/post-quantum/utils.js';

export { concatBytes, randomBytes, utf8ToBytes };

/**
 * Compare two byte arrays for equality.
 *
 * Backed by the underlying byte-equality primitive. Note that in a pure-JS runtime this is **not**
 * guaranteed to be perfectly constant-time; ML-DSA verification does not hinge
 * on a secret-dependent byte comparison here, so that is acceptable for this
 * library's threat model. Do not reuse it to compare long-lived secrets where a
 * timing side-channel is explicitly in scope.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return equalBytes(a, b);
}

/** Create a defensive copy of a byte array. */
export function copyBytes(bytes: Uint8Array): Uint8Array {
  return bytes.slice();
}
