/**
 * Example 03 — Decode and inspect a token, and select a key from a set.
 *
 * Run: `npm run example:decode`
 *
 * Demonstrates reading the (unauthenticated) header to pick the right key by
 * `kid` from a key set, then verifying against that set.
 */

import { decodeProtectedHeader, generateKeyPair, signJwt, verifyJwt, type PublicJwk } from '../src/index.js';

// Stand up two issuers, each with its own key — a realistic "key set" / JWKS.
const issuerA = generateKeyPair();
const issuerB = generateKeyPair();
const jwks: PublicJwk[] = [issuerA.publicKey, issuerB.publicKey];

// Issuer B mints a token.
const token = signJwt({ sub: 'user-7' }, issuerB.privateKey, { issuer: 'issuer-b' });

// A verifier first peeks at the header (no signature check yet) to see which
// key id signed it. This is safe for *routing* — never for *trust*.
const header = decodeProtectedHeader(token);
console.log('Header alg :', header.alg);
console.log('Header kid :', header.kid);
console.log('Matches issuer B key? ', header.kid === issuerB.publicKey.kid);

// Handing the whole set to verifyJwt lets it pick the key by kid/alg for us.
const { payload } = verifyJwt(token, jwks, { issuer: 'issuer-b' });
console.log('\n✓ Verified against the key set. Subject =', payload.sub);

// If neither key in the set had signed it, verification would fail closed.
const outsider = generateKeyPair();
const rogue = signJwt({ sub: 'mallory' }, outsider.privateKey);
try {
  verifyJwt(rogue, jwks);
  console.log('this should not print');
} catch (err) {
  console.log('✓ Token from an unknown key rejected:', (err as Error).message);
}
