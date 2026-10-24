/**
 * Example 02 — Sign and verify a post-quantum JWT.
 *
 * Run: `npm run example:sign`
 *
 * Walks through the full lifecycle: mint a key, sign a claims set, verify it,
 * and then demonstrate that tampering and expiry are correctly rejected.
 */

import {
  ClaimValidationError,
  SignatureVerificationError,
  decodeJwt,
  generateKeyPair,
  signJwt,
  verifyJwt,
} from '../src/index.js';

// 1) Create a post-quantum key pair (defaults to ML-DSA-65).
const { privateKey, publicKey } = generateKeyPair();
console.log('Signing with:', publicKey.alg, '| kid:', publicKey.kid);

// 2) Sign a claims set. Convenience options fill in the registered claims.
const token = signJwt({ sub: 'agent-42', scope: 'read:things', role: 'reader' }, privateKey, {
  issuer: 'https://issuer.example',
  audience: 'https://api.example',
  expiresIn: 3600, // one hour, expressed as a NumericDate `exp`
});

console.log('\nCompact token (note the three dot-separated segments):');
console.log(token);
console.log(
  '\nSegment sizes:',
  token
    .split('.')
    .map((s) => `${s.length}b`)
    .join(' . '),
);

// The header and claims are just base64url JSON — anyone can read them.
const { header, payload } = decodeJwt(token);
console.log('\nDecoded header :', header);
console.log('Decoded claims :', payload);

// 3) Verify: checks the ML-DSA signature AND the issuer/audience/expiry policy.
const verified = verifyJwt(token, publicKey, {
  issuer: 'https://issuer.example',
  audience: 'https://api.example',
});
console.log('\n✓ Verified. Authentic subject =', verified.payload.sub);

// 4a) Tampering with the payload invalidates the signature.
const [h, p, s] = token.split('.');
const forged = `${h}.${p}X.${s}`;
try {
  verifyJwt(forged, publicKey);
} catch (err) {
  if (err instanceof SignatureVerificationError) {
    console.log('\n✓ Tampered token rejected:', err.code);
  }
}

// 4b) An already-expired token is rejected on policy, even though it is authentic.
const expired = signJwt({ sub: 'agent-42' }, privateKey, { expiresIn: -10 });
try {
  verifyJwt(expired, publicKey);
} catch (err) {
  if (err instanceof ClaimValidationError) {
    console.log('✓ Expired token rejected  :', err.code);
  }
}
