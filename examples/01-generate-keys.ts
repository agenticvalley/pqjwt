/**
 * Example 01 — Generate post-quantum signing keys.
 *
 * Run: `npm run example:keys`
 *
 * Shows how to mint AKP JSON Web Keys (RFC 9964) for each ML-DSA parameter set,
 * and what the resulting public/private material looks like.
 */

import { SUPPORTED_ALGORITHMS, base64UrlDecode, generateKeyPair, getSignatureAlgorithmInfo } from '../src/index.js';

/** Trim a long base64url value to something readable for the console. */
function preview(value: string): string {
  return value.length <= 48 ? value : `${value.slice(0, 24)}…${value.slice(-16)} (${value.length} chars)`;
}

for (const algorithm of SUPPORTED_ALGORITHMS) {
  const info = getSignatureAlgorithmInfo(algorithm);
  const { privateKey, publicKey } = generateKeyPair(algorithm);

  console.log(`\n=== ${algorithm}  (NIST category ${info.securityCategory}, ${info.standard}) ===`);
  console.log('public key bytes :', base64UrlDecode(publicKey.pub).length, `(expected ${info.publicKeyLength})`);
  console.log('seed bytes       :', base64UrlDecode(privateKey.priv).length, `(expected ${info.seedLength})`);
  console.log('kid (thumbprint) :', publicKey.kid);
  console.log('public JWK       :', {
    kty: publicKey.kty,
    alg: publicKey.alg,
    use: publicKey.use,
    kid: publicKey.kid,
    pub: preview(publicKey.pub),
  });
  // SECURITY: never log or persist `priv` outside your KMS/HSM. It is the seed
  // from which the signing key is derived — anyone holding it can mint tokens.
  console.log('private JWK      :', { ...publicKey, priv: preview(privateKey.priv) });
}

console.log('\nTip: publish the public JWKs (e.g. in a JWKS) and keep the private JWKs secret.');
