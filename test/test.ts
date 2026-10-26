import pqjwt from '@agenticvalley/pqjwt';

const { publicKey, privateKey } = pqjwt.generateKeyPair();

console.log('Public Key:', publicKey);
console.log('Private Key:', privateKey);
