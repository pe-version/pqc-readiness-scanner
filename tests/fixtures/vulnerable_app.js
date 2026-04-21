// Fixture: Node.js app using quantum-vulnerable + broken crypto.
const crypto = require('crypto');

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

const md5sum = crypto.createHash('md5').update('hi').digest('hex');
const sha1sum = crypto.createHash('sha1').update('hi').digest('hex');

const ecdh = crypto.createECDH('secp256k1');
