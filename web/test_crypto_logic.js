import { pbkdf2 as noblePbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';

const PBKDF2_ITERATIONS = 310_000;

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function hashPassword(password, saltHex = '') {
  const enc = new TextEncoder();
  const passwordBytes = enc.encode(password);
  const saltBytes = /^[0-9a-f]{32}$/i.test(saltHex)
    ? hexToBytes(saltHex)
    : enc.encode(saltHex || 'pwdnow-demo-salt');

  return bytesToHex(noblePbkdf2(nobleSha256, passwordBytes, saltBytes, { c: PBKDF2_ITERATIONS, dkLen: 32 }));
}

async function test() {
  const password = "!!123456789..";
  const salt = "c75f6bfb957ee1ebac4e142aaae69356";
  const passwordHash = await hashPassword(password, salt);
  console.log("Password hash:", passwordHash);
}

test();
