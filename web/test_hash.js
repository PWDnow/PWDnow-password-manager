import { pbkdf2 as noblePbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import crypto from 'crypto';

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const enc = new TextEncoder();
const normalized = enc.encode('dabsi11@hotmail.com'.trim().toLowerCase());
console.log('nobleSha256:', bytesToHex(nobleSha256(normalized)));
console.log('crypto.createHash:', crypto.createHash('sha256').update('dabsi11@hotmail.com').digest('hex'));
