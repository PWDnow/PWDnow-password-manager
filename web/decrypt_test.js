import { initAuth, mountAuthAndVault } from './auth.js';
import { readFileSync } from 'fs';
import path from 'path';

// Need to mock express app and run the internal functions, but it's easier to just use the crypto directly
import crypto from 'crypto';

const DATA_DIR = './auth_data';
const MASTER_KEY = readFileSync(path.join(DATA_DIR, '.master_key'));

function derivedKey(info, length = 32) {
  const buf = crypto.hkdfSync('sha256', MASTER_KEY, Buffer.alloc(0), Buffer.from(info), length);
  return Buffer.from(buf);
}

function decryptBlob(info, blob) {
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ct = blob.subarray(28);
  const key = derivedKey(info);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

try {
  const usersBlob = readFileSync(path.join(DATA_DIR, 'users.enc'));
  const pt = decryptBlob('users/enc', usersBlob);
  console.log('users.enc:', pt.toString('utf8'));
  
  // also read a vault file
  const uid = '01e4c31882aff8da8814e7ee00d8f6a8';
  const credsBlob = readFileSync(path.join(DATA_DIR, 'vault', uid, 'credentials.enc'));
  const credsPt = decryptBlob(`vault/${uid}/credentials`, credsBlob);
  console.log('credentials.enc:', credsPt.toString('utf8'));
} catch (err) {
  console.error(err);
}
