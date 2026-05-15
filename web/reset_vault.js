// Full reset: clear cryptoSalt + reset vault data to empty plain arrays
import { readFileSync, writeFileSync, renameSync } from 'fs';
import { randomBytes, createCipheriv, createDecipheriv, hkdfSync } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, 'auth_data');
const MASTER_KEY = readFileSync(path.join(DATA_DIR, '.master_key'));
const UID = '84a2ae71b22458e9b2bf84858646e07f';

function derivedKey(info, length = 32) {
  return Buffer.from(hkdfSync('sha384', MASTER_KEY, Buffer.alloc(0), Buffer.from(info), length));
}
function decryptBlob(info, blob) {
  const iv = blob.subarray(0, 12), tag = blob.subarray(12, 28), ct = blob.subarray(28);
  const key = derivedKey(info);
  const dec = createDecipheriv('aes-256-gcm', key, iv);
  dec.setAuthTag(tag);
  return Buffer.concat([dec.update(ct), dec.final()]);
}
function encryptBlob(info, plaintext) {
  const key = derivedKey(info);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}
function writeEnc(filePath, info, jsonValue) {
  const blob = encryptBlob(info, Buffer.from(JSON.stringify(jsonValue), 'utf8'));
  const tmp = filePath + '.tmp';
  writeFileSync(tmp, blob, { mode: 0o600 });
  renameSync(tmp, filePath);
}

// 1. Clear cryptoSalt from user record
const usersFile = path.join(DATA_DIR, 'users.enc');
const users = JSON.parse(decryptBlob('users/enc', readFileSync(usersFile)).toString('utf8'));
const user = users.find(u => u.id === UID);
console.log('Current cryptoSalt:', user?.cryptoSalt);
if (user) {
  user.cryptoSalt = null;
  const newBlob = encryptBlob('users/enc', Buffer.from(JSON.stringify(users), 'utf8'));
  const tmp = usersFile + '.tmp';
  writeFileSync(tmp, newBlob, { mode: 0o600 });
  renameSync(tmp, usersFile);
  console.log('✅ Cleared cryptoSalt to null');
}

// 2. Reset folders and credentials to plain empty arrays (no browser-side encryption)
const vaultDir = path.join(DATA_DIR, 'vault', UID);
writeEnc(path.join(vaultDir, 'folders.enc'), `vault/${UID}/folders`, []);
writeEnc(path.join(vaultDir, 'credentials.enc'), `vault/${UID}/credentials`, []);
console.log('✅ Reset folders and credentials to empty arrays');
console.log('');
console.log('Now restart the server, clear browser cache, and login again.');
console.log('The browser will generate a new salt and publish it to the server.');
