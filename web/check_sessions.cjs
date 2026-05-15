const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = './auth_data';
const MASTER_KEY = fs.readFileSync(path.join(DATA_DIR, '.master_key'));

function derivedKey(info, length = 32) {
  return crypto.hkdfSync('sha256', MASTER_KEY, Buffer.alloc(0), Buffer.from(info), length);
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

const uid = '418061278d88a2e1bb3696f18983d17b';
const filePath = path.join(DATA_DIR, 'vault', uid, 'sessions.enc');
const info = `vault/${uid}/sessions`;

try {
  const blob = fs.readFileSync(filePath);
  const pt = decryptBlob(info, blob);
  const sessions = JSON.parse(pt.toString('utf8'));
  console.log('Sessions:', JSON.stringify(sessions, null, 2));
} catch (err) {
  console.error('Failed to decrypt sessions:', err.message);
}
