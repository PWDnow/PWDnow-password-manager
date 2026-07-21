#!/usr/bin/env node
// web/scripts/generate-selfhost-kms-key.js
// Provisions a SelfHostKms master key file. Usage:
//   node scripts/generate-selfhost-kms-key.js --path /var/lib/pwdnow/kms-master.key [--passphrase]
//
// --passphrase prompts for a passphrase (twice, must match) on stderr without echoing, and
// wraps the master key under it (Argon2id). Without --passphrase, the key file is raw bytes —
// simpler, but the whole security of the KMS layer then rests on file permissions alone.
import { generateSelfHostMasterKeyFile } from '../lib/kms/selfHostKms.js';
import { createInterface } from 'readline';
import { existsSync } from 'fs';

function readHidden(prompt) {
  return new Promise((resolve) => {
    process.stderr.write(prompt);
    const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    // Node's readline has no built-in hidden-input mode; muting output writes is the standard
    // workaround for a simple CLI prompt like this one.
    const onWrite = rl._writeToOutput;
    rl._writeToOutput = () => {};
    rl.question('', (answer) => {
      rl._writeToOutput = onWrite;
      rl.history = rl.history.slice(1);
      process.stderr.write('\n');
      rl.close();
      resolve(answer);
    });
  });
}

async function main() {
  const args = process.argv.slice(2);
  const pathIdx = args.indexOf('--path');
  const keyPath = pathIdx !== -1 ? args[pathIdx + 1] : null;
  const usePassphrase = args.includes('--passphrase');

  if (!keyPath) {
    console.error('Usage: node scripts/generate-selfhost-kms-key.js --path <file> [--passphrase]');
    process.exit(1);
  }
  if (existsSync(keyPath)) {
    console.error(`Refusing to overwrite existing file: ${keyPath}`);
    process.exit(1);
  }

  let passphrase;
  if (usePassphrase) {
    const a = await readHidden('Passphrase: ');
    const b = await readHidden('Confirm passphrase: ');
    if (a !== b) {
      console.error('Passphrases did not match.');
      process.exit(1);
    }
    if (a.length < 12) {
      console.error('Passphrase must be at least 12 characters.');
      process.exit(1);
    }
    passphrase = a;
  }

  await generateSelfHostMasterKeyFile({ keyPath, passphrase });
  console.error(`Wrote SelfHostKms master key to ${keyPath} (mode 0600).`);
  console.error('Set in web/.env:');
  console.error('  KMS_PROVIDER=selfhost');
  console.error(`  SELF_HOST_KMS_KEY_PATH=${keyPath}`);
  if (usePassphrase) console.error('  SELF_HOST_KMS_PASSPHRASE=<the passphrase you just entered>');
}

main();
