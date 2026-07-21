// web/tests/kms.contract.test.js
import { randomBytes } from 'crypto';
import { kmsContractSuite } from './helpers/kmsContractSuite.js';
import { LocalDevKmsProvider } from '../lib/kms/localDevKms.js';

kmsContractSuite('LocalDev', async () => new LocalDevKmsProvider(randomBytes(32)));

if (process.env.VAULT_ADDR && process.env.VAULT_TOKEN && process.env.VAULT_TRANSIT_KEY) {
  const { VaultTransitKmsProvider } = await import('../lib/kms/vaultTransitKms.js');
  kmsContractSuite('VaultTransit', async () => new VaultTransitKmsProvider({
    addr: process.env.VAULT_ADDR, token: process.env.VAULT_TOKEN, keyName: process.env.VAULT_TRANSIT_KEY,
  }));
}
