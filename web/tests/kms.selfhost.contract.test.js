// web/tests/kms.selfhost.contract.test.js
import { randomBytes } from 'crypto';
import { kmsContractSuite } from './helpers/kmsContractSuite.js';
import { SelfHostKmsProvider } from '../lib/kms/selfHostKms.js';

kmsContractSuite('SelfHost (direct key)', async () => new SelfHostKmsProvider(randomBytes(32)));
