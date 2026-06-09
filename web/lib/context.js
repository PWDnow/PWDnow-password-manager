// Shared mutable context. `initAuth()` in auth.js populates this before any request.
// All lib files import `ctx` and access its properties (never reassign the binding itself).
export const ctx = {
  MASTER_KEY: null,
  DATA_DIR: null,
  ipIntel: null,
  ipPolicy: { blockTor: true, blockProxy: true, blockVpn: false, blockAbuser: true },
  derivedKeyCache: new Map(),
  /** @type {import('./stateStore.js').InMemoryStateStore | import('./redisStateStore.js').RedisStateStore} */
  stateStore: null,
  /** @type {import('./vaultRepository.js').FileVaultRepository | import('./postgresVaultRepository.js').PostgresVaultRepository | import('./dualWriteVaultRepository.js').DualWriteVaultRepository} */
  vaultRepository: null,
  /** @type {import('./envelope.js').Envelope | null} */
  envelope: null,
  /** KMS provider (KmsProvider) or null in file mode */
  kms: null,
};
