// web/lib/kms/kmsProvider.js
// KmsProvider — wraps/unwraps a per-user 32-byte DEK using an external key authority.
//
// Interface (duck-typed):
//   async wrapDek(dek: Buffer)                 → { wrapped: Buffer, keyId: string }
//   async unwrapDek(wrapped: Buffer, keyId)    → Buffer (the 32-byte DEK)
//
// Contract:
//   • wrap(dek) then unwrap(wrapped, keyId) returns a Buffer byte-equal to dek.
//   • wrapping is non-deterministic (fresh nonce) and authenticated (tamper → reject).
//   • keyId identifies the CMK/key-version used, so rotation can be tracked per row.
//   • The plaintext DEK never leaves process memory toward the KMS in the wrapped form.
//
// Implementations: LocalDevKmsProvider (dev/CI), VaultTransitKmsProvider (default prod),
// SelfHostKmsProvider (small self-host, e.g. Raspberry Pi 5 — see selfHostKms.js).

export function createKmsProvider(config) {
  const kind = (config?.provider || process.env.KMS_PROVIDER || 'local').toLowerCase();
  if (kind === 'vault') {
    return import('./vaultTransitKms.js').then(({ VaultTransitKmsProvider }) =>
      new VaultTransitKmsProvider({
        addr: process.env.VAULT_ADDR,
        token: process.env.VAULT_TOKEN,
        keyName: process.env.VAULT_TRANSIT_KEY || 'pwdnow-dek',
      }));
  }
  if (kind === 'local') {
    return import('./localDevKms.js').then(({ LocalDevKmsProvider }) => {
      const hex = process.env.LOCAL_KMS_KEY;
      if (!hex || Buffer.from(hex, 'hex').length !== 32) {
        throw new Error('LOCAL_KMS_KEY must be 32 bytes hex when KMS_PROVIDER=local');
      }
      return new LocalDevKmsProvider(Buffer.from(hex, 'hex'));
    });
  }
  if (kind === 'selfhost') {
    return import('./selfHostKms.js').then(({ createSelfHostKmsProvider }) => {
      const keyPath = process.env.SELF_HOST_KMS_KEY_PATH;
      if (!keyPath) {
        throw new Error('SELF_HOST_KMS_KEY_PATH is required when KMS_PROVIDER=selfhost');
      }
      return createSelfHostKmsProvider({ keyPath, passphrase: process.env.SELF_HOST_KMS_PASSPHRASE || undefined });
    });
  }
  throw new Error(`unknown KMS_PROVIDER: ${kind}`);
}
