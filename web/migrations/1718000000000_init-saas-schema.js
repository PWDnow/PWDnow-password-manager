// web/migrations/1718000000000_init-saas-schema.js  (ESM — project is type:module)
// SaaS (P1) schema. Indexed/authoritative user attributes are real columns; all the
// flexible per-user fields the file model carried (loginHints, fingerprintLog,
// duressEnforce, recoveryKey*, mfaEnforce, mfaTotpSecret, revocationEpoch, …) live in
// `meta jsonb` so the row model stays as extensible as the JSON file model.

export const up = (pgm) => {
  pgm.createExtension('pgcrypto', { ifNotExists: true });

  pgm.createTable('users', {
    id:            { type: 'text', primaryKey: true },           // hex UUID (matches generateUUID())
    email_hmac:    { type: 'text', notNull: true, unique: true }, // HMAC-SHA256 blind index
    password_hash: { type: 'text', notNull: true },
    wrapped_dek:   { type: 'bytea', notNull: true },
    kms_key_id:    { type: 'text', notNull: true },
    wrap_mode:     { type: 'text', notNull: true, default: 'kms' }, // 'kms' | 'kms+pw'
    pw_wrap_salt:  { type: 'bytea' },                            // null unless wrap_mode='kms+pw'
    crypto_salt:   { type: 'text' },                            // carried from file model
    status:        { type: 'text', notNull: true, default: 'active' },
    meta:          { type: 'jsonb', notNull: true, default: '{}' }, // all other flexible user fields
    created_at:    { type: 'timestamptz', notNull: true, default: pgm.func('now()') },
  });

  // One row per (user_id, resource_name): faithful port of the per-.enc-file model.
  pgm.createTable('vault_items', {
    user_id:    { type: 'text', notNull: true, references: 'users', onDelete: 'CASCADE' },
    name:       { type: 'text', notNull: true },                 // credentials|folders|asset_holder|profile|mfa_config|sessions|emergency|audit_log|...
    ciphertext: { type: 'bytea', notNull: true },                // iv||tag||ct, AES-256-GCM under the user DEK
    version:    { type: 'integer', notNull: true, default: 1 },
    updated_at: { type: 'timestamptz', notNull: true, default: pgm.func('now()') },
  });
  pgm.addConstraint('vault_items', 'vault_items_pk', { primaryKey: ['user_id', 'name'] });
};

export const down = (pgm) => {
  pgm.dropTable('vault_items');
  pgm.dropTable('users');
};
