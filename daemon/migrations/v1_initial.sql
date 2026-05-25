CREATE TABLE IF NOT EXISTS vault_meta (
  key   TEXT PRIMARY KEY,
  value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,
  email       TEXT UNIQUE NOT NULL,
  first_name  TEXT NOT NULL,
  last_name   TEXT NOT NULL,
  profile_pic BLOB,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS fido2_credentials (
  id                 TEXT PRIMARY KEY,
  credential_id      BLOB UNIQUE NOT NULL,
  public_key_cbor    BLOB NOT NULL,
  sign_count         INTEGER NOT NULL DEFAULT 0,
  aaguid             TEXT,
  is_passkey         INTEGER DEFAULT 0,
  encrypted_vmk_copy BLOB,
  vmk_copy_nonce     BLOB,
  name               TEXT,
  created_at         INTEGER NOT NULL,
  last_used_at       INTEGER
);

CREATE TRIGGER IF NOT EXISTS enforce_max_fido2_keys
  BEFORE INSERT ON fido2_credentials
  BEGIN
    SELECT RAISE(ABORT, 'maximum 2 FIDO2 credentials allowed')
    WHERE (SELECT COUNT(*) FROM fido2_credentials) >= 2;
  END;

CREATE TABLE IF NOT EXISTS otp_config (
  id               TEXT PRIMARY KEY,
  encrypted_secret BLOB NOT NULL,
  secret_nonce     BLOB NOT NULL,
  backup_codes     BLOB NOT NULL,
  backup_nonce     BLOB NOT NULL,
  created_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS folders (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  description TEXT,
  icon_svg    TEXT,
  sort_order  INTEGER DEFAULT 0,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
  id             TEXT PRIMARY KEY,
  folder_id      TEXT REFERENCES folders(id),
  encrypted_dek  BLOB NOT NULL,
  dek_nonce      BLOB NOT NULL,
  ciphertext     BLOB NOT NULL,
  ct_nonce       BLOB NOT NULL,
  ct_aad         BLOB NOT NULL,
  schema_version INTEGER DEFAULT 1,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_holder (
  id         TEXT PRIMARY KEY,
  ciphertext BLOB NOT NULL,
  nonce      BLOB NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        INTEGER NOT NULL,
  action    TEXT NOT NULL,
  resource  TEXT,
  prev_hash BLOB NOT NULL,
  row_hash  BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_credentials_folder ON credentials(folder_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
