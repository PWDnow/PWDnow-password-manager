-- migration v2: Defense-in-Depth (Field-Level Encryption & Blind Indexing)

-- 1. Rename old tables to _legacy so Rust can migrate the data
ALTER TABLE folders RENAME TO folders_legacy;
ALTER TABLE users RENAME TO users_legacy;

-- 2. Create new tables with zero-knowledge schema
CREATE TABLE folders (
  id          TEXT PRIMARY KEY,
  ciphertext  BLOB,
  nonce       BLOB,
  sort_order  INTEGER DEFAULT 0,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

CREATE TABLE users (
  id          TEXT PRIMARY KEY,
  ciphertext  BLOB,
  nonce       BLOB,
  profile_pic BLOB,
  created_at  INTEGER NOT NULL
);

-- 3. Copy basic structure (metadata and PII remains in _legacy tables for now)
INSERT INTO folders (id, sort_order, created_at, updated_at)
SELECT id, sort_order, created_at, updated_at FROM folders_legacy;

INSERT INTO users (id, profile_pic, created_at)
SELECT id, profile_pic, created_at FROM users_legacy;

-- 4. Update credentials table for blind indexing
ALTER TABLE credentials ADD COLUMN service_hash TEXT;
ALTER TABLE credentials ADD COLUMN url_hash TEXT;
ALTER TABLE credentials ADD COLUMN username_hash TEXT;
ALTER TABLE credentials ADD COLUMN tags_hash TEXT;

-- Note: Data migration from _legacy tables will be handled by Rust code
-- on the next vault unlock.
