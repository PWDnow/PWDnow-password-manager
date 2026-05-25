-- migration v3: PQC Authenticator (Level 5)

CREATE TABLE pqc_credentials (
  id                 TEXT PRIMARY KEY,
  credential_id      BLOB UNIQUE NOT NULL,
  verifying_key      BLOB NOT NULL, -- ML-DSA-87 Public Key (2592 bytes)
  encapsulation_key  BLOB NOT NULL, -- ML-KEM-1024 Public Key (1568 bytes)
  decapsulation_seed BLOB NOT NULL, -- Seed for the daemon's DK (64 bytes), encrypted with VMK
  dk_nonce           BLOB NOT NULL, -- 12-byte AES-GCM nonce for dk_seed
  name               TEXT,
  created_at         INTEGER NOT NULL,
  last_used_at       INTEGER
);

-- Trigger: enforce max 2 PQC credentials
CREATE TRIGGER IF NOT EXISTS limit_pqc_keys
BEFORE INSERT ON pqc_credentials
WHEN (SELECT count(*) FROM pqc_credentials) >= 2
BEGIN
  SELECT RAISE(FAIL, 'maximum of 2 PQC credentials exceeded');
END;
