# P2W — PWDnow Vault Export Format

Version 1 · Binary · Post-Quantum Resilient

---

## 1. Purpose

P2W is a purpose-built binary vault export format for PWDnow. It is not
derived from JSON, CSV, XML, or any existing password-manager interchange
format. Its design goals are:

- 128-bit post-quantum confidentiality (NIST PQC Level 1 baseline)
- Independent authentication at the header level and at the file level
- Two independent AEAD cipher layers so that a break of either cipher alone
  cannot reveal the plaintext
- A self-describing binary payload that can be parsed without any external
  schema or format negotiation
- No information leakage through file structure or field names to an observer
  who does not hold the passphrase

---

## 2. High-Level Structure

```
+─────────────────────────────────────────────────────────────+
|  SECTION 0  NZ Stub               2 bytes  (0x6E 0x7A)      |
|  SECTION 1  File Header          96 bytes  (plaintext)      |
|  SECTION 2  Header MAC           64 bytes  (HMAC-SHA-512)   |
|  SECTION 3  Payload Length        4 bytes  (big-endian u32) |
|  SECTION 4  Encrypted Payload     N bytes  (see below)      |
|  SECTION 5  File MAC             64 bytes  (HMAC-SHA-512)   |
+─────────────────────────────────────────────────────────────+
```

Minimum file size (0 credentials, 0 folders): 2 + 96 + 64 + 4 + 32 + minimal
payload + 64 = approximately 312 bytes.

---

## 2a. NZ Stub (Section 0, 2 bytes)

```
File offset  Bytes  Value       Description
───────────  ─────  ──────────  ────────────────────────────────────────────
 0            2     0x6E 0x7A   ASCII "nz" — DOS-style file-type signature
```

The NZ stub is the first thing in every `.p2w` file and serves as a
human-readable file-type marker, directly analogous to the `MZ` header
(0x4D 0x5A) that opens every Windows PE executable. Opening a `.p2w` file in
any hex editor, forensic disassembler (OllyDbg, x64dbg, HxD …), or `xxd`
will show `6E 7A` at offset 0 with the ASCII annotation `nz`, confirming at a
glance that the file is a valid PWDnow vault export.

A file that does **not** begin with `6E 7A` is rejected immediately as not a
valid `.p2w` file, before any passphrase is requested or any cryptographic
material is touched.

---

## 3. File Header (Section 1, 96 bytes)

All multi-byte integers are big-endian.  
Offsets below are **relative to the start of the header** (i.e. file offset = header offset + 2).

```
Header  File    Bytes  Field            Description
offset  offset
──────  ──────  ─────  ───────────────  ────────────────────────────────────────────
 0       2       4     MAGIC            0x50 0x32 0x57 0x01  ("P2W\x01")
 4       6       1     VERSION          Format version; currently 0x01
 5       7       1     CIPHER_SUITE     0x01 = PBKDF2-SHA-512 + AES-256-GCM
                                               + XChaCha20-Poly1305 + HMAC-SHA-512
 6       8       2     FLAGS            Reserved; must be 0x0000
 8      10       8     CREATED_AT       Export instant: milliseconds since Unix epoch
                                        (big-endian int64, upper 4 bytes then lower 4)
16      18       4     CRED_COUNT       Number of credential records in the payload
20      22       4     FOLD_COUNT       Number of folder records in the payload
24      26      32     KDF_SALT         Cryptographically random salt for PBKDF2
56      58       4     KDF_ITERS        PBKDF2 iteration count (minimum 600 000)
60      62      24     XCHACHA_NONCE    Cryptographically random nonce for XChaCha20
84      86      12     AES_GCM_NONCE    Cryptographically random nonce for AES-256-GCM
──────  ──────  ─────
Total           96
```

The header is written in plaintext so an authorised reader can learn the
export date and derive the decryption keys without reading the ciphertext
first. No credential data appears in the header.

---

## 4. Header MAC (Section 2, 64 bytes)

```
HMAC-SHA-512(K_mac, header[0..96))
```

Computed over the 96-byte file header using key K_mac (see Section 7).
Provides tamper-detection for all header fields before decryption begins.
A wrong passphrase or bit-flip in the header is detected here, not after
the expensive double-decryption step.

---

## 5. Encrypted Payload (Section 4)

The payload is produced by two sequential AEAD cipher layers applied to the
plaintext P2W Record Format (PRF) payload:

```
plaintext  ──[AES-256-GCM, K_aes, AES_GCM_NONCE]──► inner_ct   (+16 B tag)
inner_ct   ──[XChaCha20-Poly1305, K_xcha, XCHACHA_NONCE]──► outer_ct  (+16 B tag)
```

The outer_ct is stored in the file as SECTION 4. Total ciphertext overhead
above the plaintext size: 32 bytes (two 16-byte AEAD authentication tags).

Each cipher independently authenticates its output. Breaking one cipher layer
alone is insufficient; an attacker must break both to recover any plaintext.

---

## 6. File MAC (Section 5, 64 bytes)

```
HMAC-SHA-512(K_mac, file[0 .. filesize-64))
```

Computed over every byte of the file except the tag itself. Prevents offline
truncation, splicing, or any other mutation that would not be caught by the
individual AEAD tags. Verified first on import (before decryption) using a
timing-safe comparison.

---

## 7. Key Derivation

A single PBKDF2-SHA-512 call produces 96 bytes (768 bits) of key material
from the user's passphrase and the random KDF_SALT embedded in the header:

```
raw[0..96) = PBKDF2-SHA-512(passphrase, KDF_SALT, KDF_ITERS, 96)

K_xcha = raw[0..32)    XChaCha20-Poly1305 key
K_aes  = raw[32..64)   AES-256-GCM key
K_mac  = raw[64..96)   HMAC-SHA-512 key (noble/hashes pads to 128 B internally)
```

SHA-512 is used because its 512-bit output provides 256-bit post-quantum
security (Grover's algorithm halves security bits for search problems).
PBKDF2 iteration counts are memory-light but computationally expensive;
combined with the memory cost of the double decryption step this provides
adequate resistance to brute-force on consumer hardware.

The three subkeys are domain-separated by their byte positions within a
single derivation pass, which is equivalent to HKDF expansion from a
shared PRK when using an iterated KDF like PBKDF2.

---

## 8. P2W Record Format (PRF) — Inner Plaintext

The plaintext fed to the encryption layers is not JSON, CSV, or XML. It is a
custom binary Type-Length-Value (TLV) record stream.

### 8.1 File Identification

The first 4 bytes of the plaintext are the PRF magic word:

```
0xB7 0xA2 0x4F 0x03
```

These bytes are not printable ASCII and do not resemble any text-based
format preamble.

### 8.2 Record Structure

Following the magic, the stream consists of zero or more records until an
END record is encountered:

```
RTYPE   1 byte     Record type (see 8.3)
RLEN    4 bytes    Big-endian uint32: byte length of RDATA
RDATA   RLEN bytes Record body
```

An END record has RTYPE=0xFF and RLEN=0x00000000 with no RDATA.

### 8.3 Record Types

```
Value  Name    Description
0x01   META    Export metadata (app name, timestamp, counts)
0x10   FOLDER  Folder definition
0x20   ENTRY   Credential entry
0xFF   END     Stream terminator
```

Exactly one META record appears, followed by all FOLDER records, followed by
all ENTRY records, followed by the END record.

### 8.4 TLV Field Encoding Within Records

The RDATA of META, FOLDER, and ENTRY records is itself a TLV field sequence:

```
FTAG    1 byte     Field tag (see 8.5 – 8.7)
FLEN    2 bytes    Big-endian uint16: byte length of FDAT
FDAT    FLEN bytes Field value (UTF-8 text unless noted)
```

The sequence is terminated by a sentinel field with FTAG=0xFF, FLEN=0.
Fields with an empty or absent value are omitted entirely.

### 8.5 META Record Fields

```
Tag   Name             Encoding   Description
0x01  APP_NAME         UTF-8      Application name, e.g. "PWDnow"
0x02  APP_VERSION      UTF-8      Application version string
0x03  EXPORT_TIMESTAMP UTF-8      ISO 8601 UTC instant, e.g. "2026-05-01T19:23:00.000Z"
0x04  CRED_COUNT       uint32 BE  Number of ENTRY records that follow
0x05  FOLD_COUNT       uint32 BE  Number of FOLDER records that follow
0xFF  END              (no data)  Sentinel
```

The EXPORT_TIMESTAMP field is the authoritative export date in international
format (ISO 8601 / RFC 3339). It is stored inside the encrypted payload so
it cannot be tampered with without detection.

### 8.6 FOLDER Record Fields

```
Tag   Name             Description
0x01  ID               Unique folder identifier (UUID)
0x02  LABEL            Display name
0x03  DESCRIPTION      Optional description
0xFF  END
```

### 8.7 ENTRY Record Fields

```
Tag   Name             Description
0x01  ID               Unique credential identifier
0x02  SERVICE          Service or site name
0x03  URL              Login URL
0x04  USERNAME         Username or email
0x05  PASSWORD         Password (may be empty for passkeys)
0x06  NOTES            Free-text notes
0x07  OTP_SECRET       TOTP base-32 secret
0x08  FOLDER_ID        Parent folder ID (references a FOLDER record)
0x09  STATUS           Active/inactive status string
0x0A  TAGS             Comma-separated tag list
0x0B  CREDENTIAL_TYPE  "login" | "passkey" | "secure_note" | "payment_card"
0xFF  END
```

---

## 9. Import Verification Sequence

On import, the following checks must pass in this order before any credential
data is returned to the caller:

1. Verify NZ stub bytes at file offset 0 (0x6E 0x7A) — fail-fast, no key
   material needed.
2. Verify MAGIC bytes at file offset 2 (0x50 0x32 0x57 0x01).
3. Verify VERSION is supported.
4. Derive K_xcha, K_aes, K_mac from the passphrase and header KDF parameters.
5. Verify FILE_MAC: HMAC-SHA-512(K_mac, file[0..size-64)) against the stored
   last 64 bytes using a timing-safe comparison. The MAC covers the entire
   file including the NZ stub. A mismatch here means either the wrong
   passphrase or file tampering.
6. Verify HEADER_MAC: HMAC-SHA-512(K_mac, file[2..98)) against the stored
   bytes at file offset 98. Provides independent assurance the header was not
   mutated after the file MAC was computed.
7. Decrypt outer layer (XChaCha20-Poly1305). The cipher raises on tag
   mismatch.
8. Decrypt inner layer (AES-256-GCM). The cipher raises on tag mismatch.
9. Verify PRF magic bytes in the recovered plaintext.
10. Parse TLV records and return credentials and folders.

Any failure in steps 4 – 8 produces a generic "wrong passphrase or tampered
file" error. Internal cipher errors are not surfaced verbatim to prevent
oracle attacks.

---

## 10. Honest Threat Model and PQC Analysis

The dominant attack against any password-protected vault is **offline
brute-force of the passphrase**, not cryptanalysis of the symmetric ciphers.
This section is written with that fact in mind.

### 10.1 Symmetric primitives under Grover

Grover's algorithm provides a quadratic speedup for unstructured search,
halving the effective security bits of a *uniformly random* symmetric key
against a quantum adversary.

```
Primitive               Classical key   Quantum key (Grover)
──────────────────────  ─────────────   ─────────────────────
AES-256-GCM             2^256           2^128
XChaCha20-Poly1305      2^256           2^128
HMAC-SHA-512  (v1)      2^512           2^256
HMAC-SHA3-512 (v2)      2^512           2^256
```

These bounds are meaningful **only for the cipher key**, not for a
user-chosen passphrase. A 40-bit-entropy passphrase remains a 40-bit
target classically and a 20-bit target under Grover — neither bound is
where the security comes from.

### 10.2 Where confidentiality actually comes from

The real cost wall is the password-based KDF. A passphrase cracker's per-
guess cost is dominated by one KDF call.

```
Cipher suite  KDF                         Per-guess cost on RTX 4090
────────────  ──────────────────────────  ──────────────────────────────
0x01 (v1)     PBKDF2-SHA-512, 600 000 it  ~4 µs   (memory-light, GPU/ASIC-friendly)
0x02 (v2)     Argon2id m=256 MiB t=3 p=1  ~600 ms (memory-hard, GPU/ASIC-resistant)
```

The v1 → v2 migration raises the per-guess cost by a factor of roughly 10⁵
on consumer hardware and a comparable factor on FPGA / ASIC because the
attacker is now memory-bandwidth-bound, not compute-bound. v2 is therefore
the recommended cipher suite for all new exports; v1 remains supported for
import only.

### 10.3 Shor's algorithm

Shor's algorithm applies only to integer factorisation and discrete-log
problems (RSA, DH, ECDH). No asymmetric primitives are used in P2W v1 or
v2; the format is symmetric-key only, so Shor's algorithm is **not
applicable** at any iteration count.

### 10.4 Defence-in-depth: double AEAD

The cascade of AES-256-GCM and XChaCha20-Poly1305 means a cryptanalytic
break of either single cipher (a future key-recovery attack on AES-256, or
a Poly1305 forgery) is not on its own sufficient. **Both** cipher layers
must be broken to recover any plaintext. Note however that all three keys
(K_aes, K_xcha, K_mac) are derived from the same passphrase via a single
KDF pass — so a passphrase break collapses the whole stack at once. The
double-AEAD layer protects against cryptanalytic primitive attacks, **not**
against offline passphrase brute force; that is the KDF's job.

### 10.5 NIST PQC level claim

P2W v2 meets **NIST PQC Level 1** for its symmetric primitives
(AES-256-GCM, XChaCha20-Poly1305, HMAC-SHA3-512) and offers
**memory-hard password protection** through Argon2id at the
recommended m=256 MiB / t=3 / p=1 parameters. P2W v2 does **not** include
asymmetric PQC primitives (ML-KEM, ML-DSA, etc.) and is not advertised as
PQC-safe for any *recipient-encrypted* (asymmetric) use case — only for
passphrase-protected exports.

### 10.6 CIA triad

- **Confidentiality**: dominated by passphrase entropy + KDF cost. Cipher
  layers (AES-256-GCM + XChaCha20-Poly1305) provide ≥ 256-bit classical /
  128-bit quantum security on the cipher key once derived.
- **Integrity**: header bound as AAD on both AEAD tags (v2 only) plus
  HMAC-SHA3-512 over header and entire file. Any single-bit mutation is
  detected before plaintext is returned, with three independent paths.
- **Availability**: self-contained, no external key store, no certificate
  authority, no revocation service.

---

## 11. Implementation Notes

- All random values (KDF_SALT, XCHACHA_NONCE, AES_GCM_NONCE) are generated
  with crypto.getRandomValues (CSPRNG). They are never reused.
- The KDF produces independent subkeys from a single derivation pass. The
  three subkeys (K_xcha, K_aes, K_mac) are separated by fixed byte positions,
  which is safe because PBKDF2 output bytes are pseudo-random and the
  positions are non-overlapping.
- The XChaCha20-Poly1305 nonce is 24 bytes (extended nonce), which eliminates
  nonce-collision risk even if CSPRNG output quality is reduced.
- Timing-safe comparison is used for all MAC verification to prevent
  timing-oracle attacks.
- The inner plaintext magic word (0xB7 0xA2 0x4F 0x03) is validated after
  decryption to detect format corruption that survived the AEAD tags.
- Passphrase material is not stored or logged anywhere. The PBKDF2 call is
  the only place the passphrase bytes touch the derived key material.

---

## 12. Planned Suite 0x03 — Recipient-Encrypted Export (deferred to Phase H)

Suite 0x03 extends P2W v2 to support asymmetric recipient encryption. Instead
of a passphrase-derived key, the file key is wrapped to a recipient public key
using a hybrid KEM (X25519 + ML-KEM-1024) at NIST PQC Level 5.

### 12.1 Header delta

| Offset | Field             | Size     | Notes |
|--------|-------------------|----------|-------|
| 0      | CIPHER_SUITE      | 1 B      | 0x03  |
| 1–32   | EPHEMERAL_X25519_PK | 32 B  | Sender's ephemeral X25519 public key |
| 33–1600| ML_KEM_CT         | 1568 B   | ML-KEM-1024 ciphertext |
| 1601–1632 | RECIPIENT_PK_HASH | 32 B | SHA3-256 of recipient's full public key (binding) |

### 12.2 Key derivation delta

```
kem_ss = X25519(ephemeral_sk, recipient_x25519_pk) || ML-KEM-1024-Decapsulate(ml_dk, ml_ct)
file_key = HKDF-SHA3-512(kem_ss, "p2w/v3/file-key", 32)
```

The remaining AEAD double-layer and HMAC-SHA3-512 MAC are unchanged from suite 0x02.
Recipients must verify `RECIPIENT_PK_HASH` matches their key before decapsulating.

### 12.3 Implementation status

Suite 0x03 is **planned but not yet implemented**. The dispatcher in
`importFromP2W` rejects `cipher_suite=0x03` with the generic `FAIL` message
until Phase H delivers the full implementation. Do not rely on this format for
production use.

---

## 13. File Extension and MIME Type

```
Extension:  .p2w
MIME type:  application/x-pwdnow-vault
```

The extension is not registered with IANA. Tools that import the file must
detect it by the 4-byte magic word, not by the file extension alone.

---

## 13. Cipher Suite 0x02 (current default for new exports)

Cipher suite `0x02` is the current default, written by every `exportToP2W`
call. Suite `0x01` (sections 5–9 above) remains supported for import only,
to allow legacy `.p2w` files to be migrated.

The on-disk layout is **identical** to suite 0x01 (NZ stub + 96 B header +
64 B header MAC + 4 B payload length + ciphertext + 64 B file MAC); the
differences are entirely in the cryptographic primitives and in how three
header fields are interpreted.

### 13.1 Header changes for suite 0x02

```
Hdr off  Bytes  v1 (suite 0x01)        v2 (suite 0x02)
─────── ─────  ────────────────────  ───────────────────────────────────────────
 5        1    CIPHER_SUITE = 0x01   CIPHER_SUITE = 0x02
 8        8    CREATED_AT (ms BE)    0x00 × 8           (encrypted-only, in PRF)
16        4    CRED_COUNT            0x00 × 4           (encrypted-only, in PRF)
20        4    FOLD_COUNT            0x00 × 4           (encrypted-only, in PRF)
56        4    PBKDF2 iters (BE)     Argon2id parameters, packed:
                                       byte 0 : log2(m_KiB)   (12..20 → 4 MiB..1 GiB)
                                       byte 1 : t              (1..10)
                                       byte 2 : p              (1..4)
                                       byte 3 : reserved 0x00
```

All other header bytes (MAGIC, VERSION, FLAGS, KDF_SALT, XCHACHA_NONCE,
AES_GCM_NONCE) are unchanged. The NZ stub at file offset 0 is unchanged
across all suite versions.

### 13.2 Key derivation for suite 0x02

```
master = Argon2id(NFC(passphrase), KDF_SALT, m, t, p, dkLen = 64)

K_aes  = HKDF-Expand(SHA3-512, master, info = "p2w/v2/aes-256-gcm",       L = 32)
K_xcha = HKDF-Expand(SHA3-512, master, info = "p2w/v2/xchacha20-poly",    L = 32)
K_mac  = HKDF-Expand(SHA3-512, master, info = "p2w/v2/hmac-sha3-512-mac", L = 64)
```

Domain-separation labels prevent a byte-slice attack against the master
output: an attacker cannot reuse v1's "K_mac = bytes[64..96]" attack code
against a v2 file.

The passphrase is NFC-normalised before UTF-8 encoding so that visually
identical strings (precomposed vs. decomposed Unicode) produce identical
KDF inputs across operating systems and keyboards.

### 13.3 Encryption for suite 0x02

The 96-byte header is bound as **additional authenticated data** on both
AEAD layers:

```
inner_ct = AES-256-GCM.encrypt(plaintext,  key=K_aes,  nonce=AES_GCM_NONCE,
                               AAD = header[0..96])
outer_ct = XChaCha20-Poly1305.encrypt(inner_ct, key=K_xcha, nonce=XCHACHA_NONCE,
                                       AAD = header[0..96])
```

Any header mutation now fails the AEAD tag check independently of the
HMAC, removing reliance on a single integrity primitive.

### 13.4 Integrity for suite 0x02

```
HEADER_MAC = HMAC-SHA3-512(K_mac, header[0..96))
FILE_MAC   = HMAC-SHA3-512(K_mac, file[0 .. filesize - 64))
```

Hash function changed from SHA-512 to SHA3-512 (Keccak family), aligning
with NIST's PQC-recommended hash. SHA3 is also resistant to length-
extension attacks that HMAC already guards against — included for
defence in depth across primitive families.

---

## 14. Import Verification Sequence (covers both suites)

On import, the following checks run in this order. Any failure in steps
4 onward returns the single error message `"Wrong passphrase or file has
been tampered with."`. Internal cipher and bound-check errors are not
surfaced verbatim.

1. Verify NZ stub bytes at file offset 0 (`0x6E 0x7A`).
2. Verify MAGIC bytes at file offset 2 (`0x50 0x32 0x57 0x01`).
3. Verify VERSION (currently `0x01`).
4. Read CIPHER_SUITE at file offset 7 and dispatch:
   - `0x01` → legacy v1 path.
   - `0x02` → current v2 path.
   - any other value → reject.
5. Bound-check the KDF parameters read from the header:
   - v1: `100 000 ≤ PBKDF2_iters ≤ 5 000 000`.
   - v2: `12 ≤ log2(m) ≤ 20`, `1 ≤ t ≤ 10`, `1 ≤ p ≤ 4`.
6. Cross-check the payload length: total file size must equal
   `2 + 96 + 64 + 4 + payload_len + 64`.
7. Derive subkeys (`K_aes`, `K_xcha`, `K_mac`) per suite.
8. Verify FILE_MAC over `file[0 .. size − 64)` (timing-safe).
9. Verify HEADER_MAC over `file[2 .. 98)` (timing-safe).
10. Decrypt outer AEAD layer (XChaCha20-Poly1305). For v2, header is the
    AAD; for v1, no AAD.
11. Decrypt inner AEAD layer (AES-256-GCM). Same AAD rule.
12. Verify PRF magic bytes in the recovered plaintext.
13. Parse TLV records with strict bounds; cross-validate META `CRED_COUNT`
    and `FOLD_COUNT` against the actually-parsed record counts.
14. Zeroise derived keys before returning.

---

## 15. Cipher-Suite Migration Notes

- Existing v1 `.p2w` files **continue to import** without user action; the
  importer dispatches by the cipher_suite byte.
- `exportToP2W` always writes suite 0x02. There is no way to ask the
  library to write suite 0x01.
- The recommended user flow for migrating a vault is: import the v1 file
  with the old passphrase, then export immediately (a v2 file is written).
- The cipher_suite byte and the KDF parameters are **bound into the AEAD
  AAD** in v2 (because they live inside the header). An attacker cannot
  silently downgrade a v2 file to v1 — any such mutation breaks both the
  AEAD tag and the HMAC.
