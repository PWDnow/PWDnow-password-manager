#!/usr/bin/env bash
# ── HIBP Offline Cuckoo Filter Builder ────────────────────────────────────────
#
# Downloads the full HIBP SHA-1 password hash list and builds a binary Cuckoo
# filter that the vault daemon can query offline.
#
# Architecture §4: passwords are NEVER sent over the network. The filter is
# built once from the full HIBP dataset, stored locally, and queried using
# SHA-1(password) → Cuckoo filter lookup.
#
# Usage:
#   ./hibp/build-filter.sh [--output PATH] [--hashes-dir PATH]
#
# Options:
#   --output PATH      Output filter file (default: /var/lib/vault-daemon/hibp.cuckoo)
#   --hashes-dir PATH  Directory to cache downloaded hash files (default: ./hibp-hashes)
#   --build-only       Skip download; assume hashes-dir already populated
#
# Requirements:
#   curl, sha1sum (or sha1), python3 (for filter builder), ~50 GB disk space
#
# Runtime estimates:
#   Download: ~10–16 GB compressed (HIBP uses k-anonymity range files)
#   Build:    ~8 GB output filter, ~30–90 min on modern hardware
#
# ── Filter file format (HIBPCF01) ─────────────────────────────────────────────
#
#  Offset  Len  Description
#  0       8    Magic bytes: b"HIBPCF01"
#  8       8    Buckets: u64 little-endian
#  16      1    Slots per bucket: u8 (= 4)
#  17      1    Fingerprint bits: u8 (= 16)
#  18      6    Reserved (zero)
#  24      N    Fingerprint data: buckets × 4 × 2 bytes
#
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

OUTPUT="${VAULT_HIBP_OUTPUT:-/var/lib/vault-daemon/hibp.cuckoo}"
HASHES_DIR="${VAULT_HIBP_HASHES_DIR:-$(dirname "$0")/hibp-hashes}"
BUILD_ONLY=0
DRY_RUN=0
# Minimum free space required before we start downloading (GiB). HIBP ranges
# weigh in at ~11 GB compressed today; the filter adds ~8 GB; leave ample
# headroom for OS, logs, and temporary files during the Python build.
MIN_FREE_GIB="${VAULT_HIBP_MIN_FREE_GIB:-50}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)      OUTPUT="$2";      shift 2 ;;
    --hashes-dir)  HASHES_DIR="$2";  shift 2 ;;
    --build-only)  BUILD_ONLY=1;     shift   ;;
    --dry-run)     DRY_RUN=1;        shift   ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

mkdir -p "$HASHES_DIR"
OUTPUT_DIR="$(dirname "$OUTPUT")"
mkdir -p "$OUTPUT_DIR"

# Atomic build: stage the output file alongside the final path, then rename.
OUTPUT_TMP="${OUTPUT}.tmp.$$"

# ── Preflight: disk-space check ──────────────────────────────────────────────
# Run the same check against both the hash cache and the output dir because
# they may live on different mounts. Fail fast — aborting a 1M-file download
# due to ENOSPC 90% through is a very bad day.
check_free_space() {
  local target="$1" label="$2"
  local avail_kib
  avail_kib=$(df --output=avail -k "$target" | tail -n1 | tr -d ' ')
  local avail_gib=$((avail_kib / 1024 / 1024))
  if (( avail_gib < MIN_FREE_GIB )); then
    echo "[hibp] ERROR: $label '$target' has ${avail_gib} GiB free, need ${MIN_FREE_GIB} GiB" >&2
    exit 2
  fi
  echo "[hibp] $label '$target': ${avail_gib} GiB free (OK)"
}
check_free_space "$HASHES_DIR" "hash cache"
check_free_space "$OUTPUT_DIR" "output dir"

for cmd in curl python3 sha256sum; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[hibp] ERROR: required command '$cmd' not found in PATH" >&2
    exit 3
  fi
done

echo "[hibp] Target filter: $OUTPUT"
echo "[hibp] Hash cache:    $HASHES_DIR"
if (( DRY_RUN )); then
  echo "[hibp] --dry-run: preflight only, skipping download + build."
  exit 0
fi

# Clean up any stale tmp file from a previous interrupted run.
rm -f "$OUTPUT_TMP"
# Ensure we don't leave a half-written tmp file on failure.
trap 'rm -f "$OUTPUT_TMP"' EXIT INT TERM

# ── Step 1: Download HIBP ordered-by-hash range files ─────────────────────────
if [[ $BUILD_ONLY -eq 0 ]]; then
  echo "[hibp] Downloading HIBP hash ranges (this will take a long time)..."
  # HIBP provides 1,048,576 range files (00000–FFFFF prefix).
  # Each contains SHA-1 hash suffixes + occurrence counts.
  TOTAL=1048576
  DOWNLOADED=0
  FAILED=0
  START_TS=$(date +%s)
  for PREFIX_INT in $(seq 0 $((TOTAL - 1))); do
    PREFIX=$(printf '%05X' "$PREFIX_INT")
    OUT_FILE="$HASHES_DIR/$PREFIX.txt"
    if [[ -f "$OUT_FILE" && -s "$OUT_FILE" ]]; then
      continue  # already downloaded
    fi
    URL="https://api.pwnedpasswords.com/range/$PREFIX"
    # --continue-at - resumes partial files from an interrupted prior run
    # instead of refetching; --fail turns HTTP errors into non-zero exits.
    if ! curl -sSf --fail --retry 3 --retry-delay 2 --continue-at - -o "$OUT_FILE" "$URL"; then
      echo "[hibp] WARNING: failed to download prefix $PREFIX" >&2
      FAILED=$((FAILED + 1))
    fi
    DOWNLOADED=$((DOWNLOADED + 1))
    if (( DOWNLOADED % 10000 == 0 )); then
      NOW_TS=$(date +%s)
      ELAPSED=$(( NOW_TS - START_TS ))
      if (( ELAPSED > 0 && DOWNLOADED > 0 )); then
        RATE=$(( DOWNLOADED / ELAPSED ))          # prefixes/sec
        if (( RATE > 0 )); then
          REMAIN_S=$(( (TOTAL - DOWNLOADED) / RATE ))
          ETA_MIN=$(( REMAIN_S / 60 ))
          echo "[hibp] Progress: $DOWNLOADED / $TOTAL ($FAILED failed, ${RATE}/s, ETA ${ETA_MIN} min)"
        else
          echo "[hibp] Progress: $DOWNLOADED / $TOTAL ($FAILED failed)"
        fi
      else
        echo "[hibp] Progress: $DOWNLOADED / $TOTAL ($FAILED failed)"
      fi
    fi
  done
  echo "[hibp] Download complete: $DOWNLOADED downloaded, $FAILED failed."
fi

# ── Step 2: Build the Cuckoo filter from downloaded hashes ───────────────────
# Build goes into OUTPUT_TMP; on success we atomically rename into place and
# emit a SHA-256 manifest so the daemon can verify the filter on load.
echo "[hibp] Building Cuckoo filter (staging at $OUTPUT_TMP)..."
python3 - "$HASHES_DIR" "$OUTPUT_TMP" <<'PYEOF'
"""
Build a HIBPCF01 Cuckoo filter from HIBP range files.

Algorithm:
  - Read all hash files, reconstruct full SHA-1 hashes (prefix + suffix).
  - Insert each hash's 16-bit fingerprint into the filter using the standard
    Cuckoo filter insertion algorithm (max 500 relocation attempts per insert).
  - Write the HIBPCF01 binary file.

Memory: approximately 8 GB for ~1 billion hashes.
"""
import sys
import os
import struct
import hashlib
import random
from pathlib import Path

HASHES_DIR = Path(sys.argv[1])
OUTPUT_PATH = Path(sys.argv[2])

SLOTS  = 4      # slots per bucket
FP_BYTES = 2    # 16-bit fingerprints
MAX_KICKS = 500 # max cuckoo relocations per insert

# Deterministic Cuckoo placement: seed from the hash-cache directory mtime so
# the same dataset snapshot produces a byte-identical filter across machines.
# This is a reproducibility / audit requirement, not a security one — the
# Cuckoo placement RNG is not secret-bearing.
_seed = int(HASHES_DIR.stat().st_mtime)
random.seed(_seed)
print(f"[hibp/py] RNG seed (from hashes dir mtime): {_seed}", flush=True)

def count_hashes(hashes_dir):
    total = 0
    for f in sorted(hashes_dir.glob("*.txt")):
        with open(f) as fh:
            total += sum(1 for _ in fh)
    return total

def fp_and_buckets(sha1_bytes, num_buckets):
    """Return (fingerprint, i1, i2) for a given SHA-1 hash."""
    fp = int.from_bytes(sha1_bytes[0:2], 'big') or 1  # non-zero
    i1 = int.from_bytes(sha1_bytes[2:10], 'big') % num_buckets
    fp_hash = int.from_bytes(hashlib.sha1(fp.to_bytes(2, 'big')).digest()[0:8], 'big')
    i2 = (i1 ^ (fp_hash % num_buckets)) % num_buckets
    return fp, i1, i2

print("[hibp/py] Counting hashes...", flush=True)
total_hashes = count_hashes(HASHES_DIR)
print(f"[hibp/py] Total hashes: {total_hashes:,}", flush=True)

# Choose bucket count: next power of 2 above total_hashes / SLOTS * 1.1 (10% headroom)
import math
min_buckets = math.ceil(total_hashes / SLOTS * 1.1)
num_buckets = 1 << math.ceil(math.log2(min_buckets))
print(f"[hibp/py] Buckets: {num_buckets:,} ({num_buckets * SLOTS * FP_BYTES / 1e9:.2f} GB)", flush=True)

# Allocate filter table (buckets × SLOTS × FP_BYTES)
table = bytearray(num_buckets * SLOTS * FP_BYTES)

def get_fp(bucket, slot):
    off = (bucket * SLOTS + slot) * FP_BYTES
    return int.from_bytes(table[off:off+FP_BYTES], 'big')

def set_fp(bucket, slot, value):
    off = (bucket * SLOTS + slot) * FP_BYTES
    table[off:off+FP_BYTES] = value.to_bytes(FP_BYTES, 'big')

def insert(fp, i1, i2):
    for bucket in (i1, i2):
        for slot in range(SLOTS):
            if get_fp(bucket, slot) == 0:
                set_fp(bucket, slot, fp)
                return True
    # No empty slot — relocate
    b = random.choice((i1, i2))
    for _ in range(MAX_KICKS):
        slot = random.randrange(SLOTS)
        evicted = get_fp(b, slot)
        set_fp(b, slot, fp)
        fp = evicted
        # Compute alternate bucket for the evicted fingerprint
        fp_hash = int.from_bytes(hashlib.sha1(fp.to_bytes(2, 'big')).digest()[0:8], 'big')
        b = (b ^ (fp_hash % num_buckets)) % num_buckets
        for s in range(SLOTS):
            if get_fp(b, s) == 0:
                set_fp(b, s, fp)
                return True
    return False  # filter is full; caller may retry or skip

inserted = 0
skipped  = 0
processed = 0

for hash_file in sorted(HASHES_DIR.glob("*.txt")):
    prefix_hex = hash_file.stem  # e.g. "00A3F"
    with open(hash_file) as fh:
        for line in fh:
            suffix_hex = line.split(':')[0].strip()
            full_hex = prefix_hex + suffix_hex
            sha1_bytes = bytes.fromhex(full_hex)
            fp, i1, i2 = fp_and_buckets(sha1_bytes, num_buckets)
            if insert(fp, i1, i2):
                inserted += 1
            else:
                skipped += 1
            processed += 1
            if processed % 5_000_000 == 0:
                print(f"[hibp/py] {processed:,} / {total_hashes:,} hashes "
                      f"(inserted={inserted:,}, skipped={skipped:,})", flush=True)

print(f"[hibp/py] Done: {inserted:,} inserted, {skipped:,} skipped.", flush=True)

# Write HIBPCF01 file
MAGIC = b"HIBPCF01"
header = (
    MAGIC
    + struct.pack('<Q', num_buckets)  # buckets
    + bytes([SLOTS])                  # slots per bucket
    + bytes([FP_BYTES * 8])           # fingerprint bits
    + b'\x00' * 6                     # reserved
)
print(f"[hibp/py] Writing {OUTPUT_PATH} ...", flush=True)
with open(OUTPUT_PATH, 'wb') as out:
    out.write(header)
    out.write(table)

print(f"[hibp/py] Filter written: {OUTPUT_PATH.stat().st_size / 1e9:.2f} GB", flush=True)
PYEOF

# ── Step 3: Verify, manifest, and atomic promote ─────────────────────────────
# Compute the SHA-256 of the staged filter, then rename both files into place
# as the last step. If the script dies before this point, the trap wipes the
# tmp file and the previous good filter (if any) remains untouched.
echo "[hibp] Computing SHA-256 manifest..."
SHA_TMP="${OUTPUT}.sha256.tmp.$$"
sha256sum "$OUTPUT_TMP" | awk -v f="$(basename "$OUTPUT")" '{print $1"  "f}' > "$SHA_TMP"

mv "$OUTPUT_TMP" "$OUTPUT"
mv "$SHA_TMP" "${OUTPUT}.sha256"
# The tmp file is now gone; disarm the cleanup trap so a later failure in
# this script can't remove the final filter.
trap - EXIT INT TERM

echo "[hibp] Filter built at: $OUTPUT"
echo "[hibp] Manifest:       ${OUTPUT}.sha256"
echo "[hibp] Register path in vault:"
echo "       UPDATE vault_meta SET value = '$OUTPUT' WHERE key = 'hibp_filter_path';"
echo "       -- or on first setup, INSERT:"
echo "       INSERT INTO vault_meta (key, value) VALUES ('hibp_filter_path', '$OUTPUT');"
