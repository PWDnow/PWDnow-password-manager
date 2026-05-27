/**
 * HIBP k-Anonymity Range API — client-side breach check.
 *
 * How it works:
 *   1. SHA-1 hash the plaintext password using Web Crypto API.
 *   2. Split the hex digest into a 5-char prefix and a 35-char suffix.
 *   3. Send only the prefix to api.pwnedpasswords.com/range/{prefix}.
 *   4. The response is a list of suffixes + occurrence counts; search for ours.
 *
 * This is the standard k-anonymity model recommended by Troy Hunt / HIBP:
 *   - The full hash never leaves the browser.
 *   - The 5-char prefix maps to ~500 hashes, hiding which one we checked.
 *   - No API key required; no rate limit for reasonable usage.
 *
 * Security notes:
 *   - SHA-1 is used ONLY for HIBP lookup (the protocol mandates it).
 *     We never use SHA-1 for password storage or authentication.
 *   - The plaintext is encoded to UTF-8, hashed, then compared uppercase.
 *   - AbortController allows callers to cancel stale requests (debounce).
 */

const HIBP_RANGE_URL = 'https://api.pwnedpasswords.com/range/';

export interface HibpResult {
  /** Whether this password appears in any known data breach. */
  pwned: boolean;
  /** Number of times found in breaches. 0 if not found. */
  count: number;
}

/**
 * Convert an ArrayBuffer to an uppercase hex string.
 * Uses a pre-built lookup table for performance.
 */
const HEX_TABLE = Array.from({ length: 256 }, (_, i) =>
  i.toString(16).padStart(2, '0').toUpperCase(),
);

function bufToHex(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += HEX_TABLE[bytes[i]];
  }
  return hex;
}

/**
 * Check whether a password has been exposed in known data breaches
 * using the HIBP k-anonymity range API.
 *
 * @param password  The plaintext password to check.
 * @param signal    Optional AbortSignal for cancellation (debounce).
 * @returns         `{ pwned, count }` — count is 0 if not found.
 * @throws          On network errors, aborted requests, or non-2xx responses.
 */
export async function checkHibpPassword(
  password: string,
  signal?: AbortSignal,
): Promise<HibpResult> {
  // Step 1: SHA-1 hash via Web Crypto (the only acceptable SHA-1 use case).
  // SHA-1 is mandated by the HIBP k-anonymity protocol for prefix lookups.
  // It is NEVER used for password storage, authentication, or key derivation.
  const encoded = new TextEncoder().encode(password);
  // snyk:ignore javascript/InsecureHash — HIBP protocol requires SHA-1; not used for password storage
  const hashBuf = await crypto.subtle.digest('SHA-1', encoded);
  const hashHex = bufToHex(hashBuf); // e.g. "E5366353F151B3693AC52273EC1221E6BD412887"

  // Step 2: Split into prefix (5 chars) and suffix (35 chars).
  const prefix = hashHex.slice(0, 5);
  const suffix = hashHex.slice(5);

  // Step 3: Query the HIBP range endpoint.
  const response = await fetch(`${HIBP_RANGE_URL}${prefix}`, {
    signal,
    headers: {
      // Pad responses to a uniform size to prevent response-length fingerprinting.
      'Add-Padding': 'true',
    },
  });

  if (!response.ok) {
    throw new Error(`HIBP API returned ${response.status}`);
  }

  const body = await response.text();

  // Step 4: Search the response for our suffix.
  // Format: "SUFFIX:COUNT\r\n" per line. Suffix is uppercase hex, count is decimal.
  // Padded lines (from Add-Padding) have a count of 0 and start with "0" — skip them.
  const lines = body.split('\r\n');
  for (const line of lines) {
    if (!line) continue;
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;

    const lineSuffix = line.slice(0, colonIdx);
    if (lineSuffix === suffix) {
      const count = parseInt(line.slice(colonIdx + 1), 10);
      // Padded entries have count=0; treat those as not-pwned.
      if (count > 0) {
        return { pwned: true, count };
      }
    }
  }

  return { pwned: false, count: 0 };
}
