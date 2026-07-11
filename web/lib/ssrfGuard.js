// web/lib/ssrfGuard.js
// Resolves a user-supplied hostname and verifies every resulting address is a
// public, routable address — not loopback/RFC-1918/link-local/CGNAT/ULA. A
// hostname-string regex alone (the previous approach) does not stop an
// attacker pointing a public DNS name at an internal IP (DNS rebinding).
import { promises as dns } from 'dns';
import { isIP } from 'net';

function isPrivateV4(ip) {
  return (
    /^0\./.test(ip) ||
    /^127\./.test(ip) ||
    /^10\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^169\.254\./.test(ip) ||                       // link-local / cloud metadata
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip) // CGNAT 100.64.0.0/10
  );
}

function isPrivateV6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('fe80:')) return true;        // link-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // ULA
  if (lower.startsWith('::ffff:')) return isPrivateV4(lower.slice(7));
  return false;
}

/**
 * Returns true only if `hostname` is not a loopback/private literal and every
 * address it resolves to (A/AAAA) is a public address. Returns false on any
 * resolution failure (fail closed).
 */
export async function resolvesToPublicHost(hostname) {
  const lower = String(hostname).trim().toLowerCase();
  if (!lower || lower === 'localhost') return false;

  const ipVer = isIP(lower);
  if (ipVer === 4) return !isPrivateV4(lower);
  if (ipVer === 6) return !isPrivateV6(lower);

  let addrs;
  try {
    addrs = await dns.lookup(lower, { all: true, verbatim: true });
  } catch {
    return false;
  }
  if (addrs.length === 0) return false;

  for (const { address, family } of addrs) {
    if (family === 4 && isPrivateV4(address)) return false;
    if (family === 6 && isPrivateV6(address)) return false;
  }
  return true;
}
