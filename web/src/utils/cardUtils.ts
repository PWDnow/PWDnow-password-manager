// Configuration from VITE_ environment variables (exposed to browser bundle, not secrets)
export const PAN_MAX_LENGTH       = Math.max(1, parseInt(import.meta.env.VITE_PAN_LENGTH          ?? '16', 10) || 16);
export const CARD_EXPIRY_MIN_DAYS = Math.max(0, parseInt(import.meta.env.VITE_CARD_EXPIRY_MIN_DAYS ?? '5',  10) || 5);
// How many trailing digits to reveal in the masked view (0 = full mask)
export const PAN_UNHIDE           = Math.max(0, parseInt(import.meta.env.VITE_PAN_UNHIDE           ?? '3',  10) || 0);
// Allow the browser's built-in password manager to autofill fields (default: false)
export const BROWSER_AUTOFILL     = import.meta.env.VITE_BROWSER_AUTOFILL === 'true';

// Optional regex override for PAN format validation — empty = smart BIN detection
export const PAN_FORMAT_REGEX: RegExp | null = (() => {
  const raw: string | undefined = import.meta.env.VITE_PAN_FORMAT;
  if (!raw) return null;
  try { return new RegExp(raw); } catch { return null; }
})();

export interface CardNetwork {
  id: string;
  label: string;    // display badge text e.g. "MASTERCARD"
  bgColor: string;  // badge background (hex)
  textColor: string;
  lengths: number[];   // valid PAN digit counts
  cvvLength: number;
  format: number[];    // digit group sizes e.g. [4,4,4,4] or [4,6,5]
}

export const NETWORKS: Record<string, CardNetwork> = {
  visa:       { id: 'visa',       label: 'VISA',       bgColor: '#1a1aff', textColor: '#fff', lengths: [13, 16],                       cvvLength: 3, format: [4, 4, 4, 4] },
  mastercard: { id: 'mastercard', label: 'MASTERCARD', bgColor: '#eb001b', textColor: '#fff', lengths: [16],                           cvvLength: 3, format: [4, 4, 4, 4] },
  amex:       { id: 'amex',       label: 'AMEX',       bgColor: '#2d7dd2', textColor: '#fff', lengths: [15],                           cvvLength: 4, format: [4, 6, 5]    },
  discover:   { id: 'discover',   label: 'DISCOVER',   bgColor: '#f97316', textColor: '#fff', lengths: [16],                           cvvLength: 3, format: [4, 4, 4, 4] },
  jcb:        { id: 'jcb',        label: 'JCB',        bgColor: '#10b981', textColor: '#fff', lengths: [16, 17, 18, 19],               cvvLength: 3, format: [4, 4, 4, 4] },
  diners:     { id: 'diners',     label: 'DINERS',     bgColor: '#6366f1', textColor: '#fff', lengths: [14],                           cvvLength: 3, format: [4, 6, 4]    },
  unionpay:   { id: 'unionpay',   label: 'UNIONPAY',   bgColor: '#f59e0b', textColor: '#fff', lengths: [16, 17, 18, 19],               cvvLength: 3, format: [4, 4, 4, 4] },
  maestro:    { id: 'maestro',    label: 'MAESTRO',    bgColor: '#ec4899', textColor: '#fff', lengths: [12, 13, 14, 15, 16, 17, 18, 19], cvvLength: 3, format: [4, 4, 4, 4] },
  rupay:      { id: 'rupay',      label: 'RUPAY',      bgColor: '#8b5cf6', textColor: '#fff', lengths: [16],                           cvvLength: 3, format: [4, 4, 4, 4] },
};

/**
 * Detect card network from BIN/IIN prefix.
 * Priority order matters — more specific ranges checked first.
 */
export function detectCardNetwork(rawPan: string): CardNetwork | null {
  const d = rawPan.replace(/\D/g, '');
  if (!d) return null;

  const p2 = d.length >= 2 ? parseInt(d.substring(0, 2), 10) : -1;
  const p3 = d.length >= 3 ? parseInt(d.substring(0, 3), 10) : -1;
  const p4 = d.length >= 4 ? parseInt(d.substring(0, 4), 10) : -1;
  const p6 = d.length >= 6 ? parseInt(d.substring(0, 6), 10) : -1;

  // Amex: 34, 37 — check before generic 3x
  if (p2 === 34 || p2 === 37) return NETWORKS.amex;

  // JCB: 3528–3589 — check before Diners (both start with 3)
  if (p4 >= 3528 && p4 <= 3589) return NETWORKS.jcb;

  // Diners Club: 300–305, 36, 38, 39
  if ((p3 >= 300 && p3 <= 305) || p2 === 36 || p2 === 38 || p2 === 39) return NETWORKS.diners;

  // Visa: starts with 4
  if (d[0] === '4') return NETWORKS.visa;

  // Mastercard: 51–55, 2221–2720 (newer range added by Mastercard)
  if ((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) return NETWORKS.mastercard;

  // Discover: 6011, 622126–622925, 644–649, 65 — check before UnionPay (62 overlaps)
  if (
    p4 === 6011 ||
    (p6 >= 622126 && p6 <= 622925) ||
    (p3 >= 644 && p3 <= 649) ||
    p2 === 65
  ) return NETWORKS.discover;

  // UnionPay / Alipay: 62 (broad range; Alipay-issued cards ride on UnionPay rails)
  if (p2 === 62) return NETWORKS.unionpay;

  // RuPay: 508, 81, 82 (60 conflicts with Discover/Maestro — skip that prefix)
  if (p3 === 508 || p2 === 81 || p2 === 82) return NETWORKS.rupay;

  // Maestro: 50, 56–69 (broad range, check last among 5x/6x)
  if (p2 === 50 || (p2 >= 56 && p2 <= 69)) return NETWORKS.maestro;

  return null;
}

/**
 * Masked view: replace all but the last `unhideCount` digits with X, then apply 4-4-4-4 spacing.
 * Example: ("4111111111111767", 3) → "XXXX XXXX XXXX X767"
 */
export function maskPan(digits: string, unhideCount: number): string {
  if (!digits) return '';
  const visibleStart = Math.max(0, digits.length - unhideCount);
  const masked = 'X'.repeat(visibleStart) + digits.slice(visibleStart);
  return formatPan(masked, null);
}

/** Format raw digits into spaced groups per network (e.g. "4111111111111111" → "4111 1111 1111 1111"). */
export function formatPan(digits: string, network: CardNetwork | null): string {
  const groups = network?.format ?? [4, 4, 4, 4];
  let pos = 0;
  const parts: string[] = [];
  for (const len of groups) {
    const chunk = digits.slice(pos, pos + len);
    if (!chunk) break;
    parts.push(chunk);
    pos += len;
  }
  return parts.join(' ');
}

/** Maximum digit count for a detected network, or PAN_MAX_LENGTH env fallback. */
export function maxPanLength(network: CardNetwork | null): number {
  if (!network) return PAN_MAX_LENGTH;
  return Math.max(...network.lengths);
}

/** Luhn algorithm — returns true when the check digit is correct. */
export function luhnCheck(rawDigits: string): boolean {
  const d = rawDigits.replace(/\D/g, '');
  if (!d || d.length < 2) return false;
  let sum = 0;
  let isEven = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let digit = parseInt(d[i], 10);
    if (isEven) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    isEven = !isEven;
  }
  return sum % 10 === 0;
}

/** True when the PAN length matches one of the network's valid lengths. */
export function isPanComplete(rawDigits: string, network: CardNetwork | null): boolean {
  const len = rawDigits.replace(/\D/g, '').length;
  if (!network) return len === PAN_MAX_LENGTH;
  return network.lengths.includes(len);
}

/**
 * Days remaining until end of the card's expiry month.
 * Negative = already expired. null = unparseable input.
 */
export function daysUntilExpiry(mmYyyy: string): number | null {
  const m = mmYyyy.match(/^(\d{1,2})\/(\d{4})$/);
  if (!m) return null;
  const month = parseInt(m[1], 10);
  const year  = parseInt(m[2], 10);
  if (month < 1 || month > 12) return null;
  // day 0 of the next month = last day of expiry month
  const lastDay = new Date(year, month, 0);
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return Math.floor((lastDay.getTime() - today.getTime()) / 86_400_000);
}
