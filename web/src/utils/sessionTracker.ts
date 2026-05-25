import { generateUUID } from './crypto';
import { writeEncryptedLocal, readDecryptedLocal } from './localCrypto';
import { getCsrfToken, apiFetch, hasServerSession } from './api';
import { isBraveBrowser } from './browser';

export interface LoginSession {
  id: string;
  timestamp: number;
  deviceName: string;
  ip: string;
  userAgent: string;
  isCurrent: boolean;
}

const SESSIONS_KEY = 'login_sessions';

function detectOSFromUA(ua: string): string {
  if (/Macintosh|Mac OS X/i.test(ua)) return 'macOS';
  if (/Windows NT 10/i.test(ua)) return 'Windows 10/11';
  if (/Windows/i.test(ua)) return 'Windows';
  if (/iPhone|iPad/i.test(ua)) return 'iOS';
  if (/Android/i.test(ua)) return 'Android';
  if (/Linux/i.test(ua)) return 'Linux';
  return 'Unknown OS';
}

async function detectBrowserFromUA(ua: string): Promise<string> {
  try {
    if (await isBraveBrowser()) {
      return 'Brave';
    }
  } catch { /* ignore */ }
  if (/Vivaldi/i.test(ua)) return 'Vivaldi';
  if (/Edg\//i.test(ua)) return 'Edge';
  if (/OPR\//i.test(ua) || /Opera/i.test(ua)) return 'Opera';
  if (/Chrome\/\d/i.test(ua) && !/Chromium/i.test(ua)) return 'Chrome';
  if (/Firefox\/\d/i.test(ua)) return 'Firefox';
  if (/Safari\/\d/i.test(ua)) return 'Safari';
  return 'Unknown Browser';
}

async function readSessions(): Promise<LoginSession[]> {
  const raw = await readDecryptedLocal(SESSIONS_KEY);
  if (!raw) return [];
  try { return JSON.parse(raw) as LoginSession[]; } catch { return []; }
}

// Returns true only when the server issued a session cookie for this browser.
// The CSRF token cookie (_pwd_csrf) is the non-HttpOnly half of the session pair
// and is the only half readable from JS. Its presence means a valid server-side
// session was established via /api/auth/login or /api/auth/register.
// Daemon-authenticated users never receive this cookie and must use local sessions.

export async function getSessions(): Promise<LoginSession[]> {
  // 1. Try server-side audit log - only when a server session cookie is present.
  //    Skipping this when unauthenticated at the server level avoids spurious 401s
  //    for daemon-mode and legacy localStorage users.
  if (hasServerSession()) {
    try {
      const serverSessions = await apiFetch<LoginSession[]>('/api/auth/sessions');
      if (Array.isArray(serverSessions) && serverSessions.length > 0) {
        return serverSessions.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
      }
    } catch { /* fallback to local */ }
  }

  // 2. Fallback to client-side localStorage sessions
  const sessions = await readSessions();
  return sessions.slice().sort((a, b) => b.timestamp - a.timestamp);
}

export async function recordSession(): Promise<void> {
  const ua = navigator.userAgent;
  const os = detectOSFromUA(ua);
  const browser = await detectBrowserFromUA(ua);
  const deviceName = `${os} - ${browser}`;

  let ip = window.location.hostname;

  // Proxy through our own server to avoid CSP restrictions on external fetches.
  try {
    const data = await apiFetch<{ ip?: string }>('/api/my-ip');
    if (data.ip) ip = data.ip;
  } catch { /* fallback to hostname */ }

  if (!ip || ip === 'localhost' || ip === '::1') ip = '127.0.0.1';

  const existing = await readSessions();
  const trimmed = existing.length > 19 ? existing.slice(existing.length - 19) : existing;
  const updated = trimmed.map(s => ({ ...s, isCurrent: false }));
  updated.push({
    id: generateUUID(),
    timestamp: Date.now(),
    deviceName,
    ip,
    userAgent: ua,
    isCurrent: true,
  });
  await writeEncryptedLocal(SESSIONS_KEY, JSON.stringify(updated));
}

export async function clearOtherSessions(): Promise<void> {
  // Revoke other sessions server-side when a server session is active.
  if (hasServerSession()) {
    try {
      await apiFetch('/api/auth/sessions/revoke-others', { method: 'POST' });
    } catch { /* non-fatal */ }
  }

  const sessions = await readSessions();
  const current = sessions.filter(s => s.isCurrent);
  await writeEncryptedLocal(SESSIONS_KEY, JSON.stringify(current));
}

export function clearAllSessions(): void {
  localStorage.removeItem(SESSIONS_KEY);
}

export function formatSessionTime(timestamp: number): string {
  const diff = Date.now() - timestamp;
  const mins = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);
  if (mins < 1) return 'Active Now';
  if (mins < 60) return `${mins} minute${mins === 1 ? '' : 's'} ago`;
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'} ago`;
  return `${days} day${days === 1 ? '' : 's'} ago`;
}
