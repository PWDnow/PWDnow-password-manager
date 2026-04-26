import { Credential } from '../types';
import { Folder } from '../types';
import { generateUUID } from './crypto';

export type ExportFormat = 'pwdnow' | 'bitwarden' | '1password' | 'nordpass';

export interface ImportResult {
  credentials: Credential[];
  detectedFormat: ExportFormat;
}

// ── CSV parser ────────────────────────────────────────────────────────────────

function parseCSV(text: string): string[][] {
  const cleaned = text.startsWith('\uFEFF') ? text.slice(1) : text;
  const rows: string[][] = [];
  const lines = cleaned.split(/\r?\n/);
  for (const line of lines) {
    if (!line.trim()) continue;
    const cols: string[] = [];
    let inQuote = false;
    let cur = '';
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuote && line[i + 1] === '"') { cur += '"'; i++; }
        else { inQuote = !inQuote; }
      } else if (ch === ',' && !inQuote) {
        cols.push(cur); cur = '';
      } else {
        cur += ch;
      }
    }
    cols.push(cur);
    rows.push(cols);
  }
  return rows;
}

function csvEscape(val: string | undefined | null): string {
  const s = val ?? '';
  if (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

// ── OTP helper ────────────────────────────────────────────────────────────────

function extractOtpSecret(uri: string): string | undefined {
  if (!uri) return undefined;
  try {
    const url = new URL(uri);
    return url.searchParams.get('secret') ?? undefined;
  } catch {
    return undefined;
  }
}

function buildOtpUri(service: string, secret: string): string {
  return `otpauth://totp/${encodeURIComponent(service)}?secret=${secret}`;
}

// ── Default values for imported credentials ───────────────────────────────────

function defaults(): Partial<Credential> {
  return { status: 'active', statusColor: '#22c55e', logo: '', folderId: '', tags: [] };
}

// ── Import: Bitwarden JSON ────────────────────────────────────────────────────

export function importBitwarden(text: string): ImportResult {
  const data = JSON.parse(text);
  if (data.encrypted) {
    throw new Error(
      'This Bitwarden export is encrypted. Please export again with "Format: JSON" and encryption disabled.',
    );
  }
  const credentials: Credential[] = [];
  for (const item of (data.items ?? [])) {
    if (item.type !== 1) continue; // 1 = login
    const login = item.login ?? {};
    credentials.push({
      ...defaults(),
      id: generateUUID(),
      service: item.name ?? 'Unknown',
      url: login.uris?.[0]?.uri ?? '',
      username: login.username ?? '',
      password: login.password ?? '',
      otpSecret: login.totp ? extractOtpSecret(login.totp) ?? login.totp : undefined,
    } as Credential);
  }
  return { credentials, detectedFormat: 'bitwarden' };
}

// ── Import: 1Password CSV ─────────────────────────────────────────────────────

export function import1Password(text: string): ImportResult {
  const rows = parseCSV(text);
  if (rows.length < 2) return { credentials: [], detectedFormat: '1password' };
  const headers = rows[0].map(h => h.toLowerCase().trim());
  const idx = {
    title:    headers.findIndex(h => h === 'title'),
    username: headers.findIndex(h => h === 'username'),
    password: headers.findIndex(h => h === 'password'),
    url:      headers.findIndex(h => h === 'url' || h === 'website'),
    otp:      headers.findIndex(h => h === 'otpauth' || h === 'one-time password'),
  };
  const credentials: Credential[] = [];
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    const service = idx.title >= 0 ? row[idx.title]?.trim() : '';
    if (!service) continue;
    credentials.push({
      ...defaults(),
      id: generateUUID(),
      service,
      url:      idx.url >= 0      ? (row[idx.url]      ?? '') : '',
      username: idx.username >= 0 ? (row[idx.username] ?? '') : '',
      password: idx.password >= 0 ? (row[idx.password] ?? '') : '',
      otpSecret: idx.otp >= 0 && row[idx.otp] ? extractOtpSecret(row[idx.otp]) : undefined,
    } as Credential);
  }
  return { credentials, detectedFormat: '1password' };
}

// ── Import: NordPass CSV ──────────────────────────────────────────────────────

export function importNordPass(text: string): ImportResult {
  const rows = parseCSV(text);
  if (rows.length < 2) return { credentials: [], detectedFormat: 'nordpass' };
  const headers = rows[0].map(h => h.toLowerCase().trim());
  const idx = {
    name:     headers.findIndex(h => h === 'name'),
    url:      headers.findIndex(h => h === 'url'),
    username: headers.findIndex(h => h === 'username'),
    password: headers.findIndex(h => h === 'password'),
    type:     headers.findIndex(h => h === 'type'),
  };
  const credentials: Credential[] = [];
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    const type = idx.type >= 0 ? (row[idx.type] ?? '').toLowerCase().trim() : 'login';
    if (type && type !== 'login' && type !== 'password' && type !== '') continue;
    const service = idx.name >= 0 ? row[idx.name]?.trim() : '';
    if (!service) continue;
    credentials.push({
      ...defaults(),
      id: generateUUID(),
      service,
      url:      idx.url >= 0      ? (row[idx.url]      ?? '') : '',
      username: idx.username >= 0 ? (row[idx.username] ?? '') : '',
      password: idx.password >= 0 ? (row[idx.password] ?? '') : '',
    } as Credential);
  }
  return { credentials, detectedFormat: 'nordpass' };
}

// ── Import: PWDnow JSON ───────────────────────────────────────────────────────

export function importPWDnow(text: string): ImportResult {
  const data = JSON.parse(text);
  const raw: unknown[] = Array.isArray(data) ? data : (data.credentials ?? []);
  const credentials: Credential[] = (raw as Credential[]).map(c => ({
    ...defaults(),
    ...c,
    id: generateUUID(), // always fresh IDs to avoid collisions
  }));
  return { credentials, detectedFormat: 'pwdnow' };
}

// ── Auto-detect and import ────────────────────────────────────────────────────

export async function importFromFile(file: File): Promise<ImportResult> {
  const text = await file.text();
  const ext = file.name.split('.').pop()?.toLowerCase();

  if (ext === 'json') {
    let data: Record<string, unknown>;
    try { data = JSON.parse(text); } catch { throw new Error('Invalid JSON file.'); }
    if ('items' in data || 'encrypted' in data) return importBitwarden(text);
    return importPWDnow(text);
  }

  if (ext === 'csv') {
    const firstLine = text.replace(/^\uFEFF/, '').split(/\r?\n/)[0].toLowerCase();
    if (firstLine.includes('title')) return import1Password(text);
    if (firstLine.includes('name') && firstLine.includes('url')) return importNordPass(text);
    // generic CSV — try 1Password column order as fallback
    return import1Password(text);
  }

  throw new Error('Unsupported file type. Please use a .json or .csv file exported from PWDnow, Bitwarden, 1Password, or NordPass.');
}

// ── Export: PWDnow JSON ───────────────────────────────────────────────────────

export function exportToPWDnow(credentials: Credential[], folders: Folder[]): string {
  return JSON.stringify(
    {
      version: 1,
      exported_at: new Date().toISOString(),
      app: 'PWDnow',
      folders,
      credentials,
    },
    null,
    2,
  );
}

// ── Export: Bitwarden JSON ────────────────────────────────────────────────────

export function exportToBitwarden(credentials: Credential[], folders: Folder[]): string {
  const bwFolders = folders.map(f => ({ id: f.id, name: f.label }));
  const folderIds = new Set(folders.map(f => f.id));
  const items = credentials.map(c => ({
    id: generateUUID(),
    organizationId: null,
    folderId: c.folderId && folderIds.has(c.folderId) ? c.folderId : null,
    type: 1,
    name: c.service,
    notes: null,
    favorite: false,
    login: {
      uris: c.url ? [{ match: null, uri: c.url }] : [],
      username: c.username,
      password: c.password ?? '',
      totp: c.otpSecret ? buildOtpUri(c.service, c.otpSecret) : null,
    },
  }));
  return JSON.stringify({ encrypted: false, folders: bwFolders, items }, null, 2);
}

// ── Export: 1Password CSV ─────────────────────────────────────────────────────

export function exportTo1Password(credentials: Credential[]): string {
  const header = 'Title,Username,Password,URL,Notes,OTPAuth';
  const rows = credentials.map(c =>
    [
      csvEscape(c.service),
      csvEscape(c.username),
      csvEscape(c.password),
      csvEscape(c.url),
      '',
      c.otpSecret ? csvEscape(buildOtpUri(c.service, c.otpSecret)) : '',
    ].join(','),
  );
  return [header, ...rows].join('\n');
}

// ── Export: NordPass CSV ──────────────────────────────────────────────────────

export function exportToNordPass(credentials: Credential[]): string {
  const header = 'name,url,username,password,note,cardholder_name,card_number,expiry_date,cvv,notes,type';
  const rows = credentials.map(c =>
    [
      csvEscape(c.service),
      csvEscape(c.url),
      csvEscape(c.username),
      csvEscape(c.password ?? ''),
      '', '', '', '', '', '',
      'login',
    ].join(','),
  );
  return [header, ...rows].join('\n');
}

// ── Download trigger ──────────────────────────────────────────────────────────

export function triggerDownload(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

// ── Format label helpers ──────────────────────────────────────────────────────

export const FORMAT_LABELS: Record<ExportFormat, string> = {
  pwdnow:     'PWDnow (JSON)',
  bitwarden:  'Bitwarden (JSON)',
  '1password':'1Password (CSV)',
  nordpass:   'NordPass (CSV)',
};
