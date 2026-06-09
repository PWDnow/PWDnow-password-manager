import type { Credential, Folder } from '../types';
import { generateUUID } from './crypto';
import { exportToP2W, importFromP2W, isP2WFile, readP2WTimestamp } from './p2wFormat';

export { exportToP2W, importFromP2W, isP2WFile, readP2WTimestamp };

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ImportResult {
  credentials: Credential[];
  detectedFormat: string;
}

export interface FormatDef {
  id: string;
  label: string;
  manager: string;       // display name in the dropdown group header
  group: string;         // 'pwdnow' | 'online' | 'offline' | 'browser'
  importExts?: string[]; // accepted file extensions for import
  canImport: boolean;
  canExport: boolean;
  exportExt?: string;
  exportMime?: string;
  exportNote?: string;   // shown below export button
  needsPassphrase?: boolean;
}

export const FORMATS: FormatDef[] = [
  // ── PWDnow ──────────────────────────────────────────────────────────────────
  { id:'pwdnow-p2w',      label:'PWDnow Vault (.p2w)',      manager:'PWDnow', group:'pwdnow', canImport:true, canExport:true, exportExt:'p2w',  exportMime:'application/x-pwdnow-vault', importExts:['p2w'], needsPassphrase:true, exportNote:'Post-quantum AES-256-GCM + XChaCha20 double encryption' },
  { id:'pwdnow-json',     label:'PWDnow JSON',              manager:'PWDnow', group:'pwdnow', canImport:true, canExport:true, exportExt:'json', exportMime:'application/json', importExts:['json'] },
  { id:'pwdnow-json-enc', label:'PWDnow JSON (Legacy Enc)', manager:'PWDnow', group:'pwdnow', canImport:true, canExport:false,                                                 importExts:['json'], exportNote:'Import only - use .p2w for new exports' },
  { id:'pwdnow-csv',      label:'PWDnow CSV',               manager:'PWDnow', group:'pwdnow', canImport:true, canExport:true, exportExt:'csv',  exportMime:'text/csv',         importExts:['csv'] },
  { id:'pwdnow-xml',      label:'PWDnow XML (KeePass)',     manager:'PWDnow', group:'pwdnow', canImport:true, canExport:true, exportExt:'xml',  exportMime:'text/xml',         importExts:['xml'], exportNote:'KeePass-compatible XML' },
  { id:'pwdnow-1pux',     label:'PWDnow 1PUX (1Password)',  manager:'PWDnow', group:'pwdnow', canImport:false, canExport:true, exportExt:'1pux', exportMime:'application/zip',  exportNote:'Importable into 1Password' },
  // ── Online managers ─────────────────────────────────────────────────────────
  { id:'bitwarden-json',  label:'Bitwarden JSON',   manager:'Bitwarden',   group:'online', canImport:true,  canExport:true,  exportExt:'json', exportMime:'application/json', importExts:['json'] },
  { id:'bitwarden-csv',   label:'Bitwarden CSV',    manager:'Bitwarden',   group:'online', canImport:true,  canExport:true,  exportExt:'csv',  exportMime:'text/csv',         importExts:['csv'] },
  { id:'bitwarden-enc',   label:'Bitwarden (.json chiffré)', manager:'Bitwarden', group:'online', canImport:false, canExport:false, exportNote:'Export as unencrypted JSON/CSV first.' },
  { id:'1password-csv',   label:'1Password CSV',    manager:'1Password',   group:'online', canImport:true,  canExport:true,  exportExt:'csv',  exportMime:'text/csv',         importExts:['csv'] },
  { id:'1password-1pux',  label:'1Password 1PUX',   manager:'1Password',   group:'online', canImport:true,  canExport:false,                                                  importExts:['1pux'] },
  { id:'1password-1pif',  label:'1Password v7 (.1pif)', manager:'1Password', group:'online', canImport:false, canExport:false, importExts:['1pif'], exportNote:'Legacy format. Export to CSV from 1Password first.' },
  { id:'1password-agile', label:'1Password v3 (.agilekeychain)', manager:'1Password', group:'online', canImport:false, canExport:false, importExts:['agilekeychain'], exportNote:'Legacy format. Export to CSV first.' },
  { id:'1password-opvault', label:'1Password v4 (.opvault)', manager:'1Password', group:'online', canImport:false, canExport:false, importExts:['opvault'], exportNote:'Legacy format. Export to CSV first.' },
  { id:'keeper-json',     label:'Keeper JSON',      manager:'Keeper',      group:'online', canImport:true,  canExport:true,  exportExt:'json', exportMime:'application/json', importExts:['json'] },
  { id:'keeper-csv',      label:'Keeper CSV',       manager:'Keeper',      group:'online', canImport:true,  canExport:true,  exportExt:'csv',  exportMime:'text/csv',         importExts:['csv'] },
  { id:'dashlane-json',   label:'Dashlane JSON',    manager:'Dashlane',    group:'online', canImport:true,  canExport:true,  exportExt:'json', exportMime:'application/json', importExts:['json'] },
  { id:'dashlane-csv',    label:'Dashlane CSV',     manager:'Dashlane',    group:'online', canImport:true,  canExport:false,                                                  importExts:['csv'] },
  { id:'nordpass-csv',    label:'NordPass CSV',     manager:'NordPass',    group:'online', canImport:true,  canExport:true,  exportExt:'csv',  exportMime:'text/csv',         importExts:['csv'] },
  { id:'lastpass-csv',    label:'LastPass CSV',     manager:'LastPass',    group:'online', canImport:true,  canExport:true,  exportExt:'csv',  exportMime:'text/csv',         importExts:['csv'] },
  { id:'protonpass-json', label:'Proton Pass JSON', manager:'Proton Pass', group:'online', canImport:true,  canExport:true,  exportExt:'json', exportMime:'application/json', importExts:['json'] },
  { id:'zoho-csv',        label:'Zoho Vault CSV',   manager:'Zoho Vault',  group:'online', canImport:true,  canExport:true,  exportExt:'csv',  exportMime:'text/csv',         importExts:['csv'] },
  { id:'passbolt-csv',    label:'Passbolt CSV',     manager:'Passbolt',    group:'online', canImport:true,  canExport:true,  exportExt:'csv',  exportMime:'text/csv',         importExts:['csv'] },
  { id:'padloc-json',     label:'Padloc JSON',      manager:'Padloc',      group:'online', canImport:true,  canExport:true,  exportExt:'json', exportMime:'application/json', importExts:['json'] },
  { id:'passky-json',     label:'Passky JSON',      manager:'Passky',      group:'online', canImport:true,  canExport:true,  exportExt:'json', exportMime:'application/json', importExts:['json'] },
  // ── Offline managers ────────────────────────────────────────────────────────
  { id:'keepass-xml',     label:'KeePass XML',      manager:'KeePass',     group:'offline', canImport:true, canExport:true,  exportExt:'xml',  exportMime:'text/xml',         importExts:['xml'] },
  { id:'keepass-csv',     label:'KeePass CSV',      manager:'KeePass',     group:'offline', canImport:true, canExport:true,  exportExt:'csv',  exportMime:'text/csv',         importExts:['csv'] },
  { id:'keepass-kdbx',    label:'KeePass / KeePassXC (.kdbx)', manager:'KeePass', group:'offline', canImport:true, canExport:true, exportExt:'xml', exportMime:'text/xml', importExts:['kdbx'], needsPassphrase:true, exportNote:'Supported natively. Exporting as KeePass XML.' },
  { id:'keepass-kdb',     label:'KeePass v1 (.kdb)', manager:'KeePass', group:'offline', canImport:false, canExport:true, exportExt:'csv', exportMime:'text/csv', importExts:['kdb'], exportNote:'Legacy format. Exporting as KeePass CSV instead.' },
  { id:'roboform-csv',    label:'RoboForm CSV',     manager:'RoboForm',    group:'offline', canImport:true, canExport:true,  exportExt:'csv',  exportMime:'text/csv',         importExts:['csv'] },
  { id:'roboform-rfp',    label:'RoboForm (.rfp / .rfo)', manager:'RoboForm', group:'offline', canImport:false, canExport:true, exportExt:'csv', exportMime:'text/csv', importExts:['rfp', 'rfo'], exportNote:'Proprietary RoboForm format. Export as CSV from RoboForm first.' },
  { id:'enpass-json',     label:'Enpass JSON',      manager:'Enpass',      group:'offline', canImport:true, canExport:false,                                                  importExts:['json'] },
  { id:'enpass-csv',      label:'Enpass CSV',       manager:'Enpass',      group:'offline', canImport:true, canExport:true,  exportExt:'csv',  exportMime:'text/csv',         importExts:['csv'] },
  { id:'enpass-enpassdb', label:'Enpass (.enpassdb)', manager:'Enpass',    group:'offline', canImport:false, canExport:true, exportExt:'csv', exportMime:'text/csv', importExts:['enpassdb'], exportNote:'SQLCipher encrypted. Exporting as Enpass CSV instead.' },
  { id:'enpass-epb',      label:'Enpass Encrypted Backup (.epb)', manager:'Enpass', group:'offline', canImport:false, canExport:false, importExts:['epb'], exportNote:'Enpass encrypted backup. Decrypt in Enpass first, then export as JSON or CSV.' },
  { id:'buttercup-json',  label:'Buttercup JSON',   manager:'Buttercup',   group:'offline', canImport:true, canExport:true,  exportExt:'json', exportMime:'application/json', importExts:['json'], exportNote:'Unzip .bcup before importing' },
  { id:'buttercup-bcup',  label:'Buttercup (.bcup)', manager:'Buttercup',  group:'offline', canImport:false, canExport:false, importExts:['bcup'], exportNote:'Encrypted Buttercup vault. Open in Buttercup, export as unencrypted JSON first.' },
  { id:'passwordsafe-csv',label:'Password Safe CSV', manager:'Password Safe', group:'offline', canImport:true, canExport:true, exportExt:'csv', exportMime:'text/csv', importExts:['csv'] },
  { id:'passwordsafe-psafe3',label:'Password Safe (.psafe3)', manager:'Password Safe', group:'offline', canImport:false, canExport:true, exportExt:'csv', exportMime:'text/csv', importExts:['psafe3'], exportNote:'Exporting as Password Safe CSV instead.' },
  { id:'passwordsafe-dat',label:'Password Safe v2 (.dat)', manager:'Password Safe', group:'offline', canImport:false, canExport:true, exportExt:'csv', exportMime:'text/csv', importExts:['dat'], exportNote:'Legacy format. Exporting as Password Safe CSV instead.' },
  { id:'stickypassword-xml',label:'Sticky Password XML', manager:'Sticky Password', group:'offline', canImport:true, canExport:true, exportExt:'xml', exportMime:'text/xml', importExts:['xml'] },
  { id:'stickypassword-spdb',label:'Sticky Password (.spdb)', manager:'Sticky Password', group:'offline', canImport:false, canExport:true, exportExt:'xml', exportMime:'text/xml', importExts:['spdb'], exportNote:'Exporting as Sticky Password XML instead.' },
  { id:'msecure-csv',     label:'mSecure CSV',      manager:'mSecure',     group:'offline', canImport:true,  canExport:false,                                                  importExts:['csv'] },
  { id:'safeincloud-xml', label:'SafeInCloud XML',  manager:'SafeInCloud', group:'offline', canImport:true,  canExport:false,                                                  importExts:['xml'] },
  { id:'norton-csv',      label:'Norton Password Mgr CSV', manager:'Norton Password Mgr', group:'online', canImport:true, canExport:true, exportExt:'csv', exportMime:'text/csv', importExts:['csv'] },
  { id:'truekey-csv',     label:'True Key CSV',     manager:'True Key',    group:'online',  canImport:true,  canExport:false,                                                  importExts:['csv'] },
  // ── Browsers ─────────────────────────────────────────────────────────────────
  { id:'chrome-csv',      label:'Chrome / Edge CSV',     manager:'Google Chrome', group:'browser', canImport:true, canExport:true, exportExt:'csv', exportMime:'text/csv', importExts:['csv'] },
  { id:'firefox-csv',     label:'Firefox CSV',            manager:'Firefox',       group:'browser', canImport:true, canExport:true, exportExt:'csv', exportMime:'text/csv', importExts:['csv'] },
  { id:'safari-csv',      label:'Safari / iCloud CSV',   manager:'Safari',        group:'browser', canImport:true, canExport:false,                                       importExts:['csv'] },
];

export const FORMAT_GROUPS: Record<string, string> = {
  pwdnow:  'PWDnow',
  online:  'Online Password Managers',
  offline: 'Offline Password Managers',
  browser: 'Browsers',
};

export function getFormat(id: string): FormatDef | undefined {
  return FORMATS.find(f => f.id === id);
}

// ── Low-level utilities ───────────────────────────────────────────────────────

function parseCSV(text: string): string[][] {
  const cleaned = text.startsWith('﻿') ? text.slice(1) : text;
  const rows: string[][] = [];
  for (const line of cleaned.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const cols: string[] = [];
    let inQuote = false, cur = '';
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuote && line[i + 1] === '"') { cur += '"'; i++; }
        else inQuote = !inQuote;
      } else if (ch === ',' && !inQuote) { cols.push(cur); cur = ''; }
      else cur += ch;
    }
    cols.push(cur);
    rows.push(cols);
  }
  return rows;
}

function csvEscape(val: string | undefined | null): string {
  const s = val ?? '';
  if (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r'))
    return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

function xmlEscape(s: string): string {
  return (s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function extractOtpSecret(uri: string): string | undefined {
  if (!uri) return undefined;
  try { return new URL(uri).searchParams.get('secret') ?? undefined; } catch { return undefined; }
}

function buildOtpUri(service: string, secret: string): string {
  return `otpauth://totp/${encodeURIComponent(service)}?secret=${secret}&digits=6&period=30`;
}

function defaults(): Partial<Credential> {
  return { status: 'active', statusColor: '#22c55e', logo: '', folderId: '', tags: [] };
}

// ── Generic CSV importer with column auto-mapping ─────────────────────────────

interface ColMap {
  title?: string | string[];
  url?: string | string[];
  username?: string | string[];
  password?: string | string[];
  notes?: string | string[];
  otp?: string | string[];
  folder?: string | string[];
}

function findCol(headers: string[], names: string | string[]): number {
  const ns = Array.isArray(names) ? names : [names];
  for (const n of ns) {
    const i = headers.findIndex(h => h === n.toLowerCase());
    if (i >= 0) return i;
  }
  return -1;
}

function csvImport(text: string, map: ColMap, formatId: string, typeFilter?: string): ImportResult {
  const rows = parseCSV(text);
  if (rows.length < 2) return { credentials: [], detectedFormat: formatId };
  const headers = rows[0].map(h => h.toLowerCase().trim());
  const ti  = findCol(headers, map.title    ?? ['title','name','account','label']);
  const ui  = findCol(headers, map.url      ?? ['url','website','web site','login_uri','uri']);
  const uni = findCol(headers, map.username ?? ['username','login','login name','user name','email','login_username']);
  const pi  = findCol(headers, map.password ?? ['password','pwd','login_password']);
  const ni  = findCol(headers, map.notes    ?? ['notes','note','extra','comment','comments']);
  const oi  = findCol(headers, map.otp      ?? ['totp','otpauth','otp','two-factor','login_totp']);
  const fi  = findCol(headers, map.folder   ?? ['folder','group','grouping','category']);

  const credentials: Credential[] = [];
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    if (typeFilter) {
      const typeIdx = headers.indexOf('type');
      if (typeIdx >= 0 && row[typeIdx] && row[typeIdx].toLowerCase() !== typeFilter) continue;
    }
    const title = ti >= 0 ? row[ti]?.trim() : '';
    if (!title && uni < 0 && pi < 0) continue;
    const otpRaw = oi >= 0 ? (row[oi] ?? '') : '';
    credentials.push({
      ...defaults(),
      id:        generateUUID(),
      service:   title || 'Untitled',
      url:       ui  >= 0 ? (row[ui]  ?? '') : '',
      username:  uni >= 0 ? (row[uni] ?? '') : '',
      password:  pi  >= 0 ? (row[pi]  ?? '') : '',
      description: ni >= 0 ? (row[ni] ?? '') : undefined,
      folderId:  '',
      otpSecret: otpRaw ? (extractOtpSecret(otpRaw) ?? otpRaw) : undefined,
      tags:      fi >= 0 && row[fi] ? [row[fi]] : [],
    } as Credential);
  }
  return { credentials, detectedFormat: formatId };
}

// ── Importers ─────────────────────────────────────────────────────────────────

export function importChrome(text: string): ImportResult {
  return csvImport(text, { title:['name'], url:['url'], username:['username'], password:['password'], notes:['note'] }, 'chrome-csv');
}

export function importFirefox(text: string): ImportResult {
  return csvImport(text, { url:['url'], username:['username'], password:['password'], notes:['httprealm'] }, 'firefox-csv');
}

export function importSafari(text: string): ImportResult {
  return csvImport(text, { title:['title','name'], url:['url','website'], username:['username'], password:['password'] }, 'safari-csv');
}

export function importLastPass(text: string): ImportResult {
  return csvImport(text, { title:'name', url:'url', username:'username', password:'password', notes:['extra','notes'], otp:'totp', folder:'grouping' }, 'lastpass-csv');
}

export function import1PasswordCSV(text: string): ImportResult {
  return csvImport(text, { title:'title', url:'url', username:'username', password:'password', notes:'notes', otp:'otpauth' }, '1password-csv');
}

export function import1PUX(text: string): ImportResult {
  const data = JSON.parse(text) as Record<string, unknown>;
  const credentials: Credential[] = [];
  const accounts = (data['accounts'] ?? []) as unknown[];
  for (const acct of accounts) {
    const vaults = ((acct as Record<string, unknown>)['vaults'] ?? []) as unknown[];
    for (const vault of vaults) {
      const items = ((vault as Record<string, unknown>)['items'] ?? []) as unknown[];
      for (const item of items) {
        const it = item as Record<string, unknown>;
        if ((it['state'] as string) === 'archived') continue;
        const overview = (it['overview'] ?? {}) as Record<string, unknown>;
        const details  = (it['details']  ?? {}) as Record<string, unknown>;
        const fields   = (details['loginFields'] ?? []) as Array<Record<string, unknown>>;
        let username = '', password = '';
        for (const f of fields) {
          if (f['designation'] === 'username') username = String(f['value'] ?? '');
          if (f['designation'] === 'password') password = String(f['value'] ?? '');
        }
        const urls = (overview['urls'] ?? []) as Array<Record<string, unknown>>;
        credentials.push({
          ...defaults(),
          id:       generateUUID(),
          service:  String(overview['title'] ?? 'Untitled'),
          url:      urls[0] ? String(urls[0]['u'] ?? '') : String(overview['url'] ?? ''),
          username,
          password,
          description: String(details['notes'] ?? '') || undefined,
        } as Credential);
      }
    }
  }
  return { credentials, detectedFormat: '1password-1pux' };
}

export function importBitwardenJSON(text: string): ImportResult {
  const data = JSON.parse(text) as Record<string, unknown>;
  if (data['encrypted']) throw new Error('Encrypted Bitwarden exports are not supported. Re-export without encryption.');
  const credentials: Credential[] = [];
  for (const item of ((data['items'] ?? []) as Array<Record<string, unknown>>)) {
    if (item['type'] !== 1) continue;
    const login = (item['login'] ?? {}) as Record<string, unknown>;
    const uris  = (login['uris'] ?? []) as Array<Record<string, unknown>>;
    const otpRaw = String(login['totp'] ?? '');
    credentials.push({
      ...defaults(),
      id:       generateUUID(),
      service:  String(item['name'] ?? 'Untitled'),
      url:      uris[0] ? String(uris[0]['uri'] ?? '') : '',
      username: String(login['username'] ?? ''),
      password: String(login['password'] ?? ''),
      description: String(item['notes'] ?? '') || undefined,
      otpSecret: otpRaw ? (extractOtpSecret(otpRaw) ?? otpRaw) : undefined,
    } as Credential);
  }
  return { credentials, detectedFormat: 'bitwarden-json' };
}

export function importBitwardenCSV(text: string): ImportResult {
  // deepcode ignore NoHardcodedPasswords: This is a CSV header mapping, not a hardcoded credential
  return csvImport(text, {
    title:'name', url:'login_uri', username:'login_username',
    password:'login_password', notes:'notes', otp:'login_totp', folder:'folder',
  }, 'bitwarden-csv', 'login');
}

export function importNordPass(text: string): ImportResult {
  return csvImport(text, { title:'name', url:'url', username:'username', password:'password', notes:['note','notes'] }, 'nordpass-csv', 'login');
}

// Portable KeePass XML parser - no DOMParser, works in Node.js and browsers.
function xmlInnerText(block: string, tag: string): string {
  const re = new RegExp('<' + tag + '(?:[^>]*)>([\\s\\S]*?)</' + tag + '>', 'i');
  const m = block.match(re);
  return m ? m[1].replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&apos;/g,"'") : '';
}

export function importKeePassXML(text: string): ImportResult {
  const credentials: Credential[] = [];
  for (const em of text.matchAll(/<Entry>([\s\S]*?)<\/Entry>/gi)) {
    const entry = em[1];
    const kvMap: Record<string, string> = {};
    for (const sm of entry.matchAll(/<String>([\s\S]*?)<\/String>/gi)) {
      const key = xmlInnerText(sm[1], 'Key');
      const val = xmlInnerText(sm[1], 'Value');
      if (key) kvMap[key] = val;
    }
    const title = kvMap['Title'] ?? '';
    if (!title) continue;
    const otpRaw = kvMap['otp'] ?? kvMap['TOTP Seed'] ?? kvMap['TimeOtp-Secret-Base32'] ?? '';
    credentials.push({
      ...defaults(),
      id:       generateUUID(),
      service:  title,
      url:      kvMap['URL'] ?? '',
      username: kvMap['UserName'] ?? '',
      password: kvMap['Password'] ?? '',
      description: kvMap['Notes'] || undefined,
      otpSecret: otpRaw ? (extractOtpSecret(otpRaw) ?? otpRaw) : undefined,
    } as Credential);
  }
  return { credentials, detectedFormat: 'keepass-xml' };
}

export function importKeePassCSV(text: string): ImportResult {
  return csvImport(text, { title:['account','title','name'], url:['web site','url'], username:['login name','username'], password:'password', notes:'comments' }, 'keepass-csv');
}

export function importKeeperJSON(text: string): ImportResult {
  const data = JSON.parse(text) as Record<string, unknown>;
  const records = ((data['records'] ?? []) as Array<Record<string, unknown>>);
  const allRecords = [...records];
  for (const sf of ((data['shared_folders'] ?? []) as Array<Record<string, unknown>>)) {
    allRecords.push(...((sf['records'] ?? []) as Array<Record<string, unknown>>));
  }
  return {
    detectedFormat: 'keeper-json',
    credentials: allRecords.map(r => ({
      ...defaults(),
      id:       generateUUID(),
      service:  String(r['title'] ?? 'Untitled'),
      url:      String(r['login_url'] ?? r['url'] ?? ''),
      username: String(r['login'] ?? r['username'] ?? ''),
      password: String(r['password'] ?? ''),
      description: String(r['notes'] ?? '') || undefined,
      otpSecret: r['totp'] ? String(r['totp']) : undefined,
    } as Credential)),
  };
}

export function importKeeperCSV(text: string): ImportResult {
  return csvImport(text, { folder:'folder', title:'title', username:['login','username'], password:'password', url:'website', notes:'notes', otp:['two-factor','otp secret'] }, 'keeper-csv');
}

export function importDashlaneJSON(text: string): ImportResult {
  const data = JSON.parse(text) as Record<string, unknown>;
  const items = (data['credentials'] ?? data['AUTHENTIFIANT'] ?? []) as Array<Record<string, unknown>>;
  return {
    detectedFormat: 'dashlane-json',
    credentials: items.map(r => ({
      ...defaults(),
      id:       generateUUID(),
      service:  String(r['title'] ?? r['name'] ?? 'Untitled'),
      url:      String(r['url'] ?? r['domain'] ?? ''),
      username: String(r['login'] ?? r['email'] ?? r['username'] ?? ''),
      password: String(r['password'] ?? ''),
      description: String(r['note'] ?? '') || undefined,
      otpSecret: r['otpSecret'] ? String(r['otpSecret']) : undefined,
    } as Credential)),
  };
}

export function importDashlaneCSV(text: string): ImportResult {
  return csvImport(text, { title:['name','title'], url:['url','domain'], username:['login','email','username'], password:'password', notes:'note' }, 'dashlane-csv');
}

export function importRoboForm(text: string): ImportResult {
  return csvImport(text, { title:'name', url:'url', username:['login','username'], password:['pwd','password'], notes:'note', folder:'folder' }, 'roboform-csv');
}

export function importMSecure(text: string): ImportResult {
  // mSecure v3/4: Account Type, Description, Notes, Username, Password, Email, Website, 2FA Key
  // mSecure v5+:  Type, Description, Notes, Username, Password, Email, Website, OTP
  return csvImport(text, {
    title:    ['description', 'title', 'name'],
    url:      ['website', 'url', 'web'],
    username: ['username', 'login', 'email'],
    password: 'password',
    notes:    ['notes', 'note'],
    otp:      ['2fa key', 'otp', 'totp'],
    folder:   ['account type', 'type', 'group', 'category'],
  }, 'msecure-csv');
}

export function importSafeInCloud(text: string): ImportResult {
  // SafeInCloud XML: <database> root, <card title="…"> children, <field name="Login"> etc.
  const credentials: Credential[] = [];
  for (const cm of text.matchAll(/<card\b([^>]*)>([\s\S]*?)<\/card>/gi)) {
    const attrStr = cm[1];
    const body    = cm[2];
    const titleAttr = attrStr.match(/\btitle="([^"]*)"/i);
    const title = titleAttr ? titleAttr[1] : xmlInnerText(body, 'name');
    if (!title) continue;
    const fields: Record<string, string> = {};
    for (const fm of body.matchAll(/<field\b[^>]*\bname="([^"]*)"[^>]*>\s*<value>([\s\S]*?)<\/value>/gi)) {
      fields[fm[1].toLowerCase()] = fm[2];
    }
    const username = fields['login'] ?? fields['username'] ?? fields['email'] ?? fields['user name'] ?? '';
    const password = fields['password'] ?? '';
    if (!username && !password) continue;
    const url    = fields['website'] ?? fields['url'] ?? fields['web site'] ?? '';
    const otp    = fields['one-time password'] ?? fields['totp'] ?? fields['2fa key'] ?? '';
    const notes  = xmlInnerText(body, 'notes');
    credentials.push({
      ...defaults(),
      id:          generateUUID(),
      service:     title,
      url,
      username,
      password,
      description: notes || undefined,
      otpSecret:   otp ? (extractOtpSecret(otp) ?? otp) : undefined,
    } as Credential);
  }
  return { credentials, detectedFormat: 'safeincloud-xml' };
}

export function importTrueKey(text: string): ImportResult {
  // True Key CSV: kind, name, url, username, password, extra, two_factor, totp, autologin, breach
  // Filter to kind='login' rows only.
  const rows = parseCSV(text);
  if (rows.length < 2) return { credentials: [], detectedFormat: 'truekey-csv' };
  const headers = rows[0].map(h => h.toLowerCase().trim());
  const ki  = headers.indexOf('kind');
  const ti  = headers.indexOf('name');
  const ui  = headers.indexOf('url');
  const uni = headers.indexOf('username');
  const pi  = headers.indexOf('password');
  const ni  = headers.indexOf('extra');
  const oi  = headers.indexOf('totp');
  const credentials: Credential[] = [];
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    if (ki >= 0 && row[ki] && row[ki].toLowerCase() !== 'login') continue;
    const title = ti >= 0 ? (row[ti] ?? '').trim() : '';
    if (!title) continue;
    const otpRaw = oi >= 0 ? (row[oi] ?? '') : '';
    credentials.push({
      ...defaults(),
      id:          generateUUID(),
      service:     title || 'Untitled',
      url:         ui  >= 0 ? (row[ui]  ?? '') : '',
      username:    uni >= 0 ? (row[uni] ?? '') : '',
      password:    pi  >= 0 ? (row[pi]  ?? '') : '',
      description: ni  >= 0 ? (row[ni]  ?? '') || undefined : undefined,
      otpSecret:   otpRaw ? (extractOtpSecret(otpRaw) ?? otpRaw) : undefined,
    } as Credential);
  }
  return { credentials, detectedFormat: 'truekey-csv' };
}

export function importProtonPass(text: string): ImportResult {
  const data = JSON.parse(text) as Record<string, unknown>;
  const credentials: Credential[] = [];
  const vaults = (data['vaults'] ?? {}) as Record<string, unknown>;
  for (const vault of Object.values(vaults)) {
    const items = ((vault as Record<string, unknown>)['items'] ?? []) as Array<Record<string, unknown>>;
    for (const item of items) {
      const d   = (item['data'] ?? {}) as Record<string, unknown>;
      const con = (d['content'] ?? {}) as Record<string, unknown>;
      const met = (d['metadata'] ?? {}) as Record<string, unknown>;
      if (d['type'] !== 'login') continue;
      const urls = (con['urls'] ?? []) as string[];
      const otpRaw = String(con['totp_uri'] ?? '');
      credentials.push({
        ...defaults(),
        id:       generateUUID(),
        service:  String(met['name'] ?? 'Untitled'),
        url:      urls[0] ?? '',
        username: String(con['username'] ?? ''),
        password: String(con['password'] ?? ''),
        description: String(met['note'] ?? '') || undefined,
        otpSecret: otpRaw ? (extractOtpSecret(otpRaw) ?? otpRaw) : undefined,
      } as Credential);
    }
  }
  return { credentials, detectedFormat: 'protonpass-json' };
}

export function importZoho(text: string): ImportResult {
  return csvImport(text, { title:['secret name','title','name'], url:['url','website'], username:['account name','username','user name'], password:'password', notes:['comments','notes'] }, 'zoho-csv');
}

export function importPassbolt(text: string): ImportResult {
  return csvImport(text, { title:'title', url:'url', username:'username', password:'password', notes:['description','note'] }, 'passbolt-csv');
}

export function importPadloc(text: string): ImportResult {
  const data = JSON.parse(text) as Record<string, unknown>;
  const credentials: Credential[] = [];
  const vaults = (data['vaults'] ?? []) as Array<Record<string, unknown>>;
  for (const vault of vaults) {
    const items = (vault['items'] ?? []) as Array<Record<string, unknown>>;
    for (const item of items) {
      const fields = (item['fields'] ?? []) as Array<Record<string, unknown>>;
      let username = '', password = '', url = '', otp = '';
      for (const f of fields) {
        const name = String(f['name'] ?? '').toLowerCase();
        const val  = String(f['value'] ?? '');
        if (name === 'username' || name === 'email') username = val;
        else if (name === 'password') password = val;
        else if (name === 'url' || name === 'website') url = val;
        else if (name === 'otp' || name === 'totp') otp = val;
      }
      credentials.push({
        ...defaults(),
        id:       generateUUID(),
        service:  String(item['name'] ?? 'Untitled'),
        url, username, password,
        otpSecret: otp ? (extractOtpSecret(otp) ?? otp) : undefined,
      } as Credential);
    }
  }
  return { credentials, detectedFormat: 'padloc-json' };
}

export function importPassky(text: string): ImportResult {
  const data = JSON.parse(text) as Record<string, unknown>;
  const passwords = (data['passwords'] ?? []) as Array<Record<string, unknown>>;
  return {
    detectedFormat: 'passky-json',
    credentials: passwords.map(r => ({
      ...defaults(),
      id:       generateUUID(),
      service:  String(r['website'] ?? r['name'] ?? 'Untitled'),
      url:      String(r['website'] ?? ''),
      username: String(r['username'] ?? ''),
      password: String(r['password'] ?? ''),
      description: String(r['note'] ?? r['message'] ?? '') || undefined,
    } as Credential)),
  };
}

export function importEnpassJSON(text: string): ImportResult {
  const data = JSON.parse(text) as Record<string, unknown>;
  const items = (data['items'] ?? []) as Array<Record<string, unknown>>;
  const credentials: Credential[] = [];
  for (const item of items) {
    if (!['login','password'].includes(String(item['category'] ?? '').toLowerCase())) {
      if (!(item['category'] ?? '')) continue;
    }
    const fields = (item['fields'] ?? []) as Array<Record<string, unknown>>;
    let username = '', password = '', url = '', otp = '';
    for (const f of fields) {
      const lbl = String(f['label'] ?? '').toLowerCase();
      const val = String(f['value'] ?? '');
      if (lbl === 'username' || lbl === 'email' || lbl === 'login') username ||= val;
      else if (lbl === 'password') password ||= val;
      else if (lbl === 'url' || lbl === 'website') url ||= val;
      else if (lbl === 'one-time password' || lbl === 'totp') otp ||= val;
    }
    const urls = (item['login_urls'] ?? []) as Array<Record<string, unknown>>;
    credentials.push({
      ...defaults(),
      id:       generateUUID(),
      service:  String(item['title'] ?? 'Untitled'),
      url:      url || (urls[0] ? String(urls[0]['url'] ?? '') : ''),
      username, password,
      otpSecret: otp ? (extractOtpSecret(otp) ?? otp) : undefined,
    } as Credential);
  }
  return { credentials, detectedFormat: 'enpass-json' };
}

export function importEnpassCSV(text: string): ImportResult {
  return csvImport(text, { title:'title', url:['url','website'], username:['username','email','login'], password:'password', notes:'notes', otp:['one-time password','totp'] }, 'enpass-csv');
}

export function importButtercup(text: string): ImportResult {
  const data = JSON.parse(text) as Record<string, unknown>;
  const credentials: Credential[] = [];
  const groups = (data['groups'] ?? data['root'] ? [(data as Record<string, unknown>)] : []) as Array<Record<string, unknown>>;

  function processGroup(g: Record<string, unknown>) {
    for (const entry of ((g['entries'] ?? g['items'] ?? []) as Array<Record<string, unknown>>)) {
      const props = (entry['properties'] ?? entry) as Record<string, unknown>;
      credentials.push({
        ...defaults(),
        id:       generateUUID(),
        service:  String(props['title'] ?? entry['name'] ?? 'Untitled'),
        url:      String(props['URL'] ?? props['url'] ?? ''),
        username: String(props['username'] ?? ''),
        password: String(props['password'] ?? ''),
      } as Credential);
    }
    for (const sub of ((g['groups'] ?? g['children'] ?? []) as Array<Record<string, unknown>>)) {
      processGroup(sub);
    }
  }

  const root = (data['root'] ?? data) as Record<string, unknown>;
  processGroup(root);
  return { credentials, detectedFormat: 'buttercup-json' };
}

export function importPWDnow(text: string): ImportResult {
  const data = JSON.parse(text);
  const raw: unknown[] = Array.isArray(data) ? data : (data.credentials ?? []);
  return {
    detectedFormat: 'pwdnow-json',
    credentials: (raw as Credential[]).map(c => ({ ...defaults(), ...c, id: generateUUID() })),
  };
}

export function importPWDnowCSV(text: string): ImportResult {
  return csvImport(text, { title:'name', url:'url', username:'username', password:'password', notes:'notes', otp:'otp_secret', folder:'folder' }, 'pwdnow-csv');
}

export function importPWDnowXML(text: string): ImportResult {
  return importKeePassXML(text);
}

// ── Exporters ─────────────────────────────────────────────────────────────────

// ── PWDnow ────────────────────────────────────────────────────────────────────

function buildPWDnowPayload(credentials: Credential[], folders: Folder[]): string {
  return JSON.stringify({ version: 1, exported_at: new Date().toISOString(), app: 'PWDnow', folders, credentials }, null, 2);
}

export function exportToPWDnow(credentials: Credential[], folders: Folder[]): string {
  return buildPWDnowPayload(credentials, folders);
}

export async function exportToPWDnowEncrypted(credentials: Credential[], folders: Folder[], passphrase: string): Promise<string> {
  const plaintext = buildPWDnowPayload(credentials, folders);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const toHex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');

  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key  = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600_000 },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt'],
  );
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext)));
  return JSON.stringify({ encrypted: true, app: 'PWDnow', kdf: 'pbkdf2-sha256', iterations: 600_000, salt: toHex(salt), iv: toHex(iv), ciphertext: btoa(String.fromCharCode(...ct)) }, null, 2);
}

export function isEncryptedPWDnow(text: string): boolean {
  try { return JSON.parse(text)?.encrypted === true && JSON.parse(text)?.app === 'PWDnow'; } catch { return false; }
}

export async function decryptPWDnowExport(text: string, passphrase: string): Promise<string> {
  const d = JSON.parse(text) as Record<string, unknown>;
  const fromHex = (h: string) => Uint8Array.from((h as string).match(/../g)!.map(x => parseInt(x, 16)));
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key  = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(d.salt as string), iterations: (d.iterations as number) ?? 600_000 },
    base, { name: 'AES-GCM', length: 256 }, false, ['decrypt'],
  );
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromHex(d.iv as string) }, key, Uint8Array.from(atob(d.ciphertext as string), c => c.charCodeAt(0)));
  return new TextDecoder().decode(plain);
}

export function exportToPWDnowCSV(credentials: Credential[]): string {
  const header = 'name,url,username,password,notes,otp_secret,folder';
  const rows = credentials.map(c =>
    [csvEscape(c.service), csvEscape(c.url), csvEscape(c.username), csvEscape(c.password), csvEscape(c.description), csvEscape(c.otpSecret), csvEscape(c.folderId)].join(','),
  );
  return [header, ...rows].join('\n');
}

function buildKeePassXML(credentials: Credential[], folders: Folder[]): string {
  const folderMap = new Map(folders.map(f => [f.id, f.label]));
  const entries = credentials.map(c => {
    const otp = c.otpSecret ? buildOtpUri(c.service, c.otpSecret) : '';
    return `    <Entry>
      <String><Key>Title</Key><Value>${xmlEscape(c.service)}</Value></String>
      <String><Key>UserName</Key><Value>${xmlEscape(c.username)}</Value></String>
      <String><Key>Password</Key><Value ProtectInMemory="True">${xmlEscape(c.password ?? '')}</Value></String>
      <String><Key>URL</Key><Value>${xmlEscape(c.url)}</Value></String>
      <String><Key>Notes</Key><Value>${xmlEscape(c.description ?? '')}</Value></String>${otp ? `
      <String><Key>otp</Key><Value>${xmlEscape(otp)}</Value></String>` : ''}
      <Tags>${xmlEscape(c.folderId ? (folderMap.get(c.folderId) ?? '') : '')}</Tags>
    </Entry>`;
  });
  return `<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
  <Meta>
    <Generator>PWDnow</Generator>
    <DatabaseName>PWDnow Export</DatabaseName>
    <DatabaseNameChanged>${new Date().toISOString()}</DatabaseNameChanged>
  </Meta>
  <Root>
    <Group>
      <Name>PWDnow</Name>
${entries.join('\n')}
    </Group>
  </Root>
</KeePassFile>`;
}

export function exportToPWDnowXML(credentials: Credential[], folders: Folder[]): string {
  return buildKeePassXML(credentials, folders);
}

// Minimal CRC-32 (PKZIP polynomial) for the 1PUX ZIP wrapper
function crc32(data: Uint8Array): number {
  let c = 0xFFFFFFFF;
  for (const b of data) { c ^= b; for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xEDB88320 : c >>> 1; }
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function writeU16LE(v: DataView, offset: number, n: number) { v.setUint16(offset, n, true); }
function writeU32LE(v: DataView, offset: number, n: number) { v.setUint32(offset, n, true); }

function createSingleFileZip(filename: string, content: Uint8Array): Uint8Array {
  const enc = new TextEncoder();
  const nameBytes = enc.encode(filename);
  const crc = crc32(content);
  const now = new Date();
  const dosDate = ((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate();
  const dosTime = (now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1);

  // Local file header (30 bytes + name)
  const lfh = new Uint8Array(30 + nameBytes.length);
  const lfv = new DataView(lfh.buffer);
  writeU32LE(lfv,  0, 0x04034B50); writeU16LE(lfv,  4, 20); writeU16LE(lfv, 6, 0);
  writeU16LE(lfv,  8, 0);          writeU16LE(lfv, 10, dosTime); writeU16LE(lfv, 12, dosDate);
  writeU32LE(lfv, 14, crc);        writeU32LE(lfv, 18, content.length); writeU32LE(lfv, 22, content.length);
  writeU16LE(lfv, 26, nameBytes.length); writeU16LE(lfv, 28, 0);
  lfh.set(nameBytes, 30);

  const cdOffset = lfh.length + content.length;

  // Central directory header (46 bytes + name)
  const cd = new Uint8Array(46 + nameBytes.length);
  const cdv = new DataView(cd.buffer);
  writeU32LE(cdv,  0, 0x02014B50); writeU16LE(cdv,  4, 20); writeU16LE(cdv,  6, 20);
  writeU16LE(cdv,  8, 0);          writeU16LE(cdv, 10, 0);  writeU16LE(cdv, 12, dosTime);
  writeU16LE(cdv, 14, dosDate);    writeU32LE(cdv, 16, crc); writeU32LE(cdv, 20, content.length);
  writeU32LE(cdv, 24, content.length); writeU16LE(cdv, 28, nameBytes.length); writeU16LE(cdv, 30, 0);
  writeU16LE(cdv, 32, 0);          writeU16LE(cdv, 34, 0);  writeU16LE(cdv, 36, 0);
  writeU32LE(cdv, 38, 0x20);       writeU32LE(cdv, 42, 0);
  cd.set(nameBytes, 46);

  // End of central directory
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  writeU32LE(ev,  0, 0x06054B50); writeU16LE(ev,  4, 0);   writeU16LE(ev,  6, 0);
  writeU16LE(ev,  8, 1);          writeU16LE(ev, 10, 1);   writeU32LE(ev, 12, cd.length);
  writeU32LE(ev, 16, cdOffset);   writeU16LE(ev, 20, 0);

  const out = new Uint8Array(cdOffset + cd.length + eocd.length);
  out.set(lfh, 0); out.set(content, lfh.length); out.set(cd, cdOffset); out.set(eocd, cdOffset + cd.length);
  return out;
}

export function exportToPWDnow1PUX(credentials: Credential[], folders: Folder[]): Uint8Array {
  const folderMap = new Map(folders.map(f => [f.id, f.label]));
  const items = credentials.map(c => ({
    uuid: generateUUID().replace(/-/g, ''),
    favIndex: 0,
    createdAt: Math.floor(Date.now() / 1000),
    updatedAt: Math.floor(Date.now() / 1000),
    state: 'active',
    categoryUuid: '001',
    details: {
      loginFields: [
        { designation: 'username', name: 'username', type: 'T', value: c.username },
        { designation: 'password', name: 'password', type: 'P', value: c.password ?? '' },
      ],
      notes: c.description ?? '',
      sections: c.otpSecret ? [{ title: 'OTP', fields: [{ k: 'concealed', n: 'totp', t: 'one-time password', v: buildOtpUri(c.service, c.otpSecret) }] }] : [],
    },
    overview: {
      ainfo: c.username,
      title: c.service,
      url: c.url,
      urls: c.url ? [{ l: 'website', u: c.url }] : [],
      tags: c.folderId ? [folderMap.get(c.folderId) ?? ''] : [],
    },
  }));

  const exportData = {
    accounts: [{
      attrs: { accountName: 'PWDnow Export', name: 'PWDnow' },
      vaults: [{ attrs: { desc: '', name: 'PWDnow Vault', type: 'P' }, items }],
    }],
  };

  const json = new TextEncoder().encode(JSON.stringify(exportData, null, 2));
  return createSingleFileZip('export.data', json);
}

// ── Third-party exporters ─────────────────────────────────────────────────────

export function exportToBitwardenJSON(credentials: Credential[], folders: Folder[]): string {
  const bwFolders = folders.map(f => ({ id: f.id, name: f.label }));
  const folderIds = new Set(folders.map(f => f.id));
  const items = credentials.map(c => ({
    id: generateUUID(), organizationId: null,
    folderId: c.folderId && folderIds.has(c.folderId) ? c.folderId : null,
    type: 1, name: c.service, notes: c.description ?? null, favorite: false,
    login: { uris: c.url ? [{ match: null, uri: c.url }] : [], username: c.username, password: c.password ?? '', totp: c.otpSecret ? buildOtpUri(c.service, c.otpSecret) : null },
  }));
  return JSON.stringify({ encrypted: false, folders: bwFolders, items }, null, 2);
}

export function exportToBitwardenCSV(credentials: Credential[], folders: Folder[]): string {
  const folderMap = new Map(folders.map(f => [f.id, f.label]));
  const header = 'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp';
  const rows = credentials.map(c =>
    [csvEscape(c.folderId ? (folderMap.get(c.folderId) ?? '') : ''), '0', 'login', csvEscape(c.service), csvEscape(c.description), '', '0', csvEscape(c.url), csvEscape(c.username), csvEscape(c.password), c.otpSecret ? csvEscape(buildOtpUri(c.service, c.otpSecret)) : ''].join(','),
  );
  return [header, ...rows].join('\n');
}

export function exportTo1PasswordCSV(credentials: Credential[]): string {
  const header = 'Title,Username,Password,URL,Notes,OTPAuth';
  const rows = credentials.map(c =>
    [csvEscape(c.service), csvEscape(c.username), csvEscape(c.password), csvEscape(c.url), csvEscape(c.description), c.otpSecret ? csvEscape(buildOtpUri(c.service, c.otpSecret)) : ''].join(','),
  );
  return [header, ...rows].join('\n');
}

export function exportToNordPass(credentials: Credential[]): string {
  const header = 'name,url,username,password,note,cardholder_name,card_number,expiry_date,cvv,notes,type';
  const rows = credentials.map(c =>
    [csvEscape(c.service), csvEscape(c.url), csvEscape(c.username), csvEscape(c.password ?? ''), csvEscape(c.description), '', '', '', '', '', 'login'].join(','),
  );
  return [header, ...rows].join('\n');
}

export function exportToLastPass(credentials: Credential[]): string {
  const header = 'url,username,password,totp,extra,name,grouping,fav';
  const rows = credentials.map(c =>
    [csvEscape(c.url), csvEscape(c.username), csvEscape(c.password), c.otpSecret ? csvEscape(buildOtpUri(c.service, c.otpSecret)) : '', csvEscape(c.description), csvEscape(c.service), '', '0'].join(','),
  );
  return [header, ...rows].join('\n');
}

export function exportToChrome(credentials: Credential[]): string {
  const header = 'name,url,username,password,note';
  const rows = credentials.map(c =>
    [csvEscape(c.service), csvEscape(c.url), csvEscape(c.username), csvEscape(c.password ?? ''), csvEscape(c.description)].join(','),
  );
  return [header, ...rows].join('\n');
}

export function exportToFirefox(credentials: Credential[]): string {
  const header = '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"';
  const now = Date.now();
  const rows = credentials.map(c =>
    [`"${c.url}"`, `"${c.username.replace(/"/g, '""')}"`, `"${(c.password ?? '').replace(/"/g, '""')}"`, `""`, `"${c.url}"`, `"{${generateUUID()}}"`, `"${now}"`, `"${now}"`, `"${now}"`].join(','),
  );
  return [header, ...rows].join('\n');
}

export function exportToKeePassXML(credentials: Credential[], folders: Folder[]): string {
  return buildKeePassXML(credentials, folders);
}

export function exportToKeePassCSV(credentials: Credential[]): string {
  const header = '"Account","Login Name","Password","Web Site","Comments"';
  const rows = credentials.map(c =>
    [`"${c.service.replace(/"/g, '""')}"`, `"${c.username.replace(/"/g, '""')}"`, `"${(c.password ?? '').replace(/"/g, '""')}"`, `"${c.url.replace(/"/g, '""')}"`, `"${(c.description ?? '').replace(/"/g, '""')}"`].join(','),
  );
  return [header, ...rows].join('\n');
}

export function exportToKeeperJSON(credentials: Credential[], folders: Folder[]): string {
  const folderMap = new Map(folders.map(f => [f.id, f.label]));
  return JSON.stringify({
    records: credentials.map(c => ({
      title: c.service, login: c.username, password: c.password ?? '',
      login_url: c.url, notes: c.description ?? '',
      folder: c.folderId ? (folderMap.get(c.folderId) ?? '') : '',
      totp: c.otpSecret ? buildOtpUri(c.service, c.otpSecret) : '',
    })),
  }, null, 2);
}

export function exportToKeeperCSV(credentials: Credential[], folders: Folder[]): string {
  const folderMap = new Map(folders.map(f => [f.id, f.label]));
  const header = 'Folder,Title,Login,Password,Website,Notes,Shared,Two-Factor';
  const rows = credentials.map(c =>
    [csvEscape(c.folderId ? (folderMap.get(c.folderId) ?? '') : ''), csvEscape(c.service), csvEscape(c.username), csvEscape(c.password), csvEscape(c.url), csvEscape(c.description), 'FALSE', c.otpSecret ? csvEscape(buildOtpUri(c.service, c.otpSecret)) : ''].join(','),
  );
  return [header, ...rows].join('\n');
}

export function exportToDashlaneJSON(credentials: Credential[]): string {
  return JSON.stringify({
    credentials: credentials.map(c => ({
      title: c.service, url: c.url, login: c.username, email: c.username,
      password: c.password ?? '', note: c.description ?? '',
      otpSecret: c.otpSecret ?? '',
    })),
  }, null, 2);
}

export function exportToRoboForm(credentials: Credential[], folders: Folder[]): string {
  const folderMap = new Map(folders.map(f => [f.id, f.label]));
  const header = 'Name,Url,Login,Pwd,Note,Folder';
  const rows = credentials.map(c =>
    [csvEscape(c.service), csvEscape(c.url), csvEscape(c.username), csvEscape(c.password), csvEscape(c.description), csvEscape(c.folderId ? (folderMap.get(c.folderId) ?? '') : '')].join(','),
  );
  return [header, ...rows].join('\n');
}

export function exportToProtonPass(credentials: Credential[], folders: Folder[]): string {
  const vaultName = 'PWDnow Vault';
  const folderMap = new Map(folders.map(f => [f.id, f.label]));
  return JSON.stringify({
    encrypted: false,
    vaults: {
      [generateUUID()]: {
        name: vaultName,
        items: credentials.map(c => ({
          data: {
            type: 'login',
            metadata: { name: c.service, note: c.description ?? '' },
            content: {
              username: c.username,
              password: c.password ?? '',
              urls: c.url ? [c.url] : [],
              totp_uri: c.otpSecret ? buildOtpUri(c.service, c.otpSecret) : '',
            },
            extraFields: [],
          },
          pinned: false,
          aliases: [],
        })),
      },
    },
  }, null, 2);
}

export function exportToZohoCSV(credentials: Credential[]): string {
  const header = 'Secret Name,Account Name,Password,Comments,Url,Tags';
  const rows = credentials.map(c =>
    [csvEscape(c.service), csvEscape(c.username), csvEscape(c.password), csvEscape(c.description), csvEscape(c.url), ''].join(','),
  );
  return [header, ...rows].join('\n');
}

export function exportToPassboltCSV(credentials: Credential[]): string {
  const header = 'Title,Username,Password,URL,Description';
  const rows = credentials.map(c =>
    [csvEscape(c.service), csvEscape(c.username), csvEscape(c.password), csvEscape(c.url), csvEscape(c.description)].join(','),
  );
  return [header, ...rows].join('\n');
}

export function exportToPadlocJSON(credentials: Credential[], folders: Folder[]): string {
  const folderMap = new Map(folders.map(f => [f.id, f.label]));
  return JSON.stringify({
    version: '3',
    vaults: [{
      name: 'PWDnow Vault',
      items: credentials.map(c => ({
        name: c.service,
        category: 'login',
        tags: c.folderId ? [folderMap.get(c.folderId) ?? ''] : [],
        fields: [
          { name: 'username', value: c.username, type: 'username' },
          { name: 'password', value: c.password ?? '', type: 'password' },
          { name: 'url', value: c.url, type: 'url' },
          ...(c.otpSecret ? [{ name: 'otp', value: buildOtpUri(c.service, c.otpSecret), type: 'totp' }] : []),
        ],
        notes: c.description ?? '',
      })),
    }],
  }, null, 2);
}

export function exportToPasskyJSON(credentials: Credential[]): string {
  return JSON.stringify({
    passwords: credentials.map(c => ({
      website: c.url, username: c.username,
      password: c.password ?? '', note: c.description ?? '',
    })),
  }, null, 2);
}

export function exportToEnpassCSV(credentials: Credential[]): string {
  const header = 'Title,URL,Username,Password,Notes,One-Time Password';
  const rows = credentials.map(c =>
    [csvEscape(c.service), csvEscape(c.url), csvEscape(c.username), csvEscape(c.password), csvEscape(c.description), c.otpSecret ? csvEscape(buildOtpUri(c.service, c.otpSecret)) : ''].join(','),
  );
  return [header, ...rows].join('\n');
}

export function exportToButtercupJSON(credentials: Credential[], folders: Folder[]): string {
  const folderMap = new Map(folders.map(f => [f.id, f.label]));
  return JSON.stringify({
    groups: [{
      title: 'PWDnow',
      entries: credentials.map(c => ({
        properties: {
          title: c.service,
          username: c.username,
          password: c.password ?? '',
          URL: c.url,
          Notes: c.description ?? '',
          group: c.folderId ? (folderMap.get(c.folderId) ?? '') : '',
        },
      })),
    }],
  }, null, 2);
}

// ── Download helpers ──────────────────────────────────────────────────────────

export function triggerDownload(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export function triggerBinaryDownload(data: Uint8Array, filename: string, mimeType: string): void {
  const blob = new Blob([data], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

// ── Auto-import: detect format from file content ──────────────────────────────

export async function importFromFile(file: File, passphrase?: string): Promise<ImportResult> {
  const ext = (file.name.split('.').pop() ?? '').toLowerCase();

  const knownFormat = FORMATS.find(f => f.importExts?.includes(ext));
  if (knownFormat && !knownFormat.canImport && knownFormat.exportNote) {
    throw new Error(`Unsupported file format. ${knownFormat.exportNote}`);
  }

  // .p2w - binary format, must be handled before text() call
  if (ext === 'p2w') {
    // p2wFormat is already statically imported at the top of this file; use it directly.
    const buf = new Uint8Array(await file.arrayBuffer());
    if (!isP2WFile(buf)) throw new Error('Not a valid .p2w file - magic bytes missing.');
    if (!passphrase) throw new Error('ENCRYPTED_PWDNOW');
    const { credentials } = await importFromP2W(buf, passphrase);
    return { credentials, detectedFormat: 'pwdnow-p2w' };
  }

  // .kdbx - KeePass binary format
  if (ext === 'kdbx') {
    const { importKdbx } = await import('./kdbxFormat');
    if (!passphrase) throw new Error('ENCRYPTED_PWDNOW');
    return await importKdbx(await file.arrayBuffer(), passphrase);
  }

  const text = await file.text();

  if (ext === 'xml') {
    // SafeInCloud has a <database> root with <card> children; KeePass uses <KeePassFile>.
    if (/<database\b/i.test(text) && /<card\b/i.test(text)) return importSafeInCloud(text);
    return importKeePassXML(text);
  }

  if (ext === '1pux') {
    // .1pux is a ZIP - extract export.data
    const data = await extractFromZip(await file.arrayBuffer(), 'export.data');
    if (!data) throw new Error('Could not read export.data from .1pux file.');
    return import1PUX(new TextDecoder().decode(data));
  }

  if (ext === 'json') {
    let obj: Record<string, unknown>;
    try { obj = JSON.parse(text); } catch { throw new Error('Invalid JSON file.'); }

    // Encrypted PWDnow
    if (obj['encrypted'] === true && obj['app'] === 'PWDnow') {
      if (!passphrase) throw new Error('ENCRYPTED_PWDNOW');
      return importPWDnow(await decryptPWDnowExport(text, passphrase));
    }
    // PWDnow unencrypted — must come before Dashlane (both have 'credentials' key)
    if (obj['app'] === 'PWDnow') return importPWDnow(text);
    // Bitwarden — always has 'encrypted' boolean; check it before Enpass (both have 'items')
    if ('items' in obj && 'encrypted' in obj) return importBitwardenJSON(text);
    // Dashlane
    if ('credentials' in obj && Array.isArray(obj['credentials']) && (obj['credentials'][0] as Record<string,unknown>)?.['url'] !== undefined) return importDashlaneJSON(text);
    // Keeper
    if ('records' in obj || 'shared_folders' in obj) return importKeeperJSON(text);
    // Proton Pass
    if ('vaults' in obj && typeof obj['vaults'] === 'object' && !Array.isArray(obj['vaults'])) return importProtonPass(text);
    // Padloc
    if ('vaults' in obj && Array.isArray(obj['vaults']) && (obj['vaults'][0] as Record<string,unknown>)?.['items']) return importPadloc(text);
    // Passky
    if ('passwords' in obj && Array.isArray(obj['passwords'])) return importPassky(text);
    // Enpass
    if ('items' in obj && Array.isArray(obj['items'])) return importEnpassJSON(text);
    // 1PUX data (unzipped manually)
    if ('accounts' in obj) return import1PUX(text);
    // Buttercup
    if ('groups' in obj) return importButtercup(text);
    // PWDnow
    return importPWDnow(text);
  }

  if (ext === 'csv') {
    const first = text.replace(/^﻿/, '').split(/\r?\n/)[0].toLowerCase();
    if (first.includes('httprealm') || first.includes('formactionorigin')) return importFirefox(text);
    if (first.includes('login_uri') || first.includes('login_username')) return importBitwardenCSV(text);
    if (first.includes('grouping') || (first.includes('extra') && first.includes('fav'))) return importLastPass(text);
    if (first.startsWith('"url"') || first.startsWith('url,username') || first.startsWith('"url",')) return importLastPass(text);
    if (first.includes('otpauth') || (first.includes('title') && first.includes('otpauth'))) return import1PasswordCSV(text);
    if (first.includes('login_url') || first.includes('login,password') || first.includes(',login,')) return importKeeperCSV(text);
    if (first.includes('cardholder') || first.includes('cvv')) return importNordPass(text);
    if (first.includes('"account"') || first.includes('login name')) return importKeePassCSV(text);
    if (first.includes('login') && first.includes('pwd')) return importRoboForm(text);
    if (first.includes('secret name') || first.includes('account name')) return importZoho(text);
    if (first.includes('title') && first.includes('username') && first.includes('password') && first.includes('url')) return importPassbolt(text);
    if (first.includes('account type') || first.includes('2fa key')) return importMSecure(text);
    if (first.includes('autologin') || (first.includes('kind') && first.includes('two_factor'))) return importTrueKey(text);
    if (first.includes('name') && first.includes('url') && first.includes('username')) return importChrome(text);
    // fallback: treat as Chrome/generic CSV
    return importChrome(text);
  }

  const supportedExts = Array.from(new Set(FORMATS.filter(f => f.canImport).flatMap(f => f.importExts || []))).join(', ').toUpperCase();
  throw new Error(`Unsupported file format. Supported: ${supportedExts}.`);
}

// Minimal ZIP reader to extract a named file
async function extractFromZip(buffer: ArrayBuffer, targetName: string): Promise<Uint8Array | null> {
  const data = new Uint8Array(buffer);
  const dv = new DataView(buffer);
  let offset = 0;
  while (offset < data.length - 4) {
    const sig = dv.getUint32(offset, true);
    if (sig !== 0x04034B50) { offset++; continue; } // skip non-LFH bytes, keep scanning
    const nameLen = dv.getUint16(offset + 26, true);
    const extraLen = dv.getUint16(offset + 28, true);
    const compSize = dv.getUint32(offset + 18, true);
    const nameBytes = data.slice(offset + 30, offset + 30 + nameLen);
    const name = new TextDecoder().decode(nameBytes);
    const fileOffset = offset + 30 + nameLen + extraLen;
    if (name === targetName) return data.slice(fileOffset, fileOffset + compSize);
    offset = fileOffset + compSize;
  }
  return null;
}

