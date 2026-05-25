import { readFileSync, writeFileSync, existsSync } from 'fs';
import { lock } from 'proper-lockfile';
import path from 'path';
import { createHmac } from 'crypto';
import { ctx } from './context.js';
import {
  derivedKey,
  userVaultDir,
  userInfo,
  readEncryptedFile,
  writeEncryptedFile,
} from './fileCrypto.js';
import { generateUUID, getClientIp } from './session.js';

// ── IP Policy ─────────────────────────────────────────────────────────────────

function parseBoolEnv(key, defaultVal) {
  const v = process.env[key];
  if (v === undefined || v === '') return defaultVal;
  return v === 'true' || v === '1';
}

export function loadIpPolicy() {
  return {
    blockTor:    parseBoolEnv('IP_BLOCK_TOR',    true),
    blockProxy:  parseBoolEnv('IP_BLOCK_PROXY',  true),
    blockVpn:    parseBoolEnv('IP_BLOCK_VPN',    false),
    blockAbuser: parseBoolEnv('IP_BLOCK_ABUSER', true),
  };
}

// ── Audit Log ─────────────────────────────────────────────────────────────────

export function auditLogPath(uid) { return path.join(userVaultDir(uid), 'audit_log.enc'); }

export function loadAuditLog(uid) {
  const events = readEncryptedFile(auditLogPath(uid), userInfo(uid, 'audit_log'), []);
  // Verify HMAC integrity chain to detect log excision or tampering.
  if (events.length > 0) {
    const key = derivedKey('audit/chain');
    let prevHash = '0'.repeat(64);
    for (const e of events) {
      const { hash, integrity_failure: _ignored, ...data } = e;
      if (!hash) {
        e.integrity_failure = true;
        continue;
      }
      const expected = createHmac('sha256', key).update(JSON.stringify(data) + prevHash).digest('hex');
      if (hash !== expected) {
        console.error(`[audit] Integrity chain broken at event ${e.id} for user ${uid}`);
        e.integrity_failure = true;
      }
      prevHash = hash;
    }
  }
  return events;
}

export function saveAuditLog(uid, events) {
  writeEncryptedFile(auditLogPath(uid), userInfo(uid, 'audit_log'), events);
}

export function compactIpInfo(record) {
  if (!record) return null;
  return {
    country: record.country, countryCode: record.countryCode,
    countryFlag: record.countryFlag, city: record.city,
    region: record.region, org: record.org,
    connectionType: record.connectionType, riskFlags: record.riskFlags,
  };
}

// ── Server public IP cache ─────────────────────────────────────────────────────
// Cache the server's outbound public IP (used when client IP is loopback).
// 24-hour persistent cache avoids beaconing on every restart.

let _serverPublicIp = null;
let _serverPublicIpLastFetch = 0;
export const PUBLIC_IP_CACHE_MS = 24 * 60 * 60 * 1000;

export async function getServerPublicIp() {
  const cachePath = path.join(ctx.DATA_DIR, 'public_ip_cache.json');
  const now = Date.now();

  if (!_serverPublicIp && existsSync(cachePath)) {
    try {
      const data = JSON.parse(readFileSync(cachePath, 'utf8'));
      _serverPublicIp = data.ip;
      _serverPublicIpLastFetch = data.timestamp;
    } catch { /* ignore corrupt cache */ }
  }

  if (_serverPublicIp && (now - _serverPublicIpLastFetch < PUBLIC_IP_CACHE_MS)) {
    return _serverPublicIp;
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    const r = await fetch('https://api64.ipify.org?format=json', { signal: controller.signal });
    clearTimeout(timer);
    const data = await r.json();
    _serverPublicIp = data.ip || null;
    _serverPublicIpLastFetch = now;
    // Persist to disk
    try {
      writeFileSync(cachePath, JSON.stringify({ ip: _serverPublicIp, timestamp: now }), { mode: 0o600 });
    } catch { /* ignore write failure */ }
  } catch {
    // Keep stale IP if fetch fails
  }
  return _serverPublicIp;
}

// ── Audit event queue ─────────────────────────────────────────────────────────

export const LOOPBACK_RE = /^(127\.|::1$|::ffff:127\.)/;
export const _auditQueue = [];
export let _isFlushingAudits = false;

// Audit events are written via an in-memory queue and async flush to prevent the
// per-user-dir lock from serializing requests on every authenticated call.
// H-12 fix: drain the queue atomically into a local array before processing.
async function flushAuditQueue() {
  if (_isFlushingAudits) return;
  _isFlushingAudits = true;
  try {
    while (_auditQueue.length > 0) {
      const drained = _auditQueue.splice(0, _auditQueue.length);
      for (const { uid, event } of drained) {
        try {
          await processAuditEvent(uid, event);
        } catch (e) {
          console.error(`[auth] Failed to process audit event for ${uid}:`, e.message);
        }
      }
    }
  } finally {
    _isFlushingAudits = false;
  }
}

async function processAuditEvent(uid, event) {
  const dir = userVaultDir(uid);
  if (!existsSync(dir)) return;

  let release = null;
  try {
    release = await lock(dir, { retries: { retries: 20, minTimeout: 100, maxTimeout: 1000 } });

    let enriched = { ...event };
    // Enrich loopback IPs with the server's real outbound public IP.
    if (LOOPBACK_RE.test(enriched.ip || '')) {
      const publicIp = await getServerPublicIp();
      if (publicIp) {
        enriched.publicIp = publicIp;
        if (ctx.ipIntel?.isEnabled() && !enriched.ipInfo) {
          const record = await ctx.ipIntel.lookup(publicIp);
          if (record) enriched.ipInfo = compactIpInfo(record);
        }
      }
    }

    const events = loadAuditLog(uid);
    const lastEvent = events[events.length - 1];
    const prevHash = lastEvent?.hash || '0'.repeat(64);

    const newEvent = { id: generateUUID(), ts: Date.now(), ...enriched };

    const key = derivedKey('audit/chain');
    newEvent.hash = createHmac('sha256', key).update(JSON.stringify(newEvent) + prevHash).digest('hex');

    events.push(newEvent);

    // Ring-buffer cap: 2000 events max to avoid excessive I/O overhead on every append.
    const trimmed = events.length > 2000 ? events.slice(events.length - 2000) : events;
    saveAuditLog(uid, trimmed);
  } finally {
    if (release) await release().catch(() => {});
  }
}

export function appendAuditEvent(uid, event) {
  // Cap queue size to prevent memory exhaustion if the flush stalls.
  if (_auditQueue.length < 5000) {
    _auditQueue.push({ uid, event });
    flushAuditQueue().catch(() => {});
  } else {
    console.warn('[auth] Audit queue full - dropping event');
  }
}

// ── IP Blocking Middleware ─────────────────────────────────────────────────────

export async function ipBlockingMiddleware(req, res, next) {
  if (!ctx.ipIntel || !ctx.ipIntel.isEnabled()) return next();
  const ip = getClientIp(req);
  try {
    const record = await ctx.ipIntel.lookup(ip);
    req.ipRecord = record || null;
    if (record && ctx.ipIntel.isThreat(record, ctx.ipPolicy)) {
      console.warn('[ipBlock] Blocked', ip, 'flags:', record.riskFlags.join(','));
      return res.status(403).json({ error: 'access_denied' });
    }
  } catch (err) {
    console.warn('[ipBlock] middleware error:', err.message);
  }
  next();
}
