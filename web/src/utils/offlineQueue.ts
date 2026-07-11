import { logger } from './logger';
import { encryptForServer, decryptFromServer } from './localCrypto';
import { apiFetch } from './api';

// ── Encrypted offline outbox ──────────────────────────────────────────────────
//
// When a server-mode vault write fails because the network is unreachable
// (not because of a real server-side error), the write is queued here instead
// of being silently dropped. Each resource (folders / credentials /
// asset-holder) keeps only its MOST RECENT failed write, because every write
// already PUTs the full collection, not a delta - a newer queued write always
// fully supersedes an older one for the same resource, so there is nothing to
// replay "in order" beyond one entry per resource.
//
// Encrypted with the same AES-256-GCM scheme already used for server-mode
// vault data (`encryptForServer`/`decryptFromServer` from `localCrypto.ts`),
// deliberately using the deterministic v1 (PBKDF2) key rather than the
// session-bound v2 (Argon2id) key. The v2 key dies with the session token;
// this queue must survive an unexpected session expiry or crashed tab and
// still be flushable after the user logs back in.

export type QueueResource = 'folders' | 'credentials' | 'asset_holder';

interface QueueEntry {
  /** Already-encrypted PUT body - identical to what /api/vault/<resource> expects. */
  encryptedValue: string;
  queuedAt: number;
}

type Outbox = Partial<Record<QueueResource, QueueEntry>>;

const OUTBOX_KEY = 'vault_outbox';
const OUTBOX_CHANGED_EVENT = 'vaultOutboxChanged';

/** Thrown by callers of `_localWrite` (VaultContext) when a write has been
 *  queued rather than failed outright, so calling code can skip the
 *  "couldn't save" rollback/notification path and instead show a
 *  pending-sync indicator while keeping the optimistic UI state. */
export class QueuedOfflineError extends Error {
  constructor(public readonly resource: QueueResource) {
    super(`write queued for ${resource} (offline)`);
    this.name = 'QueuedOfflineError';
  }
}

function resourceToEndpoint(resource: QueueResource): string {
  return resource === 'asset_holder' ? 'asset-holder' : resource;
}

async function readOutbox(): Promise<Outbox> {
  const raw = localStorage.getItem(OUTBOX_KEY);
  if (!raw) return {};
  try {
    const json = await decryptFromServer(raw);
    if (!json) return {};
    const parsed = JSON.parse(json);
    return parsed && typeof parsed === 'object' ? parsed as Outbox : {};
  } catch {
    return {};
  }
}

async function writeOutbox(outbox: Outbox): Promise<void> {
  if (Object.keys(outbox).length === 0) {
    localStorage.removeItem(OUTBOX_KEY);
    return;
  }
  const encrypted = await encryptForServer(JSON.stringify(outbox));
  // If encryption isn't possible (no key in memory), we simply can't persist
  // the queue right now - never fall back to writing plaintext.
  if (encrypted) localStorage.setItem(OUTBOX_KEY, encrypted);
}

function notifyChanged() {
  window.dispatchEvent(new CustomEvent(OUTBOX_CHANGED_EVENT));
}

/** Queue (or replace) the pending write for a resource. */
export async function queueWrite(resource: QueueResource, encryptedValue: string): Promise<void> {
  const outbox = await readOutbox();
  outbox[resource] = { encryptedValue, queuedAt: Date.now() };
  await writeOutbox(outbox);
  notifyChanged();
}

/** Remove a resource's queued write (e.g. a later online write already superseded it). */
export async function clearQueuedWrite(resource: QueueResource): Promise<void> {
  const outbox = await readOutbox();
  if (outbox[resource]) {
    delete outbox[resource];
    await writeOutbox(outbox);
    notifyChanged();
  }
}

/** Number of resources with an unsynced write pending. */
export async function getQueueSize(): Promise<number> {
  return Object.keys(await readOutbox()).length;
}

/** Forensic-wipe / logout hook: drop the queue entirely without flushing it. */
export function discardQueue(): void {
  localStorage.removeItem(OUTBOX_KEY);
  notifyChanged();
}

// ── Flush ──────────────────────────────────────────────────────────────────

let flushing = false;

export interface FlushResult {
  flushed: QueueResource[];
  /** Non-empty only when a queued write failed for a reason retrying won't
   *  fix on its own (e.g. session expired) - the caller should surface this. */
  authExpired: boolean;
}

/** Replay every queued write against the server, stopping at the first
 *  failure (if the network is genuinely down, or the session has expired,
 *  every subsequent attempt will fail the same way - no point burning
 *  requests). Safe to call opportunistically; a module-level lock prevents
 *  overlapping flushes from the same tab (e.g. an `online` event firing while
 *  a periodic check is already in flight). */
export async function flushOutbox(): Promise<FlushResult> {
  if (flushing) return { flushed: [], authExpired: false };
  flushing = true;
  const flushed: QueueResource[] = [];
  let authExpired = false;
  try {
    const outbox = await readOutbox();
    for (const resource of Object.keys(outbox) as QueueResource[]) {
      const entry = outbox[resource];
      if (!entry) continue;
      try {
        await apiFetch(`/api/vault/${resourceToEndpoint(resource)}`, {
          method: 'PUT',
          body: JSON.stringify({ data: entry.encryptedValue }),
        });
        await clearQueuedWrite(resource);
        flushed.push(resource);
      } catch (e: unknown) {
        const status = (e as { status?: number })?.status;
        if (status === 401) authExpired = true;
        logger.warn(`[offlineQueue] flush failed for ${resource}, will retry later:`, e);
        break;
      }
    }
  } finally {
    flushing = false;
  }
  return { flushed, authExpired };
}

export { OUTBOX_CHANGED_EVENT };
