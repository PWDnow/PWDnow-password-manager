import { logger } from '../utils/logger';
import React, { createContext, useContext, useState, useEffect, useCallback, useRef, ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Folder, Credential, AssetHolder } from '../types';
import { useNotification } from './NotificationContext';
import { generateUUID } from '../utils/crypto';
import { daemon } from '../utils/daemonClient';
import { writeEncryptedLocal, readDecryptedLocal, encryptForServer, decryptFromServer } from '../utils/localCrypto';
import { keyStore } from '../crypto/keystore';
import { getTravelModeConfig, getTravelModeConfigAsync } from '../utils/securityModes';
import { getCsrfToken, apiFetch, hasServerSession as _hasServerSession, ApiError } from '../utils/api';
import { queueWrite, QueuedOfflineError, getQueueSize, flushOutbox, OUTBOX_CHANGED_EVENT, type QueueResource } from '../utils/offlineQueue';

interface VaultContextType {
  folders: Folder[];
  credentials: Credential[];
  assetHolder: AssetHolder;
  isLoading: boolean;
  credentialsLoading: boolean;
  daemonConnected: boolean;
  vaultLocked: boolean;
  /** Number of vault resources (folders/credentials/asset-holder) with a
   *  write queued because it couldn't reach the server - not yet synced. */
  pendingSyncCount: number;
  /** Adds a folder. Returns the *resolved* id (which may differ from `folder.id`
   *  when the daemon assigns its own UUID or a slug collides). */
  addFolder: (folder: Folder) => Promise<string>;
  updateFolder: (folder: Folder) => Promise<void>;
  deleteFolder: (id: string) => Promise<void>;
  reorderFolders: (folders: Folder[]) => Promise<void>;
  addCredential: (credential: Credential) => Promise<void>;
  updateCredential: (credential: Credential) => Promise<void>;
  deleteCredential: (id: string | number) => Promise<void>;
  moveCredentials: (sourceFolderId: string, targetFolderId: string, credentialIds?: (string | number)[]) => Promise<void>;
  updateAssetHolder: (assetHolder: AssetHolder) => Promise<void>;
  reload: () => Promise<void>;
  reloadLocal: () => Promise<void>;
  persistFolders: (current: Folder[]) => Promise<void>;
  persistCredentials: (current: Credential[]) => Promise<void>;
}

const VaultContext = createContext<VaultContextType | undefined>(undefined);

// ── API fallbacks (demo / offline mode) ──────────────────────────────
const LOCAL_SUFFIX = '';

const VAULT_LOCAL_KEYS = [
  `vault_folders${LOCAL_SUFFIX}`,
  `vault_credentials${LOCAL_SUFFIX}`,
  `vault_asset_holder${LOCAL_SUFFIX}`,
];

function wipeDemoLocalStorage(): void {
  for (const k of VAULT_LOCAL_KEYS) localStorage.removeItem(k);
}

// ── Offline queue notification helper ─────────────────────────────────────
// A write that failed only because the network is unreachable is not an
// error from the user's point of view - their edit is safe (queued,
// encrypted, on disk) and will sync automatically. This is deliberately a
// distinct, calmer notification from the red "couldn't save" one used for
// real failures (auth/validation/server errors), which do need the user's
// attention because they won't resolve on their own.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function notifyQueuedOffline(t: any, addNotification: any, label?: string): void {
  addNotification({
    type: 'info',
    title: t('notifications.offlineQueuedTitle', 'Saved offline'),
    message: label
      ? t('notifications.offlineQueuedMessageNamed', { name: label, defaultValue: `"${label}" is saved on this device and will sync once you're back online.` })
      : t('notifications.offlineQueuedMessage', 'Your change is saved on this device and will sync once you\'re back online.'),
  });
}

// ── Per-key write mutex ──────────────────────────────────────────────
// Ensures concurrent persists on the same vault key (e.g. two rapid folder
// creations) are serialised FIFO instead of racing - the last encryption to
// finish would otherwise win, even when its plaintext is older.
const _writeChain: Record<string, Promise<unknown>> = {};
function serializedWrite<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = _writeChain[key] ?? Promise.resolve();
  // Errors in earlier writes must not poison later ones.
  const next = prev.catch(() => undefined).then(fn);
  _writeChain[key] = next;
  return next;
}

// True only when the server has issued a session cookie pair for this browser.
// The CSRF cookie (_pwd_csrf) is the non-HttpOnly half - readable from JS - and is
// set only by /api/auth/login or /api/auth/register.  Daemon-authenticated users
// and unauthenticated visitors (e.g. the login page) never have this cookie.
function hasServerSession(): boolean {
  if (typeof document === 'undefined') return false;
  return _hasServerSession();
}

/** Sentinel thrown when ciphertext is present but the local AES key is not yet
 *  imported. Callers must NOT default to `[]`; doing so would blank the UI and
 *  the migration path used to overwrite the server-side data with that empty
 *  snapshot. The error surfaces to performLoad which leaves React state alone
 *  and waits for the next `demoKeyAvailable` event. */
class DecryptionPendingError extends Error {
  constructor(key: string) { super(`decryption pending for ${key}`); this.name = 'DecryptionPendingError'; }
}

const _localRead = async (key: string): Promise<string | null> => {
  if (hasServerSession()) {
    const endpoint = key.replace('vault_', '').replace(LOCAL_SUFFIX, '');
    const url = `/api/vault/${endpoint.replace('_', '-')}`;
    let data: any;
    try {
      data = await apiFetch(url);
    } catch (e: any) {
      if (e.status === 401) {
        // Session cookie was cleared or expired - notify AppLayout to redirect.
        keyStore.clear();
        document.cookie = "_pwd_csrf=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; Secure; SameSite=Strict;";
        window.dispatchEvent(new CustomEvent('sessionInvalid'));
      }
      return null;
    }
    if (data && typeof data.data === 'string') {
      // Ensure keys are fully imported before decryption attempt
      await keyStore.restoreAsync();
      const pt = await decryptFromServer(data.data);
      if (pt === null) {
        // Expected during the brief window between page-mount and key import.
        // Suppressed from the console to avoid noise; performLoad still
        // catches DecryptionPendingError and waits for `demoKeyAvailable`.
        throw new DecryptionPendingError(key);
      }
      return pt;
    }
    return JSON.stringify(data); // legacy unencrypted blob (initial array etc.)
  }
  // No server session (daemon mode, unauthenticated) - read from encrypted localStorage.
  return readDecryptedLocal(key);
};

const _localWrite = (key: string, value: string): Promise<void> => serializedWrite(key, async () => {
  const isServer = hasServerSession();

  if (isServer) {
    const endpoint = key.replace('vault_', '').replace(LOCAL_SUFFIX, '');
    const url = `/api/vault/${endpoint.replace('_', '-')}`;
    const encryptedValue = await encryptForServer(value);
    if (!encryptedValue) {
      // Refuse to proceed: writing plaintext is forbidden by the security
      // envelope. Surface a clear error so the caller can roll back UI state
      // instead of silently dropping the change.
      throw new Error('vault encryption key not ready');
    }

    try {
      await apiFetch(url, {
        method: 'PUT',
        body: JSON.stringify({ data: encryptedValue }),
      });
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        keyStore.clear();
        document.cookie = "_pwd_csrf=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; Secure; SameSite=Strict;";
        window.dispatchEvent(new CustomEvent('sessionInvalid'));
        throw new Error('session expired');
      }
      if (!(e instanceof ApiError)) {
        // fetch() itself threw (TypeError: Failed to fetch, etc.) rather than
        // the server responding with an error status - the network is down,
        // not the write. Queue the already-encrypted payload so it isn't
        // lost, instead of surfacing a generic failure the caller would roll
        // back on.
        const resource = endpoint as QueueResource;
        await queueWrite(resource, encryptedValue);
        throw new QueuedOfflineError(resource);
      }
      throw new Error(`vault PUT ${endpoint} failed: ${e.status}`);
    }
    localStorage.removeItem(key);
    return;
  }

  await writeEncryptedLocal(key, value);
});

const DEFAULT_FOLDERS: Folder[] = [];

async function loadLocalFolders(): Promise<Folder[]> {
  const isServer = hasServerSession();
  const saved = await _localRead(`vault_folders${LOCAL_SUFFIX}`);
  
  if (saved) {
    try {
      const parsed = JSON.parse(saved);
      const seenIds = new Set<string>();
      return parsed.map((f: Folder) => {
        let id = f.id;
        while (seenIds.has(id)) id = `${id}-${generateUUID().substring(0, 8)}`;
        seenIds.add(id);
        return { ...f, id };
      });
    } catch (e) {
      logger.error('[VaultContext] Folder parse error:', e);
      // Don't throw - allow demoKeyAvailable reload to retry with correct keys
    }
  } else if (isServer) {
    // Data exists on the server but could not be decrypted (keys not yet
    // available or key mismatch from a prior session). Don't throw - the
    // demoKeyAvailable event will trigger a reload once the user logs in
    // and deterministic keys become available.
  }
  return [...DEFAULT_FOLDERS];
}

async function loadLocalCredentials(): Promise<Credential[]> {
  const isServer = hasServerSession();
  const saved = await _localRead(`vault_credentials${LOCAL_SUFFIX}`);
  if (saved) {
    try {
      const parsed = JSON.parse(saved);
      const seenIds = new Set<string | number>();
      return parsed.map((c: Credential) => {
        let id = c.id;
        while (seenIds.has(id)) id = `${id}-${generateUUID().substring(0, 8)}`;
        seenIds.add(id);
        return { ...c, id };
      });
    } catch (e) {
      logger.error('[VaultContext] Credential parse error:', e);
      // Don't throw - allow demoKeyAvailable reload to retry with correct keys
    }
  } else if (isServer) {
    // Same rationale as loadLocalFolders - wait for demoKeyAvailable.
  }
  return [];
}

async function loadLocalAssetHolder(): Promise<AssetHolder> {
  const isServer = hasServerSession();
  const saved = await _localRead(`vault_asset_holder${LOCAL_SUFFIX}`);
  if (saved) {
    try {
      const parsed = JSON.parse(saved);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return {
          emails:       Array.isArray(parsed.emails)       ? parsed.emails       : [],
          phoneNumbers: Array.isArray(parsed.phoneNumbers) ? parsed.phoneNumbers : [],
          u2fKeys:      Array.isArray(parsed.u2fKeys)      ? parsed.u2fKeys      : [],
        };
      }
    } catch (e) {
      logger.error('[VaultContext] Assets parse error:', e);
      // Don't throw - allow demoKeyAvailable reload to retry with correct keys
    }
  } else if (isServer) {
    // Same rationale as loadLocalFolders - wait for demoKeyAvailable.
  }
  return { emails: [], phoneNumbers: [], u2fKeys: [] };
}

// ── Helper: map daemon FolderRow → Folder type ────────────────────────────────
// The daemon stores predefined icon names as `icon:<name>` in the icon_svg field
// (the daemon has no separate icon_name column). Raw SVG strings start with `<`.

function rowToFolder(row: { id: string; name: string; description: string | null; icon_svg: string | null }): Folder {
  const iconSvg = row.icon_svg ?? undefined;
  const isIconName = iconSvg?.startsWith('icon:');
  return {
    id:          row.id,
    label:       row.name,
    description: row.description ?? undefined,
    iconName:    isIconName ? iconSvg!.slice('icon:'.length) : undefined,
    customSvg:   isIconName ? undefined : iconSvg,
  };
}

/** Encode a Folder's icon for the daemon's icon_svg column. */
function folderIconSvg(folder: { iconName?: string; customSvg?: string }): string | undefined {
  if (folder.iconName) return `icon:${folder.iconName}`;
  return folder.customSvg;
}

// ── Provider ──────────────────────────────────────────────────────────────────

export function VaultProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const { addNotification } = useNotification();

  // Start empty; populated async in useEffect (CRIT-03: decryption may be needed)
  const [folders,     setFolders]     = useState<Folder[]>([]);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [assetHolder,  setAssetHolder]  = useState<AssetHolder>({ emails: [], phoneNumbers: [], u2fKeys: [] });
  const [isLoading,           setIsLoading]           = useState(true);
  const [credentialsLoading,  setCredentialsLoading]  = useState(false);
  // D-12: default to true if we have a token to prevent the "save-to-local-then-wipe" 
  // race condition during initial page load / refresh.
  const [daemonConnected,     setDaemonConnected]     = useState(
    keyStore.hasToken && keyStore.get()?.length === 64
  );
  const [vaultLocked,         setVaultLocked]         = useState(false);
  const [vaultReady,          setVaultReady]          = useState(false);
  const [loadError,           setLoadError]           = useState(false);

  // Removed useEffect syncing daemonConnected

  // ── Persistence Helpers ───────────────────────────────────────────────────

  // Persist helpers no longer gate on `vaultLocked`. The actual security
  // invariant - "never write plaintext" - is enforced one level down inside
  // `encryptForServer` / `writeEncryptedLocal`, both of which refuse when no
  // key is in memory. Returning a rejected promise lets callers roll back the
  // optimistic React state when the server write fails.
  const persistFolders = useCallback(async (current: Folder[]) => {
    if (daemonConnected) return;
    await _localWrite(`vault_folders${LOCAL_SUFFIX}`, JSON.stringify(current));
  }, [daemonConnected]);

  const persistCredentials = useCallback(async (current: Credential[]) => {
    if (daemonConnected) return;
    await _localWrite(`vault_credentials${LOCAL_SUFFIX}`, JSON.stringify(current));
  }, [daemonConnected]);

  const persistAssetHolder = useCallback(async (current: AssetHolder) => {
    if (daemonConnected) return;
    await _localWrite(`vault_asset_holder${LOCAL_SUFFIX}`, JSON.stringify(current));
  }, [daemonConnected]);

  // ── localStorage async load (offline / demo mode) ─────────────────────────

  const performLoad = useCallback(async () => {
    // D-12: Skip local load ONLY if we have a daemon token (64 hex chars).
    // If we have an offline token (UUID, 36 chars), we MUST load from localStorage.
    const token = keyStore.get();
    if (token && token.length === 64) return;

    // Re-entry (e.g. the `demoKeyAvailable` reload fired right after login)
    // must flip this back to true - it only ever resolves to false in the
    // `finally` below, so without this the skeleton gate stays stuck on
    // whatever the very first pre-login mount left it as.
    setIsLoading(true);

    try {
      if (hasServerSession()) {
        await keyStore.restoreAsync();
        // If session exists but keys are gone from sessionStorage (e.g. browser restart),
        // we don't bail to "vault locked" immediately - we let loadLocalX run (they 
        // will return empty arrays if decryption fails) and wait for the 
        // demoKeyAvailable event after login to trigger a proper reload.
      }

      let f: Folder[] | null = null;
      let c: Credential[] | null = null;
      let a: AssetHolder | null = null;
      let pendingError = false;

      // These four reads are independent network/decryption calls - run them
      // concurrently instead of serially to cut the critical-path latency on
      // initial vault load roughly 4x (each was a separate /api/vault/* round trip).
      const settle = <T,>(v: T | undefined, e: any): { v?: T; e?: any } => ({ v, e });
      const [fRes, cRes, aRes, travel] = await Promise.all([
        loadLocalFolders().then(v => settle(v, undefined), e => settle<Folder[]>(undefined, e)),
        loadLocalCredentials().then(v => settle(v, undefined), e => settle<Credential[]>(undefined, e)),
        loadLocalAssetHolder().then(v => settle(v, undefined), e => settle<AssetHolder>(undefined, e)),
        getTravelModeConfigAsync(),
      ]);

      if (fRes.v !== undefined) f = fRes.v; else if (fRes.e?.name === 'DecryptionPendingError') pendingError = true; else if (fRes.e) logger.error(fRes.e);
      if (cRes.v !== undefined) c = cRes.v; else if (cRes.e?.name === 'DecryptionPendingError') pendingError = true; else if (cRes.e) logger.error(cRes.e);
      if (aRes.v !== undefined) a = aRes.v; else if (aRes.e?.name === 'DecryptionPendingError') pendingError = true; else if (aRes.e) logger.error(aRes.e);

      if (hasServerSession() && !keyStore.hasToken) {
        // Still no keys after restore attempt? User needs to log in to derive them.
        setVaultLocked(true);
        setVaultReady(false);
        setIsLoading(false);
        return;
      }

      if (pendingError && f === null && c === null && a === null) {
        // If everything threw pending, wait for demoKeyAvailable.
        setVaultLocked(false);
        return;
      }

      // Filter for Travel Mode (config already fetched concurrently above)
      if (travel.active) {
        if (f !== null) {
          f = f.filter(folder => !travel.hiddenFolderIds.includes(folder.id));
        }
        if (c !== null) {
          c = c.filter(cred => !travel.hiddenFolderIds.includes(cred.folderId));
        }
      }

      if (f !== null) setFolders(f);
      if (c !== null) setCredentials(c);
      if (a !== null) setAssetHolder(a);
      setVaultReady(true);
      setLoadError(false);
      setVaultLocked(false);

      // (No "migration re-write" here: encryptForServer is already pinned to
      //  the deterministic v1 PBKDF2 key, so nothing needs to be re-encoded
      //  on every load. The previous re-write block was racing user-initiated
      //  PUTs and silently undoing freshly created folders.)
    } catch (err: any) {
      if (err?.name === 'DecryptionPendingError') {
        // Keys aren't imported yet - leave existing folder/credential state
        // intact and wait for the `demoKeyAvailable` event after login. Do
        // not blank the sidebar with `setFolders([])`. Silent: this state
        // resolves itself within a few hundred ms after login completes.
        setVaultLocked(false);
      } else if (err?.message === 'unreadable_vault') {
        setVaultLocked(true);
        setVaultReady(false);
      } else {
        logger.error('[VaultContext] Failed to load local vault:', err);
        setLoadError(true);
        setVaultReady(false);
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    performLoad();
  }, [performLoad]);

  // ── Folder operations ─────────────────────────────────────────────────────

  const addFolder = useCallback(async (newFolder: Folder) => {
    // Always assign a fresh UUID if the caller didn't, or if the supplied id
    // collides with an existing folder. Slug-based ids ("personal" twice)
    // were the source of duplicate-key sidebar drops.
    const ensureId = (id: string | undefined): string => {
      if (!id) return generateUUID();
      if (folders.some(f => f.id === id)) return generateUUID();
      return id;
    };

    if (daemonConnected) {
      // Daemon assigns its own UUID - that is the authoritative id.
      const id = await daemon.addFolder(newFolder.label, newFolder.description, folderIconSvg(newFolder));
      const stored: Folder = { ...newFolder, id };
      setFolders(prev => [...prev, stored]);
      addNotification({
        type: 'folder_created',
        title: t('notifications.folderCreatedTitle', 'Folder Created'),
        message: t('notifications.folderCreatedMessage', { name: stored.label, defaultValue: `New folder "${stored.label}" has been created.` }),
        data: { folderId: stored.id },
      });
      return stored.id;
    }

    // Server / demo mode: optimistic state + awaited persist + rollback on failure.
    const stored: Folder = { ...newFolder, id: ensureId(newFolder.id) };
    const prevFolders = folders;
    const updated = [...prevFolders, stored];
    setFolders(updated);
    try {
      await persistFolders(updated);
    } catch (err) {
      if (err instanceof QueuedOfflineError) {
        notifyQueuedOffline(t, addNotification, stored.label);
        return stored.id;
      }
      logger.error('[VaultContext] addFolder persist failed:', err);
      setFolders(prevFolders);
      addNotification({
        type: 'persistence_failed',
        title: t('notifications.folderSaveFailedTitle', 'Could not save folder'),
        message: t('notifications.folderSaveFailedMessage', { name: stored.label, defaultValue: `Folder "${stored.label}" could not be saved. Please try again.` }),
      });
      throw err;
    }
    addNotification({
      type: 'folder_created',
      title: t('notifications.folderCreatedTitle', 'Folder Created'),
      message: t('notifications.folderCreatedMessage', { name: stored.label, defaultValue: `New folder "${stored.label}" has been created.` }),
      data: { folderId: stored.id },
    });
    return stored.id;
  }, [t, addNotification, persistFolders, folders, daemonConnected]);

  const updateFolder = useCallback(async (updatedFolder: Folder) => {
    const prevFolders = folders;
    if (daemonConnected) {
      await daemon.updateFolder(updatedFolder.id, updatedFolder.label, updatedFolder.description, folderIconSvg(updatedFolder));
      setFolders(prev => prev.map(f => f.id === updatedFolder.id ? updatedFolder : f));
      return;
    }
    const updated = prevFolders.map(f => f.id === updatedFolder.id ? updatedFolder : f);
    setFolders(updated);
    try {
      await persistFolders(updated);
    } catch (err) {
      if (err instanceof QueuedOfflineError) {
        notifyQueuedOffline(t, addNotification, updatedFolder.label);
        return;
      }
      logger.error('[VaultContext] updateFolder persist failed:', err);
      setFolders(prevFolders);
      throw err;
    }
  }, [folders, persistFolders, daemonConnected, t, addNotification]);

  const deleteFolder = useCallback(async (folderId: string) => {
    const folderToDelete = folders.find(f => f.id === folderId);
    const prevFolders = folders;
    const prevCreds = credentials;
    if (daemonConnected) {
      await daemon.deleteFolder(folderId);
      setFolders(prev => prev.filter(f => f.id !== folderId));
      setCredentials(prev => prev.filter(c => c.folderId !== folderId));
    } else {
      const newFolders = prevFolders.filter(f => f.id !== folderId);
      const newCreds = prevCreds.filter(c => c.folderId !== folderId);
      setFolders(newFolders);
      setCredentials(newCreds);
      try {
        await Promise.all([
          persistFolders(newFolders),
          // Only persist credentials when something actually changed.
          newCreds.length !== prevCreds.length ? persistCredentials(newCreds) : Promise.resolve(),
        ]);
      } catch (err) {
        if (err instanceof QueuedOfflineError) {
          notifyQueuedOffline(t, addNotification, folderToDelete?.label);
          return;
        }
        logger.error('[VaultContext] deleteFolder persist failed:', err);
        setFolders(prevFolders);
        setCredentials(prevCreds);
        throw err;
      }
    }
    if (folderToDelete) {
      addNotification({
        type: 'credential_deleted',
        title: t('notifications.folderDeletedTitle', 'Folder Deleted'),
        message: t('notifications.folderDeletedMessage', { name: folderToDelete.label, defaultValue: `Folder "${folderToDelete.label}" and its contents have been deleted.` }),
        data: { folderId },
      });
    }
  }, [folders, credentials, t, addNotification, persistFolders, persistCredentials, daemonConnected]);

  const reorderFolders = useCallback(async (newFolders: Folder[]) => {
    const prev = folders;
    if (daemonConnected) {
      await daemon.reorderFolders(newFolders.map(f => f.id));
      setFolders(newFolders);
      return;
    }
    setFolders(newFolders);
    try {
      await persistFolders(newFolders);
    } catch (err) {
      if (err instanceof QueuedOfflineError) {
        notifyQueuedOffline(t, addNotification);
        return;
      }
      logger.error('[VaultContext] reorderFolders persist failed:', err);
      setFolders(prev);
      throw err;
    }
  }, [folders, persistFolders, daemonConnected, t, addNotification]);

  // ── Credential operations ─────────────────────────────────────────────────

  const addCredential = useCallback(async (newCredential: Credential) => {
    if (daemonConnected) {
      const { id: _id, folderId, ...rest } = newCredential;
      const id = await daemon.addCredential(folderId ?? null, rest);
      setCredentials(prev => [...prev, { ...newCredential, id }]);
      addNotification({
        type: 'credential_added',
        title: t('notifications.credentialAddedTitle', 'Credential Added'),
        message: t('notifications.credentialAddedMessage', { service: newCredential.service, defaultValue: `New credential for "${newCredential.service}" has been added.` }),
        data: { credentialId: newCredential.id },
      });
      return;
    }
    // Server / demo mode: optimistic state + awaited persist + rollback on failure
    // (same pattern as addFolder - previously this fired persistCredentials()
    // without awaiting or catching it, so a failed write was invisible).
    const prevCreds = credentials;
    const updated = [...prevCreds, newCredential];
    setCredentials(updated);
    try {
      await persistCredentials(updated);
    } catch (err) {
      if (err instanceof QueuedOfflineError) {
        notifyQueuedOffline(t, addNotification, newCredential.service);
        return;
      }
      logger.error('[VaultContext] addCredential persist failed:', err);
      setCredentials(prevCreds);
      addNotification({
        type: 'persistence_failed',
        title: t('notifications.credentialSaveFailedTitle', 'Could not save credential'),
        message: t('notifications.credentialSaveFailedMessage', { service: newCredential.service, defaultValue: `Credential for "${newCredential.service}" could not be saved. Please try again.` }),
      });
      throw err;
    }
    addNotification({
      type: 'credential_added',
      title: t('notifications.credentialAddedTitle', 'Credential Added'),
      message: t('notifications.credentialAddedMessage', { service: newCredential.service, defaultValue: `New credential for "${newCredential.service}" has been added.` }),
      data: { credentialId: newCredential.id },
    });
  }, [t, addNotification, persistCredentials, credentials, daemonConnected]);

  const updateCredential = useCallback(async (updatedCredential: Credential) => {
    if (daemonConnected) {
      const { id, folderId, ...rest } = updatedCredential;
      await daemon.updateCredential(String(id), folderId ?? null, rest);
      setCredentials(prev => prev.map(c => c.id === updatedCredential.id ? updatedCredential : c));
      return;
    }
    const prevCreds = credentials;
    const updated = prevCreds.map(c => c.id === updatedCredential.id ? updatedCredential : c);
    setCredentials(updated);
    try {
      await persistCredentials(updated);
    } catch (err) {
      if (err instanceof QueuedOfflineError) {
        notifyQueuedOffline(t, addNotification, updatedCredential.service);
        return;
      }
      logger.error('[VaultContext] updateCredential persist failed:', err);
      setCredentials(prevCreds);
      addNotification({
        type: 'persistence_failed',
        title: t('notifications.credentialSaveFailedTitle', 'Could not save credential'),
        message: t('notifications.credentialSaveFailedMessage', { service: updatedCredential.service, defaultValue: `Credential for "${updatedCredential.service}" could not be saved. Please try again.` }),
      });
      throw err;
    }
  }, [credentials, persistCredentials, daemonConnected, t, addNotification]);

  const deleteCredential = useCallback(async (id: string | number) => {
    const credToDelete = credentials.find(c => c.id === id);
    if (daemonConnected) {
      await daemon.deleteCredential(String(id));
      setCredentials(prev => prev.filter(c => c.id !== id));
    } else {
      const prevCreds = credentials;
      const updated = prevCreds.filter(c => c.id !== id);
      setCredentials(updated);
      try {
        await persistCredentials(updated);
      } catch (err) {
        if (err instanceof QueuedOfflineError) {
          notifyQueuedOffline(t, addNotification, credToDelete?.service);
          return;
        }
        logger.error('[VaultContext] deleteCredential persist failed:', err);
        setCredentials(prevCreds);
        addNotification({
          type: 'persistence_failed',
          title: t('notifications.credentialDeleteFailedTitle', 'Could not delete credential'),
          message: t('notifications.credentialDeleteFailedMessage', { service: credToDelete?.service ?? '', defaultValue: `Credential for "${credToDelete?.service ?? ''}" could not be deleted. Please try again.` }),
        });
        throw err;
      }
    }
    if (credToDelete) {
      addNotification({
        type: 'credential_deleted',
        title: t('notifications.credentialDeletedTitle', 'Credential Deleted'),
        message: t('notifications.credentialDeletedMessage', { service: credToDelete.service, defaultValue: `Credential for "${credToDelete.service}" has been deleted.` }),
        data: { service: credToDelete.service },
      });
    }
  }, [credentials, t, addNotification, persistCredentials, daemonConnected]);

  const moveCredentials = useCallback(async (
    sourceFolderId: string,
    targetFolderId: string,
    credentialIds?: (string | number)[],
  ) => {
    if (daemonConnected) {
      const toMove = credentials.filter(c =>
        credentialIds ? credentialIds.includes(c.id) : c.folderId === sourceFolderId,
      );
      for (const cred of toMove) {
        const { id, folderId: _f, ...rest } = cred;
        await daemon.updateCredential(String(id), targetFolderId, rest);
      }
      setCredentials(prev => prev.map(c => {
        if (credentialIds) {
          return credentialIds.includes(c.id) ? { ...c, folderId: targetFolderId } : c;
        }
        return c.folderId === sourceFolderId ? { ...c, folderId: targetFolderId } : c;
      }));
      return;
    }
    const prevCreds = credentials;
    const updated = prevCreds.map(c => {
      if (credentialIds) {
        return credentialIds.includes(c.id) ? { ...c, folderId: targetFolderId } : c;
      }
      return c.folderId === sourceFolderId ? { ...c, folderId: targetFolderId } : c;
    });
    setCredentials(updated);
    try {
      await persistCredentials(updated);
    } catch (err) {
      if (err instanceof QueuedOfflineError) {
        notifyQueuedOffline(t, addNotification);
        return;
      }
      logger.error('[VaultContext] moveCredentials persist failed:', err);
      setCredentials(prevCreds);
      throw err;
    }
  }, [credentials, persistCredentials, daemonConnected, t, addNotification]);

  const updateAssetHolder = useCallback(async (newAssetHolder: AssetHolder) => {
    if (daemonConnected) {
      await daemon.updateAssetHolder(newAssetHolder);
      setAssetHolder(newAssetHolder);
      return;
    }
    const prevAssetHolder = assetHolder;
    setAssetHolder(newAssetHolder);
    try {
      await persistAssetHolder(newAssetHolder);
    } catch (err) {
      if (err instanceof QueuedOfflineError) {
        notifyQueuedOffline(t, addNotification);
        return;
      }
      logger.error('[VaultContext] updateAssetHolder persist failed:', err);
      setAssetHolder(prevAssetHolder);
      throw err;
    }
  }, [persistAssetHolder, daemonConnected, assetHolder, t, addNotification]);

  // ── Connect to daemon and load vault data ─────────────────────────────────

  const syncLock = useRef(false);
  const loadFromDaemon = useCallback(async () => {
    if (syncLock.current) return;
    syncLock.current = true;
    setIsLoading(true);
    try {
      if (!daemon.isConnected) {
        await daemon.connect();
      }
      const status = await daemon.getStatus();
      if (status.locked) {
        // A daemon reporting itself locked does NOT mean *this* session is
        // authenticated via the daemon — the daemon process can be reachable
        // (and its own vault locked) while the current user is authenticated
        // purely via server mode, holding a 36-char UUID token rather than a
        // real 64-char daemon session token. Blindly marking daemonConnected
        // true here routes every mutation (addFolder, addCredential, ...)
        // through the daemon RPC path with no valid session_token, which
        // fails with "session invalid" on every call. Only keep it true when
        // we already hold a genuine daemon token (matches the same check
        // used for the initial state above).
        const hasDaemonToken = keyStore.hasToken && keyStore.get()?.length === 64;
        setDaemonConnected(hasDaemonToken);
        setIsLoading(false);
        return;
      }

      const [folderRows, credMetas, assets] = await Promise.all([
        daemon.listFolders(),
        daemon.listCredentials(),
        daemon.getAssetHolder(),
      ]);

      // D-12: If we already have folders in memory (optimistically added), 
      // merge them with the daemon's list instead of a blind overwrite.
      setFolders(prev => {
        const daemonFolders = folderRows.map(rowToFolder);
        if (prev.length === 0) return daemonFolders;
        // Keep any folders that are in prev but not yet in daemonFolders (optimistic)
        // AND any that are in daemonFolders (authoritative)
        const daemonIds = new Set(daemonFolders.map(f => f.id));
        const optimistic = prev.filter(f => !daemonIds.has(f.id));
        const merged = [...daemonFolders, ...optimistic];
        return merged;
      });
      setAssetHolder(prev => ({ ...prev, ...assets }));
      setDaemonConnected(true);
      setIsLoading(false);
      setCredentialsLoading(true);

      // Phase B: fire all GetCredential requests concurrently. The daemon
      // processes them sequentially per-connection; the FIFO queue in
      // DaemonClient matches responses positionally — safe to Promise.all.
      const decrypted = await Promise.all(
        credMetas.map(async meta => {
          const cred = await daemon.getCredential(meta.id);
          return { ...cred, id: meta.id, folderId: meta.folder_id ?? '' } as Credential;
        }),
      );

      setCredentials(prev => {
        const daemonIds = new Set(decrypted.map(c => c.id));
        const optimistic = prev.filter(c => !daemonIds.has(c.id));
        return [...decrypted, ...optimistic];
      });
      // D-12: Only purge demo-mode localStorage if we successfully loaded data
      // from the daemon, to avoid deleting "leaked" local writes from a race.
      if (folderRows.length > 0 || decrypted.length > 0) {
        wipeDemoLocalStorage();
      }
    } catch (err: any) {
      if (err?.message?.includes('Session expired')) {
        keyStore.clear();
        window.dispatchEvent(new CustomEvent('sessionInvalid'));
        return;
      }
      // Daemon not running or vault locked - fall through to localStorage data
      setDaemonConnected(false);
    } finally {
      syncLock.current = false;
      setIsLoading(false);
      setCredentialsLoading(false);
    }
  }, []);

  useEffect(() => { loadFromDaemon(); }, [loadFromDaemon]);

  // Re-run loadFromDaemon after daemon.unlock() in Login.tsx (vault was locked at mount)
  useEffect(() => {
    const handler = () => { loadFromDaemon(); };
    window.addEventListener('daemonUnlocked', handler);
    return () => window.removeEventListener('daemonUnlocked', handler);
  }, [loadFromDaemon]);

  // Re-read all localStorage keys - used after Travel Mode toggle or demo re-login.
  const reloadLocal = useCallback(async () => {
    await performLoad();
  }, [performLoad]);

  // When the demo encryption key becomes available (after re-login on a reloaded page),
  // decrypt and reload vault data that was unreadable without the key.
  useEffect(() => {
    const handler = () => { reloadLocal().catch(() => {}); };
    window.addEventListener('demoKeyAvailable', handler);
    return () => window.removeEventListener('demoKeyAvailable', handler);
  }, [reloadLocal]);

  // ── Offline outbox: pending-count tracking + auto-flush on reconnect ─────────

  const [pendingSyncCount, setPendingSyncCount] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const refresh = () => { getQueueSize().then(n => { if (!cancelled) setPendingSyncCount(n); }); };
    refresh();
    window.addEventListener(OUTBOX_CHANGED_EVENT, refresh);
    return () => { cancelled = true; window.removeEventListener(OUTBOX_CHANGED_EVENT, refresh); };
  }, []);

  useEffect(() => {
    // Only server-mode writes are ever queued (see `_localWrite`), so only
    // server-mode needs to attempt flushing.
    if (daemonConnected) return;

    const attemptFlush = async () => {
      const size = await getQueueSize();
      if (size === 0) return;
      const { flushed, authExpired } = await flushOutbox();
      if (authExpired) {
        // The session died while offline (expired token, revoked cookie).
        // Leave the queue intact - AppLayout's sessionInvalid handler routes
        // to /login; the queue will flush again once re-authenticated.
        window.dispatchEvent(new CustomEvent('sessionInvalid'));
        return;
      }
      if (flushed.length > 0) {
        addNotification({
          type: 'info',
          title: t('notifications.syncCompleteTitle', 'Synced'),
          message: t('notifications.syncCompleteMessage', 'Your offline changes have been saved to the server.'),
        });
        // Pick up the authoritative server copy now that queued writes landed.
        reloadLocal().catch(() => {});
      }
    };

    window.addEventListener('online', attemptFlush);
    // `online`/`navigator.onLine` can be wrong (e.g. Wi-Fi with no real
    // internet access, a captive portal) - a low-frequency background check
    // catches reconnection in those cases without hammering the server.
    const interval = setInterval(attemptFlush, 60_000);
    attemptFlush();

    return () => {
      window.removeEventListener('online', attemptFlush);
      clearInterval(interval);
    };
  }, [daemonConnected, addNotification, t, reloadLocal]);

  return (
    <VaultContext.Provider value={{
      folders, credentials, assetHolder,
      isLoading, credentialsLoading, daemonConnected, vaultLocked,
      pendingSyncCount,
      addFolder, updateFolder, deleteFolder, reorderFolders,
      addCredential, updateCredential, deleteCredential, moveCredentials,
      updateAssetHolder,
      reload: loadFromDaemon,
      reloadLocal,
      persistFolders,
      persistCredentials,
    }}>
      {children}
    </VaultContext.Provider>
  );
}

export function useVault() {
  const context = useContext(VaultContext);
  if (context === undefined) {
    throw new Error('useVault must be used within a VaultProvider');
  }
  return context;
}
