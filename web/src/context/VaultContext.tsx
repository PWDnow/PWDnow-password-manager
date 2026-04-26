import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Folder, Credential, AssetHolder } from '../types';
import { useNotification } from './NotificationContext';
import { generateUUID } from '../utils/crypto';
import { daemon } from '../utils/daemonClient';
import { writeEncryptedLocal, readDecryptedLocal } from '../utils/localCrypto';

interface VaultContextType {
  folders: Folder[];
  credentials: Credential[];
  assetHolder: AssetHolder;
  isLoading: boolean;
  daemonConnected: boolean;
  addFolder: (folder: Folder) => Promise<void>;
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
}

const VaultContext = createContext<VaultContextType | undefined>(undefined);

// ── API fallbacks (demo / offline mode) ──────────────────────────────
const LOCAL_SUFFIX = '';

function wipeDemoLocalStorage(): void {}

// True only when the server has issued a session cookie pair for this browser.
// The CSRF cookie (_pwd_csrf) is the non-HttpOnly half — readable from JS — and is
// set only by /api/auth/login or /api/auth/register.  Daemon-authenticated users
// and unauthenticated visitors (e.g. the login page) never have this cookie.
function hasServerSession(): boolean {
  return document.cookie.split(';').some(c => c.trim().startsWith('_pwd_csrf='));
}

const _localRead = async (key: string): Promise<string | null> => {
  if (hasServerSession()) {
    // Server-side session present — read from the encrypted server store.
    try {
      const endpoint = key.replace('vault_', '').replace(LOCAL_SUFFIX, '');
      const url = `/api/vault/${endpoint.replace('_', '-')}`;
      const res = await fetch(url, { credentials: 'same-origin' });
      if (!res.ok) return null;
      const data = await res.json();
      return JSON.stringify(data);
    } catch {
      return null;
    }
  }
  // No server session (daemon mode, unauthenticated) — read from encrypted localStorage.
  return readDecryptedLocal(key);
};

const _localWrite = async (key: string, value: string): Promise<void> => {
  if (hasServerSession()) {
    // Server-side session present — persist to the encrypted server store.
    try {
      const endpoint = key.replace('vault_', '').replace(LOCAL_SUFFIX, '');
      const url = `/api/vault/${endpoint.replace('_', '-')}`;
      const csrfMatch = document.cookie.match(/(?:^|;\s*)_pwd_csrf=([^;]*)/);
      const csrf = csrfMatch ? decodeURIComponent(csrfMatch[1]) : '';
      await fetch(url, {
        method: 'PUT',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrf,
        },
        body: value,
      });
    } catch {
      // Ignore transient errors; React state is already updated.
    }
  } else {
    // No server session — persist to encrypted localStorage.
    await writeEncryptedLocal(key, value);
  }
};

const DEFAULT_FOLDERS: Folder[] = [
  { id: 'banking', label: 'Banking & Investment', description: 'Manage sensitive banking & investment credentials with high-precision security protocols.', iconName: 'Wallet' },
  { id: 'work',    label: 'Work Assets',          description: 'Manage sensitive work assets credentials with high-precision security protocols.',          iconName: 'Briefcase' },
  { id: 'social',  label: 'Social Media',          description: 'Manage sensitive social media credentials with high-precision security protocols.',          iconName: 'Globe' },
];

async function loadLocalFolders(): Promise<Folder[]> {
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
    } catch { /* ignore */ }
  }
  return [...DEFAULT_FOLDERS];
}

async function loadLocalCredentials(): Promise<Credential[]> {
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
    } catch { /* ignore */ }
  }
  return [];
}

async function loadLocalAssetHolder(): Promise<AssetHolder> {
  const saved = await _localRead(`vault_asset_holder${LOCAL_SUFFIX}`);
  if (saved) {
    try { return JSON.parse(saved); } catch { /* ignore */ }
  }
  return { emails: [], phoneNumbers: [], u2fKeys: [] };
}

// ── Helper: map daemon FolderRow → Folder type ────────────────────────────────

function rowToFolder(row: { id: string; name: string; description: string | null; icon_svg: string | null }): Folder {
  return {
    id:         row.id,
    label:      row.name,
    description: row.description ?? undefined,
    customSvg:  row.icon_svg ?? undefined,
  };
}

// ── Provider ──────────────────────────────────────────────────────────────────

export function VaultProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const { addNotification } = useNotification();

  // Start empty; populated async in useEffect (CRIT-03: decryption may be needed)
  const [folders,     setFolders]     = useState<Folder[]>([]);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [assetHolder, setAssetHolder] = useState<AssetHolder>({ emails: [], phoneNumbers: [], u2fKeys: [] });
  const [isLoading,        setIsLoading]        = useState(true);
  const [daemonConnected,  setDaemonConnected]  = useState(false);
  const [localLoaded,      setLocalLoaded]      = useState(false);

  // ── localStorage async load (offline / demo mode) ─────────────────────────

  useEffect(() => {
    // Load localStorage data asynchronously to support decryption (CRIT-03)
    Promise.all([loadLocalFolders(), loadLocalCredentials(), loadLocalAssetHolder()])
      .then(([f, c, a]) => {
        setFolders(f);
        setCredentials(c);
        setAssetHolder(a);
        setLocalLoaded(true);
      })
      .catch(() => {
        setFolders([...DEFAULT_FOLDERS]);
        setLocalLoaded(true);
      });
  }, []);

  // ── localStorage sync (offline / demo mode) ──────────────────────────────

  useEffect(() => {
    if (!daemonConnected && localLoaded) {
      _localWrite(`vault_folders${LOCAL_SUFFIX}`,      JSON.stringify(folders));
      _localWrite(`vault_credentials${LOCAL_SUFFIX}`,  JSON.stringify(credentials));
      _localWrite(`vault_asset_holder${LOCAL_SUFFIX}`, JSON.stringify(assetHolder));
    }
  }, [folders, credentials, assetHolder, daemonConnected, localLoaded]);

  // ── Cross-tab sync (demo/offline mode only) ──────────────────────────────

  useEffect(() => {
    if (daemonConnected) return; // daemon mode: daemon is source-of-truth
    const handler = (e: StorageEvent) => {
      if (e.key === `vault_folders${LOCAL_SUFFIX}` || e.key === `vault_credentials${LOCAL_SUFFIX}` || e.key === `vault_asset_holder${LOCAL_SUFFIX}`) {
        Promise.all([loadLocalFolders(), loadLocalCredentials(), loadLocalAssetHolder()])
          .then(([f, c, a]) => { setFolders(f); setCredentials(c); setAssetHolder(a); })
          .catch(() => {/* non-fatal */});
      }
    };
    window.addEventListener('storage', handler);
    return () => window.removeEventListener('storage', handler);
  }, [daemonConnected]);

  // ── Connect to daemon and load vault data ─────────────────────────────────

  const loadFromDaemon = useCallback(async () => {
    setIsLoading(true);
    try {
      if (!daemon.isConnected) {
        await daemon.connect();
      }
      const status = await daemon.getStatus();
      if (status.locked) {
        // Vault is locked — UI must call unlock first; keep localStorage data for now
        setDaemonConnected(true);
        setIsLoading(false);
        return;
      }

      const [folderRows, credMetas, assets] = await Promise.all([
        daemon.listFolders(),
        daemon.listCredentials(),
        daemon.getAssetHolder(),
      ]);

      // Decrypt all credentials (one at a time to avoid overwhelming the daemon)
      const decrypted: Credential[] = [];
      for (const meta of credMetas) {
        const cred = await daemon.getCredential(meta.id);
        decrypted.push({ ...cred, id: meta.id, folderId: meta.folder_id ?? '' });
      }

      setFolders(folderRows.map(rowToFolder));
      setCredentials(decrypted);
      setAssetHolder(assets);
      setDaemonConnected(true);

      // Daemon is now source of truth — purge all demo-mode localStorage data
      wipeDemoLocalStorage();
    } catch {
      // Daemon not running or vault locked — fall through to localStorage data
      setDaemonConnected(false);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => { loadFromDaemon(); }, [loadFromDaemon]);

  // Re-run loadFromDaemon after daemon.unlock() in Login.tsx (vault was locked at mount)
  useEffect(() => {
    const handler = () => { loadFromDaemon(); };
    window.addEventListener('daemonUnlocked', handler);
    return () => window.removeEventListener('daemonUnlocked', handler);
  }, [loadFromDaemon]);

  // ── Folder operations ─────────────────────────────────────────────────────

  const addFolder = useCallback(async (newFolder: Folder) => {
    if (daemonConnected) {
      const id = await daemon.addFolder(
        newFolder.label,
        newFolder.description,
        newFolder.customSvg,
      );
      setFolders(prev => [...prev, { ...newFolder, id }]);
    } else {
      setFolders(prev => [...prev, newFolder]);
    }
    addNotification({
      type: 'folder_created',
      title: t('notifications.folderCreatedTitle', 'Folder Created'),
      message: t('notifications.folderCreatedMessage', { name: newFolder.label, defaultValue: `New folder "${newFolder.label}" has been created.` }),
      data: { folderId: newFolder.id },
    });
  }, [daemonConnected, t, addNotification]);

  const updateFolder = useCallback(async (updatedFolder: Folder) => {
    if (daemonConnected) {
      await daemon.updateFolder(
        updatedFolder.id,
        updatedFolder.label,
        updatedFolder.description,
        updatedFolder.customSvg,
      );
    }
    setFolders(prev => prev.map(f => f.id === updatedFolder.id ? updatedFolder : f));
  }, [daemonConnected]);

  const deleteFolder = useCallback(async (folderId: string) => {
    const folderToDelete = folders.find(f => f.id === folderId);
    if (daemonConnected) {
      await daemon.deleteFolder(folderId);
    }
    setFolders(prev => prev.filter(f => f.id !== folderId));
    setCredentials(prev => prev.filter(c => c.folderId !== folderId));
    if (folderToDelete) {
      addNotification({
        type: 'credential_deleted',
        title: t('notifications.folderDeletedTitle', 'Folder Deleted'),
        message: t('notifications.folderDeletedMessage', { name: folderToDelete.label, defaultValue: `Folder "${folderToDelete.label}" and its contents have been deleted.` }),
        data: { folderId },
      });
    }
  }, [daemonConnected, folders, t, addNotification]);

  const reorderFolders = useCallback(async (newFolders: Folder[]) => {
    if (daemonConnected) {
      await daemon.reorderFolders(newFolders.map(f => f.id));
    }
    setFolders(newFolders);
  }, [daemonConnected]);

  // ── Credential operations ─────────────────────────────────────────────────

  const addCredential = useCallback(async (newCredential: Credential) => {
    if (daemonConnected) {
      const { id: _id, folderId, ...rest } = newCredential;
      const id = await daemon.addCredential(folderId ?? null, rest);
      setCredentials(prev => [...prev, { ...newCredential, id }]);
    } else {
      setCredentials(prev => [...prev, newCredential]);
    }
    addNotification({
      type: 'credential_added',
      title: t('notifications.credentialAddedTitle', 'Credential Added'),
      message: t('notifications.credentialAddedMessage', { service: newCredential.service, defaultValue: `New credential for "${newCredential.service}" has been added.` }),
      data: { credentialId: newCredential.id },
    });
  }, [daemonConnected, t, addNotification]);

  const updateCredential = useCallback(async (updatedCredential: Credential) => {
    if (daemonConnected) {
      const { id, folderId, ...rest } = updatedCredential;
      await daemon.updateCredential(String(id), folderId ?? null, rest);
    }
    setCredentials(prev => prev.map(c => c.id === updatedCredential.id ? updatedCredential : c));
  }, [daemonConnected]);

  const deleteCredential = useCallback(async (id: string | number) => {
    const credToDelete = credentials.find(c => c.id === id);
    if (daemonConnected) {
      await daemon.deleteCredential(String(id));
    }
    setCredentials(prev => prev.filter(c => c.id !== id));
    if (credToDelete) {
      addNotification({
        type: 'credential_deleted',
        title: t('notifications.credentialDeletedTitle', 'Credential Deleted'),
        message: t('notifications.credentialDeletedMessage', { service: credToDelete.service, defaultValue: `Credential for "${credToDelete.service}" has been deleted.` }),
        data: { service: credToDelete.service },
      });
    }
  }, [daemonConnected, credentials, t, addNotification]);

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
    }
    setCredentials(prev => prev.map(c => {
      if (credentialIds) {
        return credentialIds.includes(c.id) ? { ...c, folderId: targetFolderId } : c;
      }
      return c.folderId === sourceFolderId ? { ...c, folderId: targetFolderId } : c;
    }));
  }, [daemonConnected, credentials]);

  const updateAssetHolder = useCallback(async (newAssetHolder: AssetHolder) => {
    if (daemonConnected) {
      await daemon.updateAssetHolder(newAssetHolder);
    }
    setAssetHolder(newAssetHolder);
  }, [daemonConnected]);

  // Re-read all localStorage keys — used after Travel Mode toggle or demo re-login.
  const reloadLocal = useCallback(async () => {
    const [f, c, a] = await Promise.all([loadLocalFolders(), loadLocalCredentials(), loadLocalAssetHolder()]);
    setFolders(f);
    setCredentials(c);
    setAssetHolder(a);
  }, []);

  // When the demo encryption key becomes available (after re-login on a reloaded page),
  // decrypt and reload vault data that was unreadable without the key.
  useEffect(() => {
    const handler = () => { reloadLocal().catch(() => {}); };
    window.addEventListener('demoKeyAvailable', handler);
    return () => window.removeEventListener('demoKeyAvailable', handler);
  }, [reloadLocal]);

  return (
    <VaultContext.Provider value={{
      folders, credentials, assetHolder,
      isLoading, daemonConnected,
      addFolder, updateFolder, deleteFolder, reorderFolders,
      addCredential, updateCredential, deleteCredential, moveCredentials,
      updateAssetHolder,
      reload: loadFromDaemon,
      reloadLocal,
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
