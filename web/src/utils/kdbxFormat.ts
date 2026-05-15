import * as kdbxweb from 'kdbxweb';
import type { Credential, Folder } from '../types';
import type { ImportResult } from './importExport';

// ── Web Worker argon2 ──────────────────────────────────────────────────────────
// Runs the entire argon2 computation in a dedicated thread so the main thread
// stays responsive during KeePass database decryption (prevents "Page Unresponsive").

let _worker: Worker | null = null;
let _workerReqId = 0;
const _workerPending = new Map<number, { resolve: (buf: ArrayBuffer) => void; reject: (e: Error) => void }>();

function getArgon2Worker(): Worker {
  if (_worker) return _worker;
  _worker = new Worker(new URL('../workers/argon2.worker.ts', import.meta.url), { type: 'module' });
  _worker.onmessage = (e: MessageEvent) => {
    const { id, result, error } = e.data as { id: number; result?: ArrayBuffer; error?: string };
    const pending = _workerPending.get(id);
    if (!pending) return;
    _workerPending.delete(id);
    if (error) pending.reject(new Error(error));
    else pending.resolve(result!);
  };
  _worker.onerror = (e) => {
    for (const p of _workerPending.values()) p.reject(new Error(e.message));
    _workerPending.clear();
    _worker = null;
  };
  return _worker;
}

function argon2InWorker(
  password: ArrayBuffer, salt: ArrayBuffer,
  memory: number, iterations: number, length: number, parallelism: number, type: number,
): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    const id = ++_workerReqId;
    _workerPending.set(id, { resolve, reject });
    const w = getArgon2Worker();
    // Transfer the buffers to the worker (zero-copy)
    const pwCopy = password.slice(0);
    const saltCopy = salt.slice(0);
    w.postMessage({ id, password: pwCopy, salt: saltCopy, memory, iterations, length, parallelism, type }, [pwCopy, saltCopy]);
  });
}

kdbxweb.CryptoEngine.setArgon2Impl((
  password, salt, memory, iterations, length, parallelism, type, _version,
) => argon2InWorker(password, salt, memory, iterations, length, parallelism, type));

// ── KdbxImportResult ──────────────────────────────────────────────────────────

export interface KdbxImportResult extends ImportResult {
  folders: Folder[];
}

// ── importKdbx ────────────────────────────────────────────────────────────────

export async function importKdbx(buffer: ArrayBuffer, passphrase: string): Promise<KdbxImportResult> {
  const creds = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(passphrase));

  try {
    const db = await kdbxweb.Kdbx.load(buffer, creds);
    const resultCredentials: Credential[] = [];
    const resultFolders: Folder[] = [];
    const folderByName = new Map<string, string>();

    const getOrCreateFolder = (name: string): string => {
      const hit = folderByName.get(name);
      if (hit) return hit;
      const id = crypto.randomUUID();
      folderByName.set(name, id);
      resultFolders.push({ id, label: name, description: '', iconName: 'Folder' });
      return id;
    };

    const pushEntry = (entry: kdbxweb.KdbxEntry, folderId: string) => {
      const f = entry.fields;
      const pwField = f.get('Password');
      const password = (pwField instanceof kdbxweb.ProtectedValue) ? pwField.getText() : (pwField?.toString() ?? '');
      resultCredentials.push({
        id: crypto.randomUUID(),
        service: f.get('Title')?.toString() || 'Untitled',
        url: f.get('URL')?.toString() || '',
        username: f.get('UserName')?.toString() || '',
        password,
        description: f.get('Notes')?.toString() || undefined,
        status: 'active',
        statusColor: '#22c55e',
        logo: '',
        folderId,
        tags: [],
        lastUsed: 0,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      } as Credential);
    };

    const traverse = (group: kdbxweb.KdbxGroup, parentFolderName: string) => {
      const name = group.name?.toString() ?? parentFolderName;
      const folderId = name ? getOrCreateFolder(name) : '';
      for (const entry of group.entries) pushEntry(entry, folderId);
      for (const sub of group.groups) traverse(sub, name);
    };

    const root = db.getDefaultGroup();
    for (const entry of root.entries) pushEntry(entry, '');
    for (const sub of root.groups) traverse(sub, '');

    return { credentials: resultCredentials, folders: resultFolders, detectedFormat: 'keepass-kdbx' };
  } catch (err) {
    if (err instanceof Error) {
      const m = err.message;
      if (m === 'InvalidKey' || m.toLowerCase().includes('invalid key') || m.toLowerCase().includes('password')) {
        throw new Error('Invalid master password for KeePass database.');
      }
    }
    throw err;
  }
}
