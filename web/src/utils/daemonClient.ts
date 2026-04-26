import { encode, decode } from '@msgpack/msgpack';
import { keyStore } from '../crypto/keystore';
import type { Folder, Credential, AssetHolder } from '../types';

// ── Wire types (mirror the Rust protocol.rs enums) ───────────────────────────

interface FolderRow {
  id: string;
  name: string;
  description: string | null;
  icon_svg: string | null;
  sort_order: number;
  created_at: number;
  updated_at: number;
}

interface CredentialMeta {
  id: string;
  folder_id: string | null;
  schema_version: number;
  created_at: number;
  updated_at: number;
}

// Default per-RPC timeout. A hung daemon would otherwise freeze the UI.
// Callers that hit slow paths (HIBP filter load, profile picture upload) pass
// a larger value via the optional `timeoutMs` argument to request().
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
/** Timeout override for HIBP breach lookups — the daemon mmaps an 8 GB file. */
export const HIBP_REQUEST_TIMEOUT_MS = 120_000;

/** Obfuscated localStorage key for the forensic wipe ticket. */
export const WIPE_TICKET_KEY = '_sys_vk_tkv';

// ── DaemonClient ─────────────────────────────────────────────────────────────

/**
 * Communicates with the vault daemon via the WebSocket proxy at `/ws`.
 *
 * Protocol: each send is a binary WebSocket message containing a msgpack-encoded
 * `Request`.  The server responds with a single msgpack-encoded `Response`.
 * Requests are serialised (one in-flight at a time per connection).
 */
export class DaemonClient {
  #ws: WebSocket | null = null;
  /** FIFO queue of pending promise callbacks, matched to responses in order. */
  #queue: Array<{ resolve: (r: unknown) => void; reject: (e: Error) => void }> = [];
  #connected = false;

  // ── Connection ────────────────────────────────────────────────────────────

  /**
   * Open a WebSocket connection to the proxy.
   * Resolves when the socket is open, rejects if the connection fails within 5s.
   */
  connect(url = `ws://${location.host}/ws`): Promise<void> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      ws.binaryType = 'arraybuffer';
      // Tracks whether the connect() promise has already settled so that
      // late-firing onclose / ping-catch callbacks don't double-reject.
      let connectSettled = false;

      const settle = (fn: () => void) => {
        if (!connectSettled) { connectSettled = true; clearTimeout(timer); fn(); }
      };

      const timer = setTimeout(() => {
        settle(() => { ws.close(); reject(new Error('daemon connect timeout')); });
      }, 5000);

      ws.onerror = () => settle(() => reject(new Error('daemon WebSocket error')));

      ws.onclose = () => {
        this.#connected = false;
        settle(() => reject(new Error('daemon not reachable')));
        for (const pending of this.#queue) {
          pending.reject(new Error('daemon connection closed'));
        }
        this.#queue = [];
      };

      ws.onmessage = (event: MessageEvent<ArrayBuffer>) => {
        const next = this.#queue.shift();
        if (!next) return;
        try {
          const resp = decode(new Uint8Array(event.data)) as Record<string, unknown>;
          if (resp['status'] === 'Error') {
            // MED-06: sanitize error messages — map internal codes to generic UI messages
            // so internal state details are not leaked to the browser.
            const data = resp['data'] as Record<string, unknown> | undefined;
            const code = String(data?.['code'] ?? '');
            const SAFE_MESSAGES: Record<string, string> = {
              'InvalidPassword': 'Authentication failed.',
              'VaultLocked':     'Vault is locked. Please unlock first.',
              'SessionExpired':  'Session expired. Please unlock again.',
              'NotFound':        'Item not found.',
              'AlreadyExists':   'Item already exists.',
              'InvalidInput':    'Invalid input provided.',
            };
            const safeMsg = SAFE_MESSAGES[code] ?? 'Operation failed. Please try again.';
            next.reject(new Error(safeMsg));
          } else {
            next.resolve(resp);
          }
        } catch (e) {
          next.reject(e instanceof Error ? e : new Error(String(e)));
        }
      };

      ws.onopen = () => {
        this.#ws = ws;
        this.#connected = true;
        // Send a Ping to confirm the daemon unix-socket is actually reachable.
        // If the proxy accepted the WS but the daemon binary isn't running,
        // the socket error closes the WS before the pong arrives — onclose
        // fires, settle() rejects, and connect() throws just like a plain
        // connection failure, so callers fall through cleanly to localStorage.
        this.ping()
          .then(() => settle(() => resolve()))
          .catch(() => settle(() => reject(new Error('daemon not reachable'))));
      };
    });
  }

  get isConnected(): boolean {
    return this.#connected;
  }

  disconnect(): void {
    this.#ws?.close();
    this.#connected = false;
  }

  // ── Low-level request/response ────────────────────────────────────────────

  private request<T = unknown>(
    cmd: string,
    payload?: unknown,
    timeoutMs: number = DEFAULT_REQUEST_TIMEOUT_MS,
  ): Promise<T> {
    if (!this.#ws || !this.#connected) {
      return Promise.reject(new Error('daemon not connected'));
    }
    return new Promise<T>((resolve, reject) => {
      // On timeout we cannot simply drop the queued entry — responses are
      // matched FIFO by order, so removing one from the middle would misalign
      // every subsequent response. Instead we tear down the socket; the
      // onclose handler drains all pending with a generic rejection, and the
      // caller reconnects.
      const timer = setTimeout(() => {
        reject(new Error(`daemon request timed out: ${cmd}`));
        try { this.#ws?.close(4000, 'rpc timeout'); } catch { /* already closing */ }
      }, timeoutMs);
      this.#queue.push({
        resolve: (r) => { clearTimeout(timer); resolve(r as T); },
        reject:  (e) => { clearTimeout(timer); reject(e); },
      });
      const frame: Record<string, unknown> = { cmd };
      if (payload !== undefined) frame['payload'] = payload;
      this.#ws!.send(encode(frame));
    });
  }

  // ── Unauthenticated commands ──────────────────────────────────────────────

  async ping(): Promise<void> {
    await this.request('Ping');
  }

  async getStatus(): Promise<{ locked: boolean }> {
    const resp = await this.request<{ status: string; data: { locked: boolean } }>('GetStatus');
    return (resp as any).data as { locked: boolean };
  }

  /**
   * Unlock the vault with a master password (and optional YubiKey response).
   * Stores the returned session token in the SecureKeyStore.
   */
  async unlock(password: string, yubiKeyResponse?: Uint8Array): Promise<void> {
    const passwordBytes = Array.from(new TextEncoder().encode(password));
    const resp = await this.request<{ status: string; data: { session_token: string; wipe_ticket?: number[] } }>(
      'Unlock',
      {
        password: passwordBytes,
        yubikey_response: yubiKeyResponse ? Array.from(yubiKeyResponse) : null,
      },
    );
    const data = (resp as any).data as { session_token: string; wipe_ticket?: number[] };
    if (!data?.session_token) throw new Error('no session token in unlock response');
    // Persist wipe ticket for forensic wipe (even when vault later re-locks)
    if (data.wipe_ticket?.length) {
      const hex = Array.from(data.wipe_ticket, b => (b as number).toString(16).padStart(2, '0')).join('');
      localStorage.setItem(WIPE_TICKET_KEY, hex);
    }
    keyStore.store(data.session_token);
  }

  /**
   * Trigger a forensic self-destruct on the daemon side.
   * Passes the stored wipe ticket as capability proof.
   * The daemon overwrites vault files in 7 passes then exits.
   * Call wipeVaultData() immediately after to also clear the browser side.
   */
  async forensicWipe(ticket: Uint8Array): Promise<void> {
    try {
      await this.request(
        'ForensicWipe',
        { wipe_ticket: Array.from(ticket) },
        10_000,
      );
    } catch {
      // Daemon may close the connection before sending a response — that is
      // expected behaviour when the process exits during the wipe.
    }
  }

  // ── Authenticated commands ────────────────────────────────────────────────

  private get token(): string {
    const t = keyStore.get();
    if (!t) throw new Error('not authenticated');
    return t;
  }

  async lock(): Promise<void> {
    await this.request('Lock', { session_token: this.token });
    keyStore.clear();
  }

  // ── Folders ───────────────────────────────────────────────────────────────

  async listFolders(): Promise<FolderRow[]> {
    const resp = await this.request<{ status: string; data: Uint8Array }>(
      'ListFolders',
      { session_token: this.token },
    );
    const bytes = (resp as any).data as Uint8Array;
    return JSON.parse(new TextDecoder().decode(bytes)) as FolderRow[];
  }

  async addFolder(name: string, description?: string, iconSvg?: string): Promise<string> {
    const resp = await this.request<{ status: string; data: { id: string } }>(
      'AddFolder',
      {
        session_token: this.token,
        name,
        description: description ?? null,
        icon_svg: iconSvg ?? null,
      },
    );
    return (resp as any).data.id as string;
  }

  async updateFolder(id: string, name: string, description?: string, iconSvg?: string): Promise<void> {
    await this.request('UpdateFolder', {
      session_token: this.token,
      id,
      name,
      description: description ?? null,
      icon_svg: iconSvg ?? null,
    });
  }

  async deleteFolder(id: string, moveCredentialsTo?: string): Promise<void> {
    await this.request('DeleteFolder', {
      session_token: this.token,
      id,
      move_credentials_to: moveCredentialsTo ?? null,
    });
  }

  async reorderFolders(orderedIds: string[]): Promise<void> {
    await this.request('ReorderFolders', {
      session_token: this.token,
      ordered_ids: orderedIds,
    });
  }

  // ── Credentials ───────────────────────────────────────────────────────────

  async listCredentials(folderId?: string): Promise<CredentialMeta[]> {
    const resp = await this.request<{ status: string; data: Uint8Array }>(
      'ListCredentials',
      { session_token: this.token, folder_id: folderId ?? null },
    );
    const bytes = (resp as any).data as Uint8Array;
    return JSON.parse(new TextDecoder().decode(bytes)) as CredentialMeta[];
  }

  async getCredential(id: string): Promise<Credential> {
    const resp = await this.request<{ status: string; data: Uint8Array }>(
      'GetCredential',
      { session_token: this.token, id },
    );
    const bytes = (resp as any).data as Uint8Array;
    return JSON.parse(new TextDecoder().decode(bytes)) as Credential;
  }

  async addCredential(folderId: string | null, credential: Omit<Credential, 'id' | 'folderId'>): Promise<string> {
    const blob = new TextEncoder().encode(JSON.stringify(credential));
    const resp = await this.request<{ status: string; data: { id: string } }>(
      'AddCredential',
      {
        session_token: this.token,
        folder_id: folderId,
        blob: Array.from(blob),
      },
    );
    return (resp as any).data.id as string;
  }

  async updateCredential(id: string, folderId: string | null, credential: Partial<Credential>): Promise<void> {
    const blob = new TextEncoder().encode(JSON.stringify(credential));
    await this.request('UpdateCredential', {
      session_token: this.token,
      id,
      folder_id: folderId,
      blob: Array.from(blob),
    });
  }

  async deleteCredential(id: string): Promise<void> {
    await this.request('DeleteCredential', {
      session_token: this.token,
      id,
    });
  }

  // ── Asset Holder ──────────────────────────────────────────────────────────

  async getAssetHolder(): Promise<AssetHolder> {
    const resp = await this.request<{ status: string; data: Uint8Array }>(
      'GetAssetHolder',
      { session_token: this.token },
    );
    const bytes = (resp as any).data as Uint8Array;
    return JSON.parse(new TextDecoder().decode(bytes)) as AssetHolder;
  }

  async updateAssetHolder(assetHolder: AssetHolder): Promise<void> {
    const blob = new TextEncoder().encode(JSON.stringify(assetHolder));
    await this.request('UpdateAssetHolder', {
      session_token: this.token,
      blob: Array.from(blob),
    });
  }

  // ── OTP ───────────────────────────────────────────────────────────────────

  async getOtpCode(credentialId: string): Promise<string> {
    const resp = await this.request<{ status: string; data: string }>(
      'GetOtpCode',
      { session_token: this.token, credential_id: credentialId },
    );
    return (resp as any).data as string;
  }

  // ── User profile ──────────────────────────────────────────────────────────

  /**
   * Register a new vault: unlock (creating the vault if it doesn't exist),
   * then immediately store the user's profile inside the encrypted vault.
   */
  async register(
    password: string,
    firstName: string,
    lastName: string,
    email: string,
  ): Promise<void> {
    if (!this.#connected) await this.connect();
    await this.unlock(password);
    await this.updateProfile(firstName, lastName, email);
  }

  async changePassword(oldPassword: string, newPassword: string): Promise<void> {
    const oldBytes = Array.from(new TextEncoder().encode(oldPassword));
    const newBytes = Array.from(new TextEncoder().encode(newPassword));
    await this.request(
      'ChangePassword',
      {
        session_token: this.token,
        old_password: oldBytes,
        new_password: newBytes,
      },
    );
  }

  async verifyPassword(password: string): Promise<boolean> {
    const bytes = Array.from(new TextEncoder().encode(password));
    try {
      await this.request('VerifyMasterPassword', {
        session_token: this.token,
        password: bytes,
      });
      return true;
    } catch {
      return false;
    }
  }

  async getProfile(): Promise<{ firstName: string; lastName: string; email: string; profilePic?: Uint8Array; passwordChangedAt?: number }> {
    const resp = await this.request<{ status: string; data: Record<string, unknown> }>(
      'GetProfile',
      { session_token: this.token },
    );
    const d = (resp as any).data as Record<string, unknown>;
    return {
      firstName: d.first_name as string,
      lastName: d.last_name as string,
      email: d.email as string,
      profilePic: d.profile_pic ? new Uint8Array(d.profile_pic as number[]) : undefined,
      passwordChangedAt: d.password_changed_at ? (d.password_changed_at as number) * 1000 : undefined,
    };
  }

  async updateProfile(firstName: string, lastName: string, email: string): Promise<void> {
    await this.request('UpdateProfile', {
      session_token: this.token,
      first_name: firstName,
      last_name: lastName,
      email,
    });
  }

  async uploadProfilePicture(imageBytes: Uint8Array): Promise<void> {
    await this.request('UploadProfilePicture', {
      session_token: this.token,
      image_bytes: Array.from(imageBytes),
    });
  }

  // ── HIBP breach check ─────────────────────────────────────────────────────

  /**
   * Check a password against the local HIBP Cuckoo filter (architecture §4).
   * The plaintext never leaves this machine — the daemon hashes it with SHA-1
   * and queries the filter in-memory. We scrub the typed array before return.
   *
   * `filter_available: false` means the daemon has no filter file registered
   * (fresh install, no `hibp/build-filter.sh` run) — treat as "unknown", not
   * as a clean bill of health.
   */
  async checkPasswordBreached(password: string): Promise<{ pwned: boolean; filter_available: boolean }> {
    const enc = new TextEncoder().encode(password);
    try {
      const resp = await this.request<{ status: string; data: { pwned: boolean; filter_available: boolean } }>(
        'CheckPasswordBreached',
        { session_token: this.token, password_bytes: Array.from(enc) },
        HIBP_REQUEST_TIMEOUT_MS,
      );
      return (resp as any).data as { pwned: boolean; filter_available: boolean };
    } finally {
      enc.fill(0);
    }
  }
}

/** Singleton daemon client — one per browser tab. */
export const daemon = new DaemonClient();
