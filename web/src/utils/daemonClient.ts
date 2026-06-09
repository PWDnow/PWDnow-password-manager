import { logger } from './logger';
import { keyStore } from '../crypto/keystore';
import type { Folder, Credential, AssetHolder } from '../types';
import i18n from '../i18n';

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
const DEFAULT_REQUEST_TIMEOUT_MS = 60_000;
/** Timeout override for HIBP breach lookups - the daemon mmaps an 8 GB file. */
export const HIBP_REQUEST_TIMEOUT_MS = 120_000;

/** Obfuscated localStorage key for the forensic wipe ticket. */
export const WIPE_TICKET_KEY = '_sys_vk_tkv';

// ── UUID wire helpers ────────────────────────────────────────────────────────
//
// The daemon's protocol enums use Rust `Uuid`, which `rmp_serde` deserializes
// from a 16-byte array (msgpack bin or fixarray of u8). The JSON responses we
// get back from list-style commands carry UUIDs as RFC-4122 strings (because
// `serde_json` picks the human-readable form). To bridge that mismatch, every
// Uuid field crossing this boundary goes through `uuidStringToBytes` on the
// way out and `uuidBytesToString` on the way in — keeping the React side a
// pure-string world.

/** Parse "1394a7ac-4891-45d1-81ed-f2b33c0af637" -> 16-byte Uint8Array. */
function uuidStringToBytes(s: string): Uint8Array {
  const hex = s.replace(/-/g, '');
  if (hex.length !== 32 || !/^[0-9a-f]{32}$/i.test(hex)) {
    throw new Error(`invalid uuid: ${s}`);
  }
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Normalize whatever shape msgpack handed us back for a `Uuid` field
 * (Uint8Array | number[] | byte-keyed object) to its canonical RFC-4122 string.
 */
function uuidBytesToString(b: Uint8Array | number[] | Record<string, number>): string {
  const bytes = b instanceof Uint8Array
    ? b
    : Array.isArray(b)
      ? new Uint8Array(b)
      : new Uint8Array(Object.values(b));
  if (bytes.length !== 16) throw new Error(`invalid uuid bytes: ${bytes.length}`);
  const hex = Array.from(bytes, x => x.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Convert an outgoing string UUID (or empty/null sentinel) to the wire form. */
function uuidOut(id: string): Uint8Array {
  return uuidStringToBytes(id);
}

/** Same as `uuidOut` but tolerates null/empty as "no folder". */
function uuidOutOptional(id: string | null | undefined): Uint8Array | null {
  if (id === null || id === undefined || id === '') return null;
  return uuidStringToBytes(id);
}

// ── DaemonClient ─────────────────────────────────────────────────────────────

/**
 * Communicates with the vault daemon via the Express gRPC bridge at `POST /api/rpc`.
 *
 * Protocol: each call POSTs `{ method, payload }` as JSON; the server forwards it
 * to the daemon over gRPC (tonic, 127.0.0.1:50051) and returns `{ status, data }`.
 * Byte fields cross the JSON boundary as number arrays (see `convertArraysToBuffers`
 * / `convertBuffersToArrays` in server.js). `connect()`/`disconnect()` are no-ops
 * retained for API compatibility with the former WebSocket transport.
 */
export class DaemonClient {
  #connected = true;

  connect(): Promise<void> {
    return Promise.resolve();
  }

  get isConnected(): boolean {
    return this.#connected;
  }

  disconnect(): void {
    // No-op for HTTP
  }

  private async request<T = unknown>(
    cmd: string,
    payload?: unknown,
    timeoutMs: number = DEFAULT_REQUEST_TIMEOUT_MS,
  ): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch('/api/rpc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method: cmd, payload }),
        signal: controller.signal,
      });
      const data = await resp.json();
      if (data.status === 'Error') {
        const errData = data.data as Record<string, unknown> | undefined;
        const code = String(errData?.['code'] ?? '');
        const msg = String(errData?.['message'] ?? '');
        logger.warn('[Daemon Error]', { code, msg });
        
        const SAFE_MESSAGES: Record<string, string> = {
          'InvalidPassword': i18n.t('common.daemonAuthFailed',       'Authentication failed.'),
          'VaultLocked':     i18n.t('common.daemonVaultLocked',      'Vault is locked. Please unlock first.'),
          'SessionExpired':  i18n.t('common.daemonSessionExpired',   'Session expired. Please unlock again.'),
          'NotFound':        i18n.t('common.daemonNotFound',         'Item not found.'),
          'AlreadyExists':   i18n.t('common.daemonAlreadyExists',    'Item already exists.'),
          'InvalidInput':    i18n.t('common.daemonInvalidInput',     'Invalid input provided.'),
          '401':             i18n.t('common.daemonSessionExpired',   'Session expired. Please unlock again.'),
        };
        const safeMsg = SAFE_MESSAGES[code] ?? i18n.t('common.daemonOperationFailed', 'Operation failed. Please try again.');
        throw new Error(safeMsg);
      }
      return data as T;
    } catch (e: any) {
      if (e.name === 'AbortError') {
        throw new Error(`daemon request timed out: ${cmd}`);
      }
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }

  private async rpc<T>(cmd: string, payload?: unknown, timeoutMs?: number): Promise<T> {
    const resp = await this.request<{ status: string; data: T }>(cmd, payload, timeoutMs);
    return resp.data;
  }

  private async rpcJson<T>(cmd: string, payload?: unknown): Promise<T> {
    const data = await this.rpc<Uint8Array | number[]>(cmd, payload);
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    return JSON.parse(new TextDecoder().decode(bytes)) as T;
  }

  // ── Unauthenticated commands ──────────────────────────────────────────────

  async ping(): Promise<void> {
    await this.request('Ping');
  }

  async getStatus(): Promise<{ locked: boolean }> {
    return this.rpc<{ locked: boolean }>('GetStatus');
  }

  async getLoginHints(): Promise<{
    password_login_enabled: boolean;
    totp_enabled: boolean;
    email_otp_enabled: boolean;
    recovery_key_active: boolean;
    fido2_ids: Uint8Array[];
  }> {
    type Raw = { password_login_enabled: boolean; totp_enabled: boolean; email_otp_enabled: boolean; recovery_key_active: boolean; fido2_ids: number[][] };
    const d = await this.rpc<Raw>('GetLoginHints');
    return {
      password_login_enabled: d.password_login_enabled,
      totp_enabled: d.totp_enabled,
      email_otp_enabled: d.email_otp_enabled,
      recovery_key_active: !!d.recovery_key_active,
      fido2_ids: d.fido2_ids.map((arr) => new Uint8Array(arr)),
    };
  }

  async getPasskeyChallenge(): Promise<Uint8Array> {
    return new Uint8Array(await this.rpc<number[]>('GetPasskeyChallenge'));
  }

  async unlockWithPasskey(
    credentialId: Uint8Array, authData: Uint8Array, signature: Uint8Array,
    clientDataHash: Uint8Array,
  ): Promise<void> {
    type UnlockData = { session_token: string; wipe_ticket?: number[] };
    const data = await this.rpc<UnlockData>('UnlockWithPasskey', {
      credential_id: Array.from(credentialId),
      auth_data: Array.from(authData),
      signature: Array.from(signature),
      client_data_hash: Array.from(clientDataHash),
    });
    if (!data?.session_token) throw new Error('no session token in unlock response');
    if (data.wipe_ticket?.length) {
      localStorage.setItem(WIPE_TICKET_KEY, data.wipe_ticket.map(b => b.toString(16).padStart(2, '0')).join(''));
    }
    keyStore.store(data.session_token);
  }

  /**
   * Unlock the vault with a master password (and optional YubiKey response).
   * Stores the returned session token in the SecureKeyStore.
   */
  async unlock(password: string, yubiKeyResponse?: Uint8Array): Promise<void> {
    type UnlockData = { session_token: string; wipe_ticket?: number[] };
    const data = await this.rpc<UnlockData>('Unlock', {
      password: Array.from(new TextEncoder().encode(password)),
      yubikey_response: yubiKeyResponse ? Array.from(yubiKeyResponse) : null,
    });
    if (!data?.session_token) throw new Error('no session token in unlock response');
    if (data.wipe_ticket?.length) {
      localStorage.setItem(WIPE_TICKET_KEY, data.wipe_ticket.map(b => b.toString(16).padStart(2, '0')).join(''));
    }
    keyStore.store(data.session_token);
  }

  // ── Quick Unlock ──────────────────────────────────────────────────────────

  async quickUnlockEnroll(password: string, dbk: Uint8Array): Promise<void> {
    await this.request('QuickUnlockEnroll', {
      session_token: this.token,
      password: Array.from(new TextEncoder().encode(password)),
      dbk: Array.from(dbk),
    });
  }

  async quickUnlock(dbk: Uint8Array): Promise<void> {
    type UnlockData = { session_token: string; wipe_ticket?: number[] };
    const data = await this.rpc<UnlockData>('QuickUnlock', {
      dbk: Array.from(dbk),
    });
    if (!data?.session_token) throw new Error('no session token in unlock response');
    if (data.wipe_ticket?.length) {
      localStorage.setItem(WIPE_TICKET_KEY, data.wipe_ticket.map(b => b.toString(16).padStart(2, '0')).join(''));
    }
    keyStore.store(data.session_token);
  }

  async quickUnlockRevoke(): Promise<void> {
    await this.request('QuickUnlockRevoke', {
      session_token: this.token,
    });
  }

  async enrollRecoveryKey(recoveryKey: string): Promise<void> {
    await this.request('EnrollRecoveryKey', {
      session_token: this.token,
      recovery_key: Array.from(new TextEncoder().encode(recoveryKey)),
    });
  }

  async unlockWithRecoveryKey(recoveryKey: string): Promise<void> {
    type UnlockData = { session_token: string; wipe_ticket?: number[] };
    const data = await this.rpc<UnlockData>('UnlockWithRecoveryKey', {
      recovery_key: Array.from(new TextEncoder().encode(recoveryKey)),
    });
    if (!data?.session_token) throw new Error('no session token in recovery unlock response');
    if (data.wipe_ticket?.length) {
      localStorage.setItem(WIPE_TICKET_KEY, data.wipe_ticket.map(b => b.toString(16).padStart(2, '0')).join(''));
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
      // Daemon may close the connection before sending a response - that is
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

  // ── FIDO2 / Passkey management ────────────────────────────────────────────

  async listFido2Keys(): Promise<Record<string, unknown>[]> {
    return this.rpcJson<Record<string, unknown>[]>('ListFido2Keys', { session_token: this.token });
  }

  async registerFido2(devicePath: string, name?: string, residentKey: boolean = false): Promise<string> {
    const data = await this.rpc<{ id: string }>('RegisterFido2', {
      session_token: this.token,
      device_path: devicePath,
      name: name ?? null,
      resident_key: residentKey,
    });
    return data.id;
  }

  async removeFido2(id: string): Promise<void> {
    await this.request('RemoveFido2', {
      session_token: this.token,
      id,
    });
  }

  async listFido2Devices(): Promise<string[]> {
    return this.rpc<string[]>('ListFido2Devices');
  }

  // ── Folders ───────────────────────────────────────────────────────────────

  async listFolders(): Promise<FolderRow[]> {
    return this.rpcJson<FolderRow[]>('ListFolders', { session_token: this.token });
  }

  async addFolder(name: string, description?: string, iconSvg?: string): Promise<string> {
    // Response::Created.id is a raw 16-byte Uuid in msgpack — normalize back to string.
    const data = await this.rpc<{ id: Uint8Array | number[] | Record<string, number> }>('AddFolder', {
      session_token: this.token,
      name,
      description: description ?? null,
      icon_svg: iconSvg ?? null,
    });
    return uuidBytesToString(data.id);
  }

  async updateFolder(id: string, name: string, description?: string, iconSvg?: string): Promise<void> {
    await this.request('UpdateFolder', {
      session_token: this.token,
      id: uuidOut(id),
      name,
      description: description ?? null,
      icon_svg: iconSvg ?? null,
    });
  }

  async deleteFolder(id: string, moveCredentialsTo?: string): Promise<void> {
    await this.request('DeleteFolder', {
      session_token: this.token,
      id: uuidOut(id),
      move_credentials_to: uuidOutOptional(moveCredentialsTo),
    });
  }

  async reorderFolders(orderedIds: string[]): Promise<void> {
    await this.request('ReorderFolders', {
      session_token: this.token,
      ordered_ids: orderedIds.map(uuidOut),
    });
  }

  // ── Credentials ───────────────────────────────────────────────────────────

  async listCredentials(folderId?: string): Promise<CredentialMeta[]> {
    return this.rpcJson<CredentialMeta[]>('ListCredentials', {
      session_token: this.token,
      folder_id: uuidOutOptional(folderId),
    });
  }

  async getCredential(id: string): Promise<Credential> {
    return this.rpcJson<Credential>('GetCredential', {
      session_token: this.token,
      id: uuidOut(id),
    });
  }

  async addCredential(folderId: string | null, credential: Omit<Credential, 'id' | 'folderId'>): Promise<string> {
    const data = await this.rpc<{ id: Uint8Array | number[] | Record<string, number> }>('AddCredential', {
      session_token: this.token,
      folder_id: uuidOutOptional(folderId),
      blob: Array.from(new TextEncoder().encode(JSON.stringify(credential))),
    });
    return uuidBytesToString(data.id);
  }

  async updateCredential(id: string, folderId: string | null, credential: Partial<Credential>): Promise<void> {
    const blob = new TextEncoder().encode(JSON.stringify(credential));
    await this.request('UpdateCredential', {
      session_token: this.token,
      id: uuidOut(id),
      folder_id: uuidOutOptional(folderId),
      blob: Array.from(blob),
    });
  }

  async deleteCredential(id: string): Promise<void> {
    await this.request('DeleteCredential', {
      session_token: this.token,
      id: uuidOut(id),
    });
  }

  // ── Asset Holder ──────────────────────────────────────────────────────────

  async getAssetHolder(): Promise<AssetHolder> {
    return this.rpcJson<AssetHolder>('GetAssetHolder', { session_token: this.token });
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
    return this.rpc<string>('GetOtpCode', {
      session_token: this.token,
      credential_id: uuidOut(credentialId),
    });
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
    // unlock() created the vault (if missing) and stored the session token.
    // Write the profile fields so they survive a future relogin — without this
    // call, UserContext.reloadProfile() sees empty strings forever.
    try {
      await this.updateProfile(firstName, lastName, email);
    } catch (e) {
      // Non-fatal: registration's primary goal (vault creation + unlock) is
      // already done. The user can still set their profile from Settings.
      logger.warn('[daemon.register] profile write failed:', e);
    }
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

  async verifyPassword(password: string): Promise<void> {
    const bytes = Array.from(new TextEncoder().encode(password));
    await this.request('VerifyMasterPassword', {
      session_token: this.token,
      password: bytes,
    });
  }

  async updateLoginPolicy(passwordEnabled: boolean, totpEnabled: boolean, emailOtpEnabled: boolean, duressMaxAttempts: number = 0): Promise<void> {
    await this.request('UpdateLoginPolicy', {
      session_token: this.token,
      password_login_enabled: passwordEnabled,
      totp_enabled: totpEnabled,
      email_otp_enabled: emailOtpEnabled,
      duress_max_attempts: duressMaxAttempts,
    });
  }

  async getProfile(): Promise<{ firstName: string; lastName: string; email: string; profilePic?: Uint8Array; passwordChangedAt?: number }> {
    const d = await this.rpc<Record<string, unknown>>('GetProfile', { session_token: this.token });
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

  async removeProfilePicture(): Promise<void> {
    await this.request('RemoveProfilePicture', { session_token: this.token });
  }

  // ── HIBP breach check ─────────────────────────────────────────────────────

  /**
   * Check a password against the local HIBP Cuckoo filter (architecture §4).
   * The plaintext never leaves this machine - the daemon hashes it with SHA-1
   * and queries the filter in-memory. We scrub the typed array before return.
   *
   * `filter_available: false` means the daemon has no filter file registered
   * (fresh install, no `hibp/build-filter.sh` run) - treat as "unknown", not
   * as a clean bill of health.
   */
  async checkPasswordBreached(password: string): Promise<{ pwned: boolean; filter_available: boolean }> {
    const enc = new TextEncoder().encode(password);
    try {
      return await this.rpc<{ pwned: boolean; filter_available: boolean }>(
        'CheckPasswordBreached',
        { session_token: this.token, password_bytes: Array.from(enc) },
        HIBP_REQUEST_TIMEOUT_MS,
      );
    } finally {
      enc.fill(0);
    }
  }
}

/** Singleton daemon client - one per browser tab. */
export const daemon = new DaemonClient();
