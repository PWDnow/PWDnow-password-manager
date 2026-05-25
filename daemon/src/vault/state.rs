use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::HashMap;

use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::auth::session::{Session, SessionStore, DEFAULT_TTL_SECS};
use crate::auth::fido2::DeviceBackend; // needed to call trait method verify_assertion
use crate::crypto::{kdf, xchacha20, secure_store::LockedKey};
use crate::error::VaultError;
use crate::ipc::protocol;
use crate::vault::{audit, db, lockout::LockoutTracker};

pub const IDLE_TIMEOUT_SECS: u64 = 15 * 60;

fn default_true() -> bool { true }

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PasskeySidecarEntry {
    pub credential_id_hex: String,
    pub encrypted_vmk_copy: String,
    pub vmk_copy_nonce: String,
    /// COSE public key stored for offline assertion signature verification (F1-FIX).
    /// None for entries written before this fix; such entries require re-registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pub_key_cbor_hex: Option<String>,
    #[serde(default)]
    pub sign_count: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PqcSidecarEntry {
    pub credential_id_hex: String,
    pub verifying_key_hex: String, // ML-DSA-87
    pub dk_seed_hex: String,       // Seed for ML-KEM-1024 DK (encrypted with VMK)
    pub dk_nonce_hex: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QuickUnlockCred {
    pub credential_id_hex: String,
    pub enc_kek: String,
    pub nonce: String,
    pub pub_key_cbor_hex: String,
    pub created_at: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RecoveryKeySidecarEntry {
    pub encrypted_vmk_copy: String,
    pub vmk_copy_nonce: String,
    pub salt: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultHeader {
    pub vault_uuid: String,
    pub argon2_salt: String,
    pub argon2_m_cost: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
    #[serde(default)]
    pub kem_suite: u8,
    pub encrypted_vmk: String,
    pub vmk_nonce: String,
    #[serde(default = "default_true")]
    pub password_login_enabled: bool,
    #[serde(default)]
    pub totp_enabled: bool,
    #[serde(default)]
    pub email_otp_enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub strict_pqc_mode: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkey_credentials: Vec<PasskeySidecarEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pqc_credentials: Vec<PqcSidecarEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quick_unlock_credentials: Vec<QuickUnlockCred>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key_copy: Option<RecoveryKeySidecarEntry>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub duress_max_attempts: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub wipe_ticket_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_hmac: Option<String>,
}

fn is_zero(num: &u32) -> bool { *num == 0 }
fn is_false(b: &bool) -> bool { !*b }

pub struct DaemonState {
    pub sessions: SessionStore,
    pub db: Mutex<Option<Connection>>,
    vmk: RwLock<Option<LockedKey>>,
    pub vault_uuid: Mutex<Option<String>>,
    wipe_ticket: Mutex<Option<Vec<u8>>>,
    pub vault_path: PathBuf,
    pub last_activity: Arc<AtomicU64>,
    // M-01 fix: multi-slot time-bounded challenge store.
    // Maps issued 32-byte challenge -> expiry Instant.
    challenges: Mutex<HashMap<[u8; 32], Instant>>,
    pub pre_auth_count: Arc<std::sync::atomic::AtomicU32>,
    pending_audit: Mutex<Vec<(String, Option<String>)>>,
    // Key is uid only — lockout persists across WebSocket reconnections
    pub lockout: LockoutTracker,
    // SLA P4: dispatch-driven watchdog. The free-running watchdog ticker
    // checks these atomics before sending WATCHDOG=1 — if requests are in
    // flight but none has completed in `WATCHDOG_STALL_SECS`, the daemon is
    // wedged and the ticker skips the heartbeat, letting systemd restart us.
    pub in_flight_requests: Arc<AtomicU64>,
    pub last_completion_secs: Arc<AtomicU64>,
}

impl DaemonState {
    pub fn new(vault_path: PathBuf) -> Self {
        let now = now_secs();
        Self {
            sessions: SessionStore::new(),
            db: Mutex::new(None),
            vmk: RwLock::new(None),
            vault_uuid: Mutex::new(None),
            wipe_ticket: Mutex::new(None),
            vault_path,
            last_activity: Arc::new(AtomicU64::new(now)),
            challenges: Mutex::new(HashMap::new()),
            pre_auth_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            pending_audit: Mutex::new(Vec::new()),
            lockout: LockoutTracker::new(),
            // Initialise to "we just completed something" so an idle daemon
            // at boot doesn't immediately appear wedged.
            in_flight_requests: Arc::new(AtomicU64::new(0)),
            last_completion_secs: Arc::new(AtomicU64::new(now)),
        }
    }

    pub fn new_biometric_challenge(&self) -> [u8; 32] {
        let mut chal = [0u8; 32]; OsRng.fill_bytes(&mut chal);
        let mut map = self.challenges.lock().unwrap();
        // Prune expired challenges to keep map small.
        let now = Instant::now();
        map.retain(|_, &mut exp| exp > now);
        // Limit map size to 1000 concurrent challenges globally.
        if map.len() < 1000 {
            map.insert(chal, now + Duration::from_secs(600)); // 10 min TTL
        }
        chal
    }

    pub fn new_passkey_challenge(&self) -> [u8; 32] { self.new_biometric_challenge() }
    pub fn new_pqc_challenge(&self) -> [u8; 32] { self.new_biometric_challenge() }
    pub fn new_quick_unlock_challenge(&self) -> [u8; 32] { self.new_biometric_challenge() }

    fn consume_challenge(&self, chal: &[u8; 32]) -> bool {
        let mut map = self.challenges.lock().unwrap();
        let now = Instant::now();
        if let Some(exp) = map.remove(chal) {
            if exp > now { return true; }
        }
        false
    }

    pub fn is_locked(&self) -> bool {
        self.vmk.read().unwrap().is_none()
    }

    pub fn get_login_hints(&self) -> Result<protocol::Response, VaultError> {
        if !self.vault_path.exists() {
            return Ok(protocol::Response::LoginHints {
                password_login_enabled: true,
                totp_enabled: false,
                email_otp_enabled: false,
                recovery_key_active: false,
                fido2_ids: vec![],
                quick_unlock_credentials: vec![],
            });
        }
        let header = self.read_header()?;
        Ok(protocol::Response::LoginHints {
            password_login_enabled: header.password_login_enabled,
            totp_enabled: header.totp_enabled,
            email_otp_enabled: header.email_otp_enabled,
            recovery_key_active: header.recovery_key_copy.is_some(),
            fido2_ids: header.passkey_credentials.iter()
                .map(|e| hex::decode(&e.credential_id_hex).unwrap_or_default())
                .collect(),
            quick_unlock_credentials: header.quick_unlock_credentials,
        })
    }

    pub fn audit_log(&self, action: &str, resource: Option<&str>) -> Result<(), VaultError> {
        self.with_vmk(|vmk| {
            if let Some(conn) = self.db.lock().unwrap().as_ref() {
                let _ = audit::log(conn, vmk, action, resource);
            }
            Ok(())
        })
    }

    fn check_unlock_lockout(&self, uid: u32, _conn_id: u64) -> Result<(), VaultError> {
        self.lockout.check_unlock_lockout(uid)
    }

    pub fn record_failed_unlock(&self, uid: u32, _conn_id: u64) {
        {
            let mut pending = self.pending_audit.lock().unwrap();
            if pending.len() < 100 {
                pending.push((audit::ACTION_UNLOCK_FAILED.to_string(), None));
            }
        }
        let count = self.lockout.record_failed_unlock(uid);

        // NIST SP 800-88 Rev. 2 — trigger wipe if failure threshold reached.
        if let Ok(header) = self.read_header() {
            if header.duress_max_attempts > 0 && count >= header.duress_max_attempts {
                let _ = self.forensic_wipe_internal();
            }
        }
    }

    /// M-3 fix: prune expired entries from lockout_map. Called from the
    /// background ticker in socket.rs so idle attackers don't accumulate
    /// forever (check_unlock_lockout only prunes for accounts that retry).
    pub fn prune_lockout_map(&self) {
        self.lockout.prune();
    }

    pub fn reset_unlock_counter(&self, uid: u32, _conn_id: u64) {
        self.lockout.reset_lockout(uid);
        
        // M-62 fix: only drain and log if the vault is actually open.
        // Otherwise, keep the events in pending_audit until the next successful unlock.
        if !self.is_locked() {
            let pending: Vec<_> = self.pending_audit.lock().unwrap().drain(..).collect();
            if !pending.is_empty() {
                let _ = self.with_vmk(|vmk| {
                    if let Some(conn) = self.db.lock().unwrap().as_ref() {
                        for (action, resource) in pending {
                            let _ = audit::log(conn, vmk, &action, resource.as_deref());
                        }
                    }
                    Ok(())
                });
            }
        }
    }

    pub fn verify_master_password(&self, password: &[u8], uid: u32, conn_id: u64) -> Result<(), VaultError> {
        self.check_unlock_lockout(uid, conn_id)?;
        let res = self.verify_master_password_inner(password);
        if res.is_err() { self.record_failed_unlock(uid, conn_id); }
        res
    }

    fn verify_master_password_inner(&self, password: &[u8]) -> Result<(), VaultError> {
        if password.len() > 1024 { return Err(VaultError::Auth("password too long".into())); }
        let header = self.read_header()?;
        let salt_bytes = hex::decode(&header.argon2_salt).map_err(|e| { tracing::error!("salt decode fail"); VaultError::Crypto("invalid salt".into()) })?;
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&salt_bytes);
        let kek_buf = kdf::derive_kek(password, None, &salt, header.argon2_m_cost, header.argon2_t_cost, header.argon2_p_cost)?;
        let kek: [u8; 32] = kek_buf.as_bytes()[..32].try_into().unwrap();
        let ct = hex::decode(&header.encrypted_vmk).map_err(|e| { tracing::error!("vmk decode fail"); VaultError::Crypto("invalid vmk".into()) })?;
        let nonce_vec = hex::decode(&header.vmk_nonce).map_err(|e| { tracing::error!("nonce decode fail"); VaultError::Crypto("invalid nonce".into()) })?;
        
        let mut vmk_plain = match nonce_vec.len() {
            12 => {
                let nonce: [u8; 12] = nonce_vec.try_into().unwrap();
                crate::crypto::aes_gcm::decrypt(&kek, &ct, &nonce, b"vmk-aad-v1").map_err(|e| VaultError::Auth(format!("aes_gcm fail: {:?}", e)))?
            }
            24 => {
                let nonce: [u8; 24] = nonce_vec.try_into().unwrap();
                crate::crypto::xchacha20::decrypt(&kek, &ct, &nonce, b"vmk-aad-v1").map_err(|e| VaultError::Auth(format!("xchacha20 fail: {:?}", e)))?
            }
            _ => { return Err(VaultError::Auth("invalid vmk_nonce length".into())); }
        };

        let result = self.with_vmk(|k| {
            if k != vmk_plain.as_slice() {
                return Err(VaultError::Auth("vmk_plain mismatch".into()));
            }
            Ok(())
        });
        if result.is_err() {
            return Err(VaultError::Auth(format!("with_vmk fail: {:?}", result)));
        }
        vmk_plain.zeroize();
        Ok(())
    }

    pub fn change_password(&self, old_password: &[u8], new_password: &[u8], yk: Option<&[u8; 20]>, uid: u32, conn_id: u64) -> Result<(), VaultError> {
        self.check_unlock_lockout(uid, conn_id)?;
        let res = self.change_password_inner(old_password, new_password, yk);
        if res.is_err() { self.record_failed_unlock(uid, conn_id); }
        res
    }

    fn change_password_inner(&self, old_password: &[u8], new_password: &[u8], yk: Option<&[u8; 20]>) -> Result<(), VaultError> {
        if new_password.len() < 12 { return Err(VaultError::Auth("new password too short".into())); }
        if new_password.len() > 1024 { return Err(VaultError::Auth("new password too long".into())); }
        self.verify_master_password_inner(old_password)?;
        let mut new_salt = [0u8; 32]; OsRng.fill_bytes(&mut new_salt);
        let mut new_vmk = [0u8; 32]; OsRng.fill_bytes(&mut new_vmk);
        let (m, t, p) = crate::crypto::kdf_tune::tune_params();
        let new_kek_buf = kdf::derive_kek(new_password, yk, &new_salt, m, t, p)?;
        let new_kek: [u8; 32] = new_kek_buf.as_bytes()[..32].try_into().unwrap();
        let (new_enc_vmk, new_nonce) = crate::crypto::aes_gcm::encrypt(&new_kek, &new_vmk, b"vmk-aad-v1")?;

        let current_vmk = self.with_vmk(|k| Ok(*k))?;
        let old_sc_key = Self::sqlcipher_key(&current_vmk);
        let new_sc_key = Self::sqlcipher_key(&new_vmk);

        {
            let mut guard = self.db.lock().unwrap();
            let conn = guard.as_mut().ok_or_else(|| VaultError::Auth("vault is locked".into()))?;
            db::rekey_vault(conn, &old_sc_key, &new_sc_key)?;
            conn.execute("INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('password_changed_at', ?1)", params![now_secs()])?;

            // H-06: re-read sidecar INSIDE the lock
            let mut header = self.read_header()?;
            header.argon2_salt = hex::encode(new_salt);
            header.argon2_m_cost = m; header.argon2_t_cost = t; header.argon2_p_cost = p;
            header.encrypted_vmk = hex::encode(new_enc_vmk);
            header.vmk_nonce = hex::encode(new_nonce);
            header.passkey_credentials.clear();
            header.pqc_credentials.clear();
            header.quick_unlock_credentials.clear();
            self.write_header(&header)?;
        }

        let mut locked = LockedKey::new(32)?;
        locked.as_bytes_mut().copy_from_slice(&new_vmk);
        *self.vmk.write().unwrap() = Some(locked);
        self.touch();
        Ok(())
    }
    pub fn touch(&self) { self.last_activity.store(now_secs(), Ordering::Relaxed); }
    pub fn idle_secs(&self) -> u64 { now_secs().saturating_sub(self.last_activity.load(Ordering::Relaxed)) }

    fn meta_path(&self) -> PathBuf {
        let mut p = self.vault_path.clone();
        let name = p.file_name().map(|n| format!("{}.meta", n.to_string_lossy())).unwrap_or_else(|| "vault.db.meta".into());
        p.set_file_name(name); p
    }

    pub fn read_header(&self) -> Result<VaultHeader, VaultError> {
        // M-44 fix: use O_NOFOLLOW to prevent symlink traversal attacks.
        use std::os::unix::fs::OpenOptionsExt;
        use std::io::Read;
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.meta_path())?;
        let mut data = String::new();
        f.read_to_string(&mut data)?;
        serde_json::from_str(&data).map_err(|e| VaultError::Crypto(format!("invalid header: {e}")))
    }

    pub fn write_header(&self, header: &VaultHeader) -> Result<(), VaultError> {
        let mut header = header.clone();
        // If we have a VMK, we must update the HMAC.
        if let Some(vmk) = self.vmk.read().unwrap().as_ref() {
            let mut vmk_bytes = [0u8; 32];
            vmk_bytes.copy_from_slice(&vmk.as_bytes());
            header.header_hmac = Some(self.calculate_header_hmac(&header, &vmk_bytes));
            vmk_bytes.zeroize();
        }

        let path = self.meta_path();
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let data = serde_json::to_string(&header).map_err(|e| VaultError::Crypto(e.to_string()))?;
        // Atomic write: tmp + fsync + rename — prevents partial writes on crash.
        // M-10 fix: include the process ID and 64 bits of CSPRNG entropy in the
        // tmp filename so two concurrent write_header invocations cannot
        // blind-write the same tmp path (which would lose one writer's diff
        // entirely on the second rename).
        let mut suffix = [0u8; 8]; OsRng.fill_bytes(&mut suffix);
        let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "vault.db.meta".to_string());
        let tmp_name = format!("{}.tmp.{}.{}", file_name, std::process::id(), hex::encode(suffix));
        let tmp = path.with_file_name(tmp_name);
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, &path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    fn calculate_header_hmac(&self, header: &VaultHeader, vmk: &[u8; 32]) -> String {
        let mut h = header.clone();
        h.header_hmac = None;
        let json = serde_json::to_string(&h).unwrap_or_default();
        
        use hkdf::Hkdf;
        use sha2::Sha384;
        use hmac::{Hmac, Mac};
        
        let hk = Hkdf::<Sha384>::new(None, vmk);
        let mut okm = [0u8; 32];
        hk.expand(b"sidecar-hmac", &mut okm).unwrap();
        
        let mut mac = Hmac::<Sha384>::new_from_slice(&okm).expect("HMAC can take 32 bytes");
        mac.update(json.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn derive_wipe_key(&self, vmk: &[u8; 32]) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha384;
        let hk = Hkdf::<Sha384>::new(None, vmk);
        let mut okm = [0u8; 32];
        hk.expand(b"wipe-ticket-key", &mut okm).unwrap();
        okm
    }

    pub fn encrypt_wipe_ticket(&self, ticket: &[u8], vmk: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
        let key = self.derive_wipe_key(vmk);
        let (ct, nonce) = crate::crypto::aes_gcm::encrypt(&key, ticket, b"wipe-ticket-aad-v1")?;
        Ok((ct, nonce.to_vec()))
    }

    pub fn decrypt_wipe_ticket(&self, ct: &[u8], nonce_vec: &[u8], vmk: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
        let key = self.derive_wipe_key(vmk);
        let nonce: [u8; 12] = nonce_vec.try_into().map_err(|_| VaultError::Crypto("invalid wipe nonce".into()))?;
        crate::crypto::aes_gcm::decrypt(&key, ct, &nonce, b"wipe-ticket-aad-v1")
    }

    pub fn add_passkey_to_sidecar(
        &self, cid: &[u8], enc_vmk: &[u8], nonce: &[u8], pub_key_cbor: &[u8],
    ) -> Result<(), VaultError> {
        let _guard = self.db.lock().unwrap();
        let mut header = self.read_header()?;
        let cid_hex = hex::encode(cid);
        header.passkey_credentials.retain(|e| e.credential_id_hex != cid_hex);

        // H-11: cap at 16 credentials to prevent sidecar DoS
        if header.passkey_credentials.len() >= 16 {
            return Err(VaultError::Auth("too many passkeys registered (max 16)".into()));
        }

        header.passkey_credentials.push(PasskeySidecarEntry {
            credential_id_hex: cid_hex,
            encrypted_vmk_copy: hex::encode(enc_vmk),
            vmk_copy_nonce: hex::encode(nonce),
            pub_key_cbor_hex: Some(hex::encode(pub_key_cbor)),
            sign_count: 0,
        });
        self.write_header(&header)
    }

    pub fn update_login_policy(&self, p: bool, t: bool, e: bool, d: u32) -> Result<(), VaultError> {
        let _guard = self.db.lock().unwrap();
        let mut h = self.read_header()?;
        h.password_login_enabled = p; h.totp_enabled = t; h.email_otp_enabled = e;
        h.duress_max_attempts = d;
        self.write_header(&h)
    }

    pub fn unlock_with_passkey(
        &self, cid: &[u8], auth_data: &[u8], sig: &[u8], client_data_json: &[u8], uid: u32, conn_id: u64,
    ) -> Result<Session, VaultError> {
        self.check_unlock_lockout(uid, conn_id)?;
        let res = self.unlock_with_passkey_inner(cid, auth_data, sig, client_data_json, uid);
        if res.is_ok() { self.reset_unlock_counter(uid, conn_id); self.touch(); } else { self.record_failed_unlock(uid, conn_id); }
        res
    }

    fn unlock_with_passkey_inner(
        &self, cid: &[u8], auth_data: &[u8], sig: &[u8], client_data_json: &[u8], uid: u32,
    ) -> Result<Session, VaultError> {

        let cdata: serde_json::Value = serde_json::from_slice(client_data_json)
            .map_err(|_| VaultError::Auth("invalid clientDataJSON".into()))?;

        // #28-FIX: validate type and crossOrigin (W3C WebAuthn §7.2 step 11).
        let cdtype = cdata.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if cdtype != "webauthn.get" {
            return Err(VaultError::Auth("invalid clientDataJSON type".into()));
        }
        if cdata.get("crossOrigin").and_then(|v| v.as_bool()).unwrap_or(false) {
            return Err(VaultError::Auth("cross-origin passkey assertion not allowed".into()));
        }

        let chal_b64 = cdata.get("challenge").and_then(|v| v.as_str())
            .ok_or_else(|| VaultError::Auth("missing challenge".into()))?;
        use base64::Engine;
        let chal_b64_clean = chal_b64.trim_end_matches('=').to_string();
        let chal_decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&chal_b64_clean)
            .map_err(|_| VaultError::Auth("invalid challenge b64".into()))?;

        if chal_decoded.len() != 32 { return Err(VaultError::Auth("invalid challenge length".into())); }
        let mut chal_arr = [0u8; 32]; chal_arr.copy_from_slice(&chal_decoded);
        if !self.consume_challenge(&chal_arr) {
            return Err(VaultError::Auth("challenge invalid or expired".into()));
        }

        let header = self.read_header()?;
        if header.strict_pqc_mode { return Err(VaultError::Auth("Strict Mode enabled".into())); }
        let cid_hex = hex::encode(cid);
        let entry = header.passkey_credentials.iter()
            .find(|e| e.credential_id_hex == cid_hex)
            .ok_or_else(|| VaultError::Auth("not registered".into()))?;

        // F1-FIX: verify the FIDO2 assertion signature before deriving the wrap key.
        let pub_key_bytes = entry.pub_key_cbor_hex.as_deref()
            .ok_or_else(|| VaultError::Auth(
                "passkey re-registration required: public key not in sidecar".into(),
            ))
            .and_then(|h| hex::decode(h)
                .map_err(|_| VaultError::Crypto("pub_key_cbor_hex decode failed".into())))?;

        use sha2::{Sha256, Digest};
        let cdh: [u8; 32] = Sha256::digest(client_data_json).into();

        let assertion = crate::auth::fido2::AssertOutput {
            credential_id: cid.to_vec(),
            auth_data: auth_data.to_vec(),
            signature: sig.to_vec(),
        };
        let backend = crate::auth::fido2::FidoDevice::new();
        backend.verify_assertion(&pub_key_bytes, &assertion, &cdh, "localhost", true) // UV required for primary unlock
            .map_err(|_| VaultError::Auth("assertion signature verification failed".into()))?;

        // H-16: verify signature counter to detect cloned authenticators.
        // Only VERIFY here (before VMK load). The sidecar write happens AFTER
        // self.vmk is set so write_header can compute the HMAC correctly (#16-FIX).
        let updated_sign_count: Option<u32> = if auth_data.len() >= 37 {
            let mut count_bytes = [0u8; 4];
            count_bytes.copy_from_slice(&auth_data[33..37]);
            let new_count = u32::from_be_bytes(count_bytes);
            if new_count > 0 && new_count <= entry.sign_count {
                return Err(VaultError::Auth("signature counter regression - cloned authenticator detected".into()));
            }
            if new_count > entry.sign_count { Some(new_count) } else { None }
        } else {
            None
        };

        let wrap_key = crate::auth::fido2::derive_vmk_wrap_key(auth_data, cid, header.kem_suite)?;
        let ct = hex::decode(&entry.encrypted_vmk_copy).map_err(|_| VaultError::Crypto("hex".into()))?;
        let nonce_vec = hex::decode(&entry.vmk_copy_nonce).map_err(|_| VaultError::Crypto("hex".into()))?;
        
        let mut vmk_plain = match nonce_vec.len() {
            12 => {
                let nonce: [u8; 12] = nonce_vec.try_into().unwrap();
                crate::crypto::aes_gcm::decrypt(&wrap_key, &ct, &nonce, b"passkey-vmk-aad-v1")?
            }
            24 => {
                let nonce: [u8; 24] = nonce_vec.try_into().unwrap();
                xchacha20::decrypt(&wrap_key, &ct, &nonce, b"passkey-vmk-aad-v1")?
            }
            _ => return Err(VaultError::Crypto("nonce len".into())),
        };

        let mut sc_key = Self::sqlcipher_key(&vmk_plain);
        let conn = db::open_vault(&self.vault_path, &sc_key)?;
        sc_key.zeroize();
        let vmk_bytes: [u8; 32] = vmk_plain.as_slice().try_into().unwrap();
        
        // H-09: verify audit chain
        audit::verify_chain(&conn, &vmk_bytes)?;
        
        self.migrate_data_to_v2(&conn, &vmk_bytes)?;
        let mut locked = LockedKey::new(32)?;
        locked.as_bytes_mut().copy_from_slice(&vmk_plain);
        vmk_plain.zeroize();

        *self.vmk.write().unwrap() = Some(locked);
        *self.db.lock().unwrap() = Some(conn);
        *self.vault_uuid.lock().unwrap() = Some(header.vault_uuid.clone());
        *self.wipe_ticket.lock().unwrap() = None;

        // #16-FIX: persist updated sign count NOW that self.vmk is set, so
        // write_header can recompute the sidecar HMAC over the mutated payload.
        // M-8 fix: hold db.lock() across the read-modify-write so concurrent
        // RegisterFido2 or UpdateLoginPolicy can't clobber the sign-count, and
        // this writer can't clobber a freshly-added passkey credential.
        // Matches the locking pattern in add_passkey_to_sidecar / update_login_policy.
        if let Some(new_count) = updated_sign_count {
            let _guard = self.db.lock().unwrap();
            if let Ok(mut fresh_header) = self.read_header() {
                if let Some(e) = fresh_header.passkey_credentials.iter_mut()
                    .find(|e| e.credential_id_hex == cid_hex)
                {
                    e.sign_count = new_count;
                    let _ = self.write_header(&fresh_header);
                }
            }
        }

        let sess = self.sessions.create(&header.vault_uuid, uid, DEFAULT_TTL_SECS)?;
        Ok(sess)
    }

    fn sqlcipher_key(vmk: &[u8]) -> [u8; 32] {
        use sha3::Sha3_512;
        let hk = Hkdf::<Sha3_512>::new(None, vmk);
        let mut key = [0u8; 32];
        hk.expand(b"vault-sqlcipher-key-v2-sha3-512", &mut key).unwrap(); key
    }

    pub fn blind_index_key(&self, vmk: &[u8]) -> [u8; 64] {
        use sha3::Sha3_512;
        let hk = Hkdf::<Sha3_512>::new(None, vmk);
        let mut key = [0u8; 64];
        hk.expand(b"vault-blind-index-key-v1-sha3-512", &mut key).unwrap(); key
    }

    fn migrate_data_to_v2(&self, conn: &Connection, vmk: &[u8; 32]) -> Result<(), VaultError> {
        // M-05 fix: check short-circuit flag in vault_meta first.
        let already_done: bool = conn.query_row(
            "SELECT count(*) FROM vault_meta WHERE key='data_migrated_to_v2' AND value='true'",
            [], |r| r.get(0)
        ).unwrap_or(0) > 0;
        if already_done { return Ok(()); }

        let bi_key = self.blind_index_key(vmk);
        let vault_uuid = self.vault_uuid_str();

        // Wrap the entire migration in a transaction.
        // NOTE: we need to use 'conn' but some methods called inside might try to use it too.
        // SQLCipher usually allows nested transactions if supported, but here we just want atomicity.
        conn.execute("BEGIN TRANSACTION", [])?;

        let res: Result<(), VaultError> = (|| {
            let has_legacy: bool = conn.query_row("SELECT count(*) FROM sqlite_master WHERE name='folders_legacy'", [], |r| r.get(0)).unwrap_or(0) > 0;
            if has_legacy {
                tracing::info!("Migrating folders from legacy table...");
                let mut stmt = conn.prepare("SELECT id, name, description, icon_svg FROM folders_legacy")?;
                let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Option<String>>(3)?)))?;
                for r in rows {
                    let (id_str, name, desc, icon) = r?;
                    if let Ok(id) = Uuid::parse_str(&id_str) {
                        let _ = crate::vault::folders::update(conn, vmk, &vault_uuid, id, &name, desc.as_deref(), icon.as_deref());
                    }
                }
                conn.execute("DROP TABLE folders_legacy", [])?;
            }

            let has_u_legacy: bool = conn.query_row("SELECT count(*) FROM sqlite_master WHERE name='users_legacy'", [], |r| r.get(0)).unwrap_or(0) > 0;
            if has_u_legacy {
                tracing::info!("Migrating users from legacy table...");
                let mut stmt = conn.prepare("SELECT id, first_name, last_name, email FROM users_legacy")?;
                let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?)))?;
                for r in rows {
                    let (_id, f, l, e) = r?;
                    let _ = crate::vault::user_profile::update(conn, vmk, &f, &l, &e);
                }
                conn.execute("DROP TABLE users_legacy", [])?;
            }

            let mut stmt = conn.prepare("SELECT id FROM credentials WHERE service_hash IS NULL")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            for r in rows {
                let id_str = r?;
                if let Ok(id) = Uuid::parse_str(&id_str) {
                    if let Ok(blob) = crate::vault::credentials::get(conn, vmk, id) {
                        let folder_id: Option<String> = conn.query_row("SELECT folder_id FROM credentials WHERE id=?1", params![id_str], |r| r.get(0)).unwrap_or(None);
                        let fid = folder_id.and_then(|s| Uuid::parse_str(&s).ok());
                        let _ = crate::vault::credentials::update(conn, vmk, &bi_key, &vault_uuid, id, fid, &blob);
                    }
                }
            }
            
            conn.execute("INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('data_migrated_to_v2', 'true')", [])?;
            Ok(())
        })();

        match res {
            Ok(()) => {
                conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }

    pub fn unlock(&self, pw: &[u8], yk: Option<&[u8; 20]>, uid: u32, conn_id: u64) -> Result<Session, VaultError> {
        if pw.len() > 1024 { return Err(VaultError::Auth("password too long".into())); }
        if !self.vault_path.exists() && pw.len() < 12 {
            return Err(VaultError::Auth("password must be at least 12 characters".into()));
        }
        self.check_unlock_lockout(uid, conn_id)?;
        let res = if self.vault_path.exists() { self.unlock_existing(pw, yk, uid) } else { self.create_and_unlock(pw, yk, uid) };
        if res.is_ok() {
            self.reset_unlock_counter(uid, conn_id);
            // Start the 15-min idle clock from unlock completion — the Argon2id KDF
            // can take 60s+, leaving last_activity stale from the prior session and
            // causing the idle auto-lock task to fire seconds after unlock returns,
            // wiping the just-issued session token.
            self.touch();
        } else {
            self.record_failed_unlock(uid, conn_id);
        }
        res
    }

    fn unlock_existing(&self, password: &[u8], yubikey_response: Option<&[u8; 20]>, uid: u32) -> Result<Session, VaultError> {
        
        let header = self.read_header()?;

        // H-22 fix: enforce "passwordless-only" policy if enabled.
        if !header.password_login_enabled {
            return Err(VaultError::Auth("password login disabled for this vault".into()));
        }

        let salt_bytes = hex::decode(&header.argon2_salt).map_err(|_| VaultError::Crypto("salt".into()))?;
        let mut salt = [0u8; 32]; salt.copy_from_slice(&salt_bytes);
        
        let start = std::time::Instant::now();
        let kek_buf = kdf::derive_kek(password, yubikey_response, &salt, header.argon2_m_cost, header.argon2_t_cost, header.argon2_p_cost)?;
        tracing::trace!("unlock_kdf={}ms", start.elapsed().as_millis()); // #21-FIX: downgraded to trace (off by default)
        
        let kek: [u8; 32] = kek_buf.as_bytes()[..32].try_into().unwrap();
        let ct = hex::decode(&header.encrypted_vmk).map_err(|_| VaultError::Crypto("vmk".into()))?;
        let nonce_vec = hex::decode(&header.vmk_nonce).map_err(|_| VaultError::Crypto("nonce".into()))?;
        
        let mut vmk_plain = match nonce_vec.len() {
            12 => {
                let nonce: [u8; 12] = nonce_vec.try_into().unwrap();
                crate::crypto::aes_gcm::decrypt(&kek, &ct, &nonce, b"vmk-aad-v1")?
            }
            24 => {
                let nonce: [u8; 24] = nonce_vec.try_into().unwrap();
                xchacha20::decrypt(&kek, &ct, &nonce, b"vmk-aad-v1")?
            }
            _ => return Err(VaultError::Crypto("nonce len".into())),
        };

        let mut vmk_locked = LockedKey::new(32)?; vmk_locked.as_bytes_mut().copy_from_slice(&vmk_plain);
        
        let mut vmk_arr = [0u8; 32];
        vmk_arr.copy_from_slice(&vmk_plain);

        // #17-FIX: header_hmac is mandatory once the vault DB exists. An absent HMAC
        // could indicate a downgrade attack on KDF parameters. Only allow None for
        // newly-created vaults (vault.db does not exist yet at first unlock).
        match &header.header_hmac {
            None => {
                vmk_plain.zeroize(); vmk_arr.zeroize();
                return Err(VaultError::Auth("vault header integrity check failed".into()));
            }
            Some(expected_hmac) => {
                let actual_hmac = self.calculate_header_hmac(&header, &vmk_arr);
                if actual_hmac != *expected_hmac {
                    vmk_plain.zeroize(); vmk_arr.zeroize();
                    return Err(VaultError::Auth("vault header integrity check failed".into()));
                }
            }
        }

        let mut sc_key = Self::sqlcipher_key(&vmk_plain);
        let conn = db::open_vault(&self.vault_path, &sc_key)?;

        // H-09: verify full audit HMAC chain on unlock
        audit::verify_chain(&conn, &vmk_arr)?;

        sc_key.zeroize(); vmk_plain.zeroize(); vmk_arr.zeroize();
        let mut vmk_bytes = [0u8; 32]; vmk_bytes.copy_from_slice(&vmk_locked.as_bytes());
        self.migrate_data_to_v2(&conn, &vmk_bytes)?;

        let raw_ticket = if header.wipe_ticket_hash.is_empty() {
            use sha3::{Sha3_512, Digest};
            let mut t = [0u8; 32]; OsRng.fill_bytes(&mut t);
            let mut h = header.clone(); h.wipe_ticket_hash = hex::encode(Sha3_512::digest(&t));
            self.write_header(&h)?; t.to_vec()
        } else { vec![] };

        // Transparent KEK-param migration.
        if crate::crypto::kdf_tune::is_legacy_heavy(
            header.argon2_m_cost, header.argon2_t_cost, header.argon2_p_cost,
        ) {
            if let Err(e) = self.rewrap_vmk_with_current_kdf(password, yubikey_response, &vmk_bytes) {
                tracing::warn!(err = %e, "transparent KDF migration failed (non-fatal)");
            } else {
                tracing::info!("migrated vault KDF from legacy heavy profile to current floor");
            }
        }

        // M-02 fix: zeroize the stack-allocated vmk_bytes copy before it is dropped.
        vmk_bytes.zeroize();

        *self.vmk.write().unwrap() = Some(vmk_locked);
        *self.db.lock().unwrap() = Some(conn);
        *self.vault_uuid.lock().unwrap() = Some(header.vault_uuid.clone());
        *self.wipe_ticket.lock().unwrap() = if raw_ticket.is_empty() { None } else { Some(raw_ticket) };
        self.sessions.create(&header.vault_uuid, uid, DEFAULT_TTL_SECS)
    }

    /// Re-derive the KEK at the current KDF floor and re-wrap the VMK in the
    /// sidecar. Used by the transparent migration path in `unlock_existing`.
    /// The caller must already have successfully decrypted the VMK with the
    /// existing (legacy) params — passing `vmk_bytes` proves that.
    fn rewrap_vmk_with_current_kdf(
        &self,
        password: &[u8],
        yubikey_response: Option<&[u8; 20]>,
        vmk_bytes: &[u8; 32],
    ) -> Result<(), VaultError> {
        let (new_m, new_t, new_p) = crate::crypto::kdf_tune::tune_params();
        let mut new_salt = [0u8; 32]; OsRng.fill_bytes(&mut new_salt);

        let kek_buf = kdf::derive_kek(password, yubikey_response, &new_salt, new_m, new_t, new_p)?;
        let kek: [u8; 32] = kek_buf.as_bytes()[..32].try_into()
            .map_err(|_| VaultError::Crypto("kek len".into()))?;

        let (new_enc_vmk, new_nonce) = crate::crypto::aes_gcm::encrypt(&kek, vmk_bytes, b"vmk-aad-v1")?;

        // Atomic header update.
        let mut h = self.read_header()?;
        h.argon2_salt = hex::encode(new_salt);
        h.argon2_m_cost = new_m;
        h.argon2_t_cost = new_t;
        h.argon2_p_cost = new_p;
        h.encrypted_vmk = hex::encode(&new_enc_vmk);
        h.vmk_nonce = hex::encode(new_nonce);
        // Passkey VMK copies and quick-unlock entries wrapped the same VMK with
        // a different (auth-data-derived / dbk-derived) key, so they remain
        // valid; we do NOT clear them here.
        self.write_header(&h)?;
        Ok(())
    }

    fn create_and_unlock(&self, password: &[u8], yk: Option<&[u8; 20]>, uid: u32) -> Result<Session, VaultError> {
        let vault_uuid = Uuid::new_v4().to_string();
        let mut salt = [0u8; 32]; OsRng.fill_bytes(&mut salt);
        let mut vmk_bytes = [0u8; 32]; OsRng.fill_bytes(&mut vmk_bytes);
        let (m, t, p) = crate::crypto::kdf_tune::tune_params();
        let kek_buf = kdf::derive_kek(password, yk, &salt, m, t, p)?;
        let kek: [u8; 32] = kek_buf.as_bytes()[..32].try_into().unwrap();
        let (enc_vmk, nonce) = crate::crypto::aes_gcm::encrypt(&kek, &vmk_bytes, b"vmk-aad-v1")?;
        
        let mut wipe_ticket = [0u8; 32]; OsRng.fill_bytes(&mut wipe_ticket);
        use sha3::{Sha3_512, Digest};
        let header = VaultHeader {
            vault_uuid: vault_uuid.clone(),
            argon2_salt: hex::encode(salt),
            argon2_m_cost: m, argon2_t_cost: t, argon2_p_cost: p,
            kem_suite: if cfg!(feature = "pq-hybrid-1024") { 2 } else { 0 },
            encrypted_vmk: hex::encode(&enc_vmk), vmk_nonce: hex::encode(nonce),
            password_login_enabled: true, totp_enabled: false, email_otp_enabled: false,
            strict_pqc_mode: false, passkey_credentials: vec![], pqc_credentials: vec![],
            quick_unlock_credentials: vec![],
            recovery_key_copy: None,
            duress_max_attempts: 0,
            wipe_ticket_hash: hex::encode(Sha3_512::digest(&wipe_ticket)),
            header_hmac: None,
        };
        
        let mut locked = LockedKey::new(32)?; locked.as_bytes_mut().copy_from_slice(&vmk_bytes);
        *self.vmk.write().unwrap() = Some(locked);
        
        self.write_header(&header)?;
        let sc_key = Self::sqlcipher_key(&vmk_bytes);
        let conn = db::open_vault(&self.vault_path, &sc_key)?;
        *self.db.lock().unwrap() = Some(conn);
        *self.vault_uuid.lock().unwrap() = Some(vault_uuid.clone());
        *self.wipe_ticket.lock().unwrap() = Some(wipe_ticket.to_vec());
        self.sessions.create(&vault_uuid, uid, DEFAULT_TTL_SECS)
    }

    pub fn lock(&self) {
        // D-2 fix: canonical lock order across the codebase is
        //   db → vmk → vault_uuid → wipe_ticket → lockout → sessions.
        // Every sidecar writer (change_password_inner, add_passkey_to_sidecar,
        // update_login_policy, write_header) acquires db.lock() then takes
        // vmk.read() via write_header. If lock() acquired vmk.write() first,
        // an AB-BA deadlock would form on multi-threaded tokio whenever a
        // background lock() races a passkey enrollment or login-policy update.
        // Acquiring db.lock() first matches every other site.
        drop(self.db.lock().unwrap().take());
        drop(self.vmk.write().unwrap().take());
        drop(self.vault_uuid.lock().unwrap().take());
        drop(self.wipe_ticket.lock().unwrap().take());
        self.lockout.clear();
        self.sessions.revoke_all();
    }

    pub fn wipe_ticket_bytes(&self) -> Option<Vec<u8>> { self.wipe_ticket.lock().unwrap().clone() }

    pub fn forensic_wipe(&self, presented_ticket: &[u8]) -> Result<(), VaultError> {
        // M-41 fix: enforce strict ticket length before hashing to prevent length-extension or ambiguity.
        if presented_ticket.len() != 32 {
            return Err(VaultError::Auth("invalid ticket length (must be 32 bytes)".into()));
        }
        use sha3::{Sha3_512, Digest};
        let header = self.read_header()?;
        if header.wipe_ticket_hash.is_empty() { return Err(VaultError::Auth("no ticket".into())); }
        let hash = Sha3_512::digest(presented_ticket);
        if !ct_eq(hex::encode(hash).as_bytes(), header.wipe_ticket_hash.as_bytes()) { return Err(VaultError::Auth("invalid".into())); }
        self.forensic_wipe_internal()
    }

    fn forensic_wipe_internal(&self) -> Result<(), VaultError> {
        self.lock();
        let db_path = self.vault_path.clone();
        let meta_path = self.meta_path();
        // NIST SP 800-88 Rev. 2 cryptographic erase (primary path).
        // Falls back to unlink-only if header sanitisation fails.
        let wipe_result = if std::env::var("VAULT_WIPE_MODE").as_deref() == Ok("overwrite") {
            super::wipe::media_overwrite(&meta_path, 7)
                .and_then(|_| super::wipe::media_overwrite(&db_path, 7))
        } else {
            super::wipe::cryptographic_erase(&meta_path, &db_path).or_else(|_| {
                let _ = std::fs::remove_file(&db_path);
                let _ = std::fs::remove_file(&meta_path);
                Ok(())
            })
        };
        wipe_result
    }

    pub fn unlock_with_pqc(&self, _uid: u32, cid: &[u8], sig: &[u8], _ct: &[u8], client_data_json: &[u8], conn_id: u64) -> Result<Session, VaultError> {
        self.check_unlock_lockout(_uid, conn_id)?;
        let res = self.unlock_with_pqc_inner(_uid, cid, sig, _ct, client_data_json);
        if res.is_ok() { self.reset_unlock_counter(_uid, conn_id); self.touch(); } else { self.record_failed_unlock(_uid, conn_id); }
        res
    }

    fn unlock_with_pqc_inner(&self, _uid: u32, cid: &[u8], sig: &[u8], _ct: &[u8], client_data_json: &[u8]) -> Result<Session, VaultError> {

        let cdata: serde_json::Value = serde_json::from_slice(client_data_json)
            .map_err(|_| VaultError::Auth("invalid clientDataJSON".into()))?;

        // #28-FIX: validate type and crossOrigin (W3C WebAuthn §7.2 step 11).
        let cdtype = cdata.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if cdtype != "webauthn.get" {
            return Err(VaultError::Auth("invalid clientDataJSON type".into()));
        }
        if cdata.get("crossOrigin").and_then(|v| v.as_bool()).unwrap_or(false) {
            return Err(VaultError::Auth("cross-origin passkey assertion not allowed".into()));
        }

        let chal_b64 = cdata.get("challenge").and_then(|v| v.as_str())
            .ok_or_else(|| VaultError::Auth("missing challenge".into()))?;
        use base64::Engine;
        let chal_b64_clean = chal_b64.trim_end_matches('=').to_string();
        let chal_decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&chal_b64_clean)
            .map_err(|_| VaultError::Auth("invalid challenge b64".into()))?;

        if chal_decoded.len() != 32 { return Err(VaultError::Auth("invalid challenge length".into())); }
        let mut chal_arr = [0u8; 32]; chal_arr.copy_from_slice(&chal_decoded);
        if !self.consume_challenge(&chal_arr) {
            return Err(VaultError::Auth("challenge invalid or expired".into()));
        }

        let header = self.read_header()?;
        let cid_hex = hex::encode(cid);
        let entry = header.pqc_credentials.iter().find(|e| e.credential_id_hex == cid_hex).ok_or_else(|| VaultError::Auth("not reg".into()))?;
        let vk_bytes = hex::decode(&entry.verifying_key_hex).map_err(|_| VaultError::Crypto("hex".into()))?;
        crate::crypto::sign::verify(&vk_bytes, client_data_json, sig).map_err(|_| VaultError::Auth("sig".into()))?;
        Err(VaultError::Auth("PQC binding planned".into()))
    }

    pub fn quick_unlock_enroll(&self, password: &[u8], cid: &[u8], pub_key_cbor: &[u8], dbk: &[u8]) -> Result<(), VaultError> {
        if password.len() > 1024 { return Err(VaultError::Auth("password too long".into())); }
        let mut header = self.read_header()?;
        let salt_bytes = hex::decode(&header.argon2_salt).map_err(|_| VaultError::Crypto("salt".into()))?;
        let mut salt = [0u8; 32]; salt.copy_from_slice(&salt_bytes);
        
        let kek_buf = kdf::derive_kek(password, None, &salt, header.argon2_m_cost, header.argon2_t_cost, header.argon2_p_cost)?;
        let kek: [u8; 32] = kek_buf.as_bytes()[..32].try_into().unwrap();
        let dbk_arr: &[u8; 32] = dbk.try_into().map_err(|_| VaultError::Crypto("dbk len".into()))?;
        
        let (enc_kek, nonce) = crate::crypto::aes_gcm::encrypt(dbk_arr, &kek, b"quick-unlock-v1")?;
        
        header.quick_unlock_credentials.push(QuickUnlockCred {
            credential_id_hex: hex::encode(cid),
            enc_kek: hex::encode(enc_kek),
            nonce: hex::encode(nonce),
            pub_key_cbor_hex: hex::encode(pub_key_cbor),
            created_at: now_secs(),
        });
        self.write_header(&header)
    }

    pub fn quick_unlock(
        &self, cid: &[u8], auth_data: &[u8], sig: &[u8], client_data_json: &[u8], dbk: &[u8], uid: u32, conn_id: u64
    ) -> Result<Session, VaultError> {
        self.check_unlock_lockout(uid, conn_id)?;
        let res = self.quick_unlock_inner(cid, auth_data, sig, client_data_json, dbk, uid);
        if res.is_ok() { self.reset_unlock_counter(uid, conn_id); self.touch(); } else { self.record_failed_unlock(uid, conn_id); }
        res
    }

    fn quick_unlock_inner(
        &self, cid: &[u8], auth_data: &[u8], sig: &[u8], client_data_json: &[u8], dbk: &[u8], uid: u32
    ) -> Result<Session, VaultError> {

        let cdata: serde_json::Value = serde_json::from_slice(client_data_json)
            .map_err(|_| VaultError::Auth("invalid clientDataJSON".into()))?;

        // #28-FIX: validate type and crossOrigin (W3C WebAuthn §7.2 step 11).
        let cdtype = cdata.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if cdtype != "webauthn.get" {
            return Err(VaultError::Auth("invalid clientDataJSON type".into()));
        }
        if cdata.get("crossOrigin").and_then(|v| v.as_bool()).unwrap_or(false) {
            return Err(VaultError::Auth("cross-origin passkey assertion not allowed".into()));
        }

        let chal_b64 = cdata.get("challenge").and_then(|v| v.as_str())
            .ok_or_else(|| VaultError::Auth("missing challenge".into()))?;
        use base64::Engine;
        let chal_b64_clean = chal_b64.trim_end_matches('=').to_string();
        let chal_decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&chal_b64_clean)
            .map_err(|_| VaultError::Auth("invalid challenge b64".into()))?;

        if chal_decoded.len() != 32 { return Err(VaultError::Auth("invalid challenge length".into())); }
        let mut chal_arr = [0u8; 32]; chal_arr.copy_from_slice(&chal_decoded);
        if !self.consume_challenge(&chal_arr) {
            return Err(VaultError::Auth("challenge invalid or expired".into()));
        }

        let header = self.read_header()?;
        let cid_hex = hex::encode(cid);
        let entry = header.quick_unlock_credentials.iter()
            .find(|e| e.credential_id_hex == cid_hex)
            .ok_or_else(|| VaultError::Auth("not registered".into()))?;

        // F-06: verify the signature to ensure the user is actually present
        use sha2::{Sha256, Digest};
        let cdh: [u8; 32] = Sha256::digest(client_data_json).into();
        let assertion = crate::auth::fido2::AssertOutput {
            credential_id: cid.to_vec(),
            auth_data: auth_data.to_vec(),
            signature: sig.to_vec(),
        };
        let backend = crate::auth::fido2::FidoDevice::new();
        // For Quick Unlock we use the public key stored during enrollment
        let pub_key_bytes = hex::decode(&entry.pub_key_cbor_hex)
            .map_err(|_| VaultError::Crypto("pub key decode failed".into()))?;
        
        backend.verify_assertion(&pub_key_bytes, &assertion, &cdh, "localhost", true)
            .map_err(|_| VaultError::Auth("quick unlock signature verification failed".into()))?;

        let dbk_arr: &[u8; 32] = dbk.try_into().map_err(|_| VaultError::Crypto("dbk len".into()))?;
        
        if let (Ok(ct), Ok(nonce_vec)) = (hex::decode(&entry.enc_kek), hex::decode(&entry.nonce)) {
            if nonce_vec.len() == 12 {
                let nonce: [u8; 12] = nonce_vec.try_into().unwrap();
                if let Ok(kek_vec) = crate::crypto::aes_gcm::decrypt(dbk_arr, &ct, &nonce, b"quick-unlock-v1") {
                    if kek_vec.len() == 32 {
                        let mut k = [0u8; 32];
                        k.copy_from_slice(&kek_vec);
                        let kek = k;
                        
                        let ct = hex::decode(&header.encrypted_vmk).map_err(|_| VaultError::Crypto("vmk".into()))?;
                        let nonce_vec = hex::decode(&header.vmk_nonce).map_err(|_| VaultError::Crypto("nonce".into()))?;
                        
                        let mut vmk_plain = match nonce_vec.len() {
                            12 => {
                                let nonce: [u8; 12] = nonce_vec.try_into().unwrap();
                                crate::crypto::aes_gcm::decrypt(&kek, &ct, &nonce, b"vmk-aad-v1")?
                            }
                            24 => {
                                let nonce: [u8; 24] = nonce_vec.try_into().unwrap();
                                xchacha20::decrypt(&kek, &ct, &nonce, b"vmk-aad-v1")?
                            }
                            _ => return Err(VaultError::Crypto("nonce len".into())),
                        };

                        let mut vmk_locked = LockedKey::new(32)?; vmk_locked.as_bytes_mut().copy_from_slice(&vmk_plain);
                        let mut sc_key = Self::sqlcipher_key(&vmk_plain);
                        let conn = db::open_vault(&self.vault_path, &sc_key)?;
                        
                        // H-09: verify audit chain
                        let mut vmk_arr = [0u8; 32];
                        vmk_arr.copy_from_slice(&vmk_plain);
                        audit::verify_chain(&conn, &vmk_arr)?;
                        vmk_arr.zeroize();
                        
                        sc_key.zeroize(); vmk_plain.zeroize();
                        
                        let raw_ticket = if header.wipe_ticket_hash.is_empty() {
                            use sha3::{Sha3_512, Digest};
                            let mut t = [0u8; 32]; OsRng.fill_bytes(&mut t);
                            let mut h = header.clone(); h.wipe_ticket_hash = hex::encode(Sha3_512::digest(&t));
                            let _ = self.write_header(&h); t.to_vec()
                        } else { vec![] };

                        *self.vmk.write().unwrap() = Some(vmk_locked);
                        *self.db.lock().unwrap() = Some(conn);
                        *self.vault_uuid.lock().unwrap() = Some(header.vault_uuid.clone());
                        *self.wipe_ticket.lock().unwrap() = if raw_ticket.is_empty() { None } else { Some(raw_ticket) };
                        
                        return self.sessions.create(&header.vault_uuid, uid, DEFAULT_TTL_SECS);
                    }
                }
            }
        }
        
        Err(VaultError::Auth("quick unlock failed".into()))
    }

    pub fn quick_unlock_revoke(&self) -> Result<(), VaultError> {
        let mut header = self.read_header()?;
        header.quick_unlock_credentials.clear();
        self.write_header(&header)
    }

    pub fn enroll_recovery_key(&self, recovery_key: &[u8]) -> Result<(), VaultError> {
        let vmk_guard = self.vmk.read().unwrap();
        let vmk = vmk_guard.as_ref().ok_or(VaultError::Auth("Vault locked".into()))?;
        let mut vmk_bytes = [0u8; 32];
        vmk_bytes.copy_from_slice(&vmk.as_bytes());

        let mut salt = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut salt);
        
        // High-security params for recovery key (256 MiB / t=3 / p=4)
        let (m, t, p) = crate::crypto::kdf_tune::tune_params();
        let kek_buf = crate::crypto::kdf::derive_kek(recovery_key, None, &salt, m, t, p)?;
        let kek: [u8; 32] = kek_buf.as_bytes()[..32].try_into().unwrap();

        let (enc_vmk, nonce) = crate::crypto::aes_gcm::encrypt(&kek, &vmk_bytes, b"vmk-recovery-aad-v1")?;

        let _guard = self.db.lock().unwrap();
        let mut h = self.read_header()?;
        h.recovery_key_copy = Some(RecoveryKeySidecarEntry {
            encrypted_vmk_copy: hex::encode(enc_vmk),
            vmk_copy_nonce: hex::encode(nonce),
            salt: hex::encode(salt),
            m_cost: m,
            t_cost: t,
            p_cost: p,
        });
        self.write_header(&h)
    }

    pub fn unlock_with_recovery_key(&self, recovery_key: &[u8], uid: u32, conn_id: u64) -> Result<Session, VaultError> {
        self.check_unlock_lockout(uid, conn_id)?;
        let header = self.read_header()?;
        let entry = header.recovery_key_copy.as_ref().ok_or(VaultError::Auth("No recovery key enrolled".into()))?;
        
        let salt_vec = hex::decode(&entry.salt).map_err(|_| VaultError::Crypto("Invalid recovery salt".into()))?;
        let salt: [u8; 32] = salt_vec.try_into().map_err(|_| VaultError::Crypto("Invalid recovery salt len".into()))?;
        
        let kek_buf = crate::crypto::kdf::derive_kek(recovery_key, None, &salt, entry.m_cost, entry.t_cost, entry.p_cost)?;
        let kek: [u8; 32] = kek_buf.as_bytes()[..32].try_into().unwrap();
        
        let ct = hex::decode(&entry.encrypted_vmk_copy).map_err(|_| VaultError::Crypto("Invalid recovery vmk blob".into()))?;
        let nonce_vec = hex::decode(&entry.vmk_copy_nonce).map_err(|_| VaultError::Crypto("Invalid recovery vmk nonce".into()))?;
        let nonce: [u8; 12] = nonce_vec.try_into().map_err(|_| VaultError::Crypto("Invalid recovery vmk nonce len".into()))?;
        
        let mut vmk_plain = crate::crypto::aes_gcm::decrypt(&kek, &ct, &nonce, b"vmk-recovery-aad-v1")?;
        
        let mut sc_key = Self::sqlcipher_key(&vmk_plain);
        let conn = db::open_vault(&self.vault_path, &sc_key)?;
        sc_key.zeroize();
        
        let vmk_bytes: [u8; 32] = vmk_plain.as_slice().try_into().unwrap();
        audit::verify_chain(&conn, &vmk_bytes)?;
        
        let mut locked = LockedKey::new(32)?;
        locked.as_bytes_mut().copy_from_slice(&vmk_plain);
        vmk_plain.zeroize();

        *self.vmk.write().unwrap() = Some(locked);
        *self.db.lock().unwrap() = Some(conn);
        *self.vault_uuid.lock().unwrap() = Some(header.vault_uuid.clone());
        *self.wipe_ticket.lock().unwrap() = None;

        self.reset_unlock_counter(uid, conn_id);
        let sess = self.sessions.create(&header.vault_uuid, uid, DEFAULT_TTL_SECS)?;
        Ok(sess)
    }

    pub fn vmk_read_guard(&self) -> std::sync::RwLockReadGuard<'_, Option<LockedKey>> {
        self.vmk.read().unwrap()
    }

    pub fn vault_uuid_str(&self) -> String {
        self.vault_uuid.lock().unwrap().clone().unwrap_or_default()
    }

    pub fn with_vmk<F, T>(&self, f: F) -> Result<T, VaultError> where F: FnOnce(&[u8; 32]) -> Result<T, VaultError> {
        let guard = self.vmk.read().unwrap();
        match guard.as_ref() {
            None => Err(VaultError::Auth("locked".into())),
            Some(locked) => {
                let b = locked.as_bytes();
                let mut key = [0u8; 32];
                key.copy_from_slice(&b);
                let res = f(&key);
                key.zeroize();
                res
            }
        }
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}


#[cfg(test)]
mod stress {
    use super::*;
    use std::thread;
    use crate::auth::session::MAX_TOTAL_SESSIONS;

    #[test]
    fn test_session_stress_and_concurrency() {
        let db_path = PathBuf::from("/tmp/stress.db");
        let _ = std::fs::remove_file(&db_path);
        let state = Arc::new(DaemonState::new(db_path.clone()));

        let mut handles = vec![];
        for i in 0..20 {
            let state = Arc::clone(&state);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    let user_id = format!("user_{}", (i * 100 + j) % 500);
                    let _ = state.sessions.create(&user_id, 1000, 60);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let active = state.sessions.active_count();
        assert!(active <= MAX_TOTAL_SESSIONS, "Global session cap breached: {}", active);
        assert!(active > 900, "Global session count unexpectedly low: {}", active);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_rapid_lock_unlock_stability() {
        let db_path = PathBuf::from("/tmp/stability.db");
        let _ = std::fs::remove_file(&db_path);
        let mut meta = db_path.clone();
        meta.set_extension("db.meta");
        let _ = std::fs::remove_file(&meta);

        let state = DaemonState::new(db_path.clone());
        let password = b"senior_dev_password";

        // Initial setup
        state.unlock(password, None, 1000, 0).unwrap();
        state.lock();

        for _ in 0..10 {
            state.unlock(password, None, 1000, 0).expect("Unlock failed during stability test");
            assert!(!state.is_locked());
            state.lock();
            assert!(state.is_locked());
        }
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&meta);
    }

    // ── Batch 4 race-condition regression tests ──────────────────────────────
    // Each test exercises a specific finding from race-condition.md (2026-05-21)
    // and is designed to FAIL against the pre-patch code in addition to
    // passing against the patched code. Preventing the original race from
    // sneaking back in is exactly what these tests are for.

    /// D-1 regression: `forensic_wipe` used to call `self.lock()` from inside
    /// a `with_vmk` closure. `with_vmk` holds `vmk.read()`; `self.lock()`
    /// takes `vmk.write()`. The dispatch task would deadlock forever, the
    /// 120 s deadline would fire, and the on-disk vault would never be wiped.
    /// Post-fix the wipe completes in well under 5 s on a tiny test vault.
    #[test]
    fn forensic_wipe_under_vmk_read_does_not_deadlock() {
        use std::time::Duration;
        let db_path = PathBuf::from("/tmp/race-d1.db");
        let mut meta = db_path.clone();
        meta.set_extension("db.meta");
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&meta);

        let state = Arc::new(DaemonState::new(db_path.clone()));
        let password = b"correct horse battery staple";
        state.unlock(password, None, 1000, 0).expect("initial unlock");
        let ticket = state.wipe_ticket_bytes().expect("wipe ticket present");
        assert_eq!(ticket.len(), 32);

        // Drive forensic_wipe from a worker thread with a hard timeout. Pre-fix
        // this would never resolve.
        let state_clone = Arc::clone(&state);
        let ticket_clone = ticket.clone();
        let handle = thread::spawn(move || {
            state_clone.forensic_wipe(&ticket_clone).expect("forensic_wipe must complete");
        });

        // Poll-join with a 5 s ceiling.
        let start = std::time::Instant::now();
        loop {
            if handle.is_finished() { break; }
            assert!(start.elapsed() < Duration::from_secs(5),
                "forensic_wipe deadlocked — D-1 regression!");
            std::thread::sleep(Duration::from_millis(50));
        }
        handle.join().expect("wipe worker panicked");

        assert!(!db_path.exists(),  "vault.db survived forensic_wipe");
        assert!(!meta.exists(),     "vault.db.meta survived forensic_wipe");
    }

    /// D-2 regression: `lock()` used to acquire `vmk.write()` before
    /// `db.lock()` while every sidecar writer goes db → vmk. Under
    /// multi-threaded execution this produces an AB-BA deadlock. The
    /// rapid-lock-unlock test above already exercises this scenario; here we
    /// add a higher-contention variant with multiple workers to make the
    /// regression louder if it returns.
    #[test]
    fn lock_unlock_under_high_contention_does_not_deadlock() {
        use std::time::Duration;
        let db_path = PathBuf::from("/tmp/race-d2.db");
        let mut meta = db_path.clone();
        meta.set_extension("db.meta");
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&meta);

        let state = Arc::new(DaemonState::new(db_path.clone()));
        let password = b"another good password";
        state.unlock(password, None, 1000, 0).unwrap();

        let mut handles = vec![];
        for i in 0..6u32 {
            let s = Arc::clone(&state);
            handles.push(thread::spawn(move || {
                for _ in 0..8 {
                    s.lock();
                    let _ = s.unlock(password, None, 1000 + i, i as u64);
                }
            }));
        }
        let start = std::time::Instant::now();
        for h in handles {
            // Each worker should complete in well under 30 s (each unlock is
            // bounded by Argon2id KDF cost ~1-2 s on test params).
            h.join().expect("worker thread panicked");
        }
        assert!(start.elapsed() < Duration::from_secs(60),
            "lock/unlock contention took too long — possible D-2 regression!");

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&meta);
    }

    /// M-8 regression: passkey sign-count update used to skip the db.lock()
    /// that every other sidecar writer holds. We exercise concurrent
    /// `update_login_policy` calls — which DO hold db.lock + take vmk.read
    /// via write_header — under high contention. Pre-D-2-fix this combined
    /// with a racing `lock()` would deadlock; post-fix it completes quickly.
    #[test]
    fn concurrent_policy_updates_do_not_deadlock() {
        use std::time::Duration;
        let db_path = PathBuf::from("/tmp/race-m8.db");
        let mut meta = db_path.clone();
        meta.set_extension("db.meta");
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&meta);

        let state = Arc::new(DaemonState::new(db_path.clone()));
        let password = b"yet another good password";
        state.unlock(password, None, 1000, 0).unwrap();

        let mut handles = vec![];
        for i in 0..4 {
            let s = Arc::clone(&state);
            handles.push(thread::spawn(move || {
                for j in 0..8 {
                    let _ = s.update_login_policy(true, j % 2 == 0, i % 2 == 0, 0);
                }
            }));
        }
        let start = std::time::Instant::now();
        for h in handles { h.join().expect("policy worker panicked"); }
        assert!(start.elapsed() < Duration::from_secs(10),
            "update_login_policy contention deadlocked — M-8/D-2 regression!");

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&meta);
    }
}
