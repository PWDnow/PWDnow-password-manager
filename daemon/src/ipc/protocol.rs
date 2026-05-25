use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum safe frame body size (4 MiB)
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;

// ── Request variants ──────────────────────────────────────────────────────────

/// Requests from the frontend client to the vault daemon.
///
/// Unauthenticated requests carry no session token.
/// Authenticated requests embed `session_token` and are rejected with
/// `Response::Error { code: 401 }` if the token is missing, expired, or
/// belongs to a different UID (SO_PEERCRED check).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "payload", deny_unknown_fields)]
pub enum Request {
    // ── Unauthenticated ──────────────────────────────────────────────────────
    /// connectivity probe — always answered, even when locked.
    Ping,

    /// Returns whether the vault is currently locked.
    GetStatus,

    /// Returns metadata about enabled MFA methods and login policy for this vault.
    /// Used by the frontend to decide which login options to show.
    GetLoginHints,

    /// Open the vault and create a new session.
    /// `yubikey_response`: 20-byte HMAC-SHA256 output from YubiKey slot 2.
    /// `totp_code`: 6-digit TOTP code required when vault-level TOTP is configured.
    Unlock {
        password: Vec<u8>,
        yubikey_response: Option<Vec<u8>>,
        totp_code: Option<String>,
    },

    /// Forensic self-destruct — multi-pass overwrites vault files and deletes them.
    /// `wipe_ticket_ciphertext`: the encrypted capability token returned in `Response::Unlocked`.
    /// `wipe_ticket_nonce`: the nonce used to encrypt the ticket.
    /// Does NOT require a session token; works even when the vault is locked.
    /// After responding with `WipeComplete` the daemon exits the process.
    ForensicWipe {
        wipe_ticket_ciphertext: Vec<u8>,
        wipe_ticket_nonce: Vec<u8>,
    },

    /// List connected FIDO2/U2F hardware devices (requires authentication).
    ListFido2Devices { session_token: String },

    /// Begin a passkey (passwordless) unlock.
    /// Returns a 32-byte challenge the client must pass to the authenticator via
    /// `get_assertion`, then send back in `UnlockWithPasskey`.
    GetPasskeyChallenge,

    /// Begin a PQC Authenticator (Level 5) unlock.
    GetPqcChallenge,

    /// Complete a passkey unlock — no password needed.
    /// `credential_id`: raw bytes from the authenticator.
    /// `auth_data` + `signature`: from the FIDO2 assertion.
    /// `client_data_hash`: SHA-256 of the WebAuthn clientDataJSON — required to
    ///   verify the assertion signature (F1-FIX: pen-test Finding 1).
    UnlockWithPasskey {
        credential_id: Vec<u8>,
        auth_data: Vec<u8>,
        signature: Vec<u8>,
        client_data_json: Vec<u8>,
    },

    /// Complete a PQC Authenticator (Level 5) unlock.
    UnlockWithPqc {
        credential_id: Vec<u8>,
        signature: Vec<u8>,
        kem_ciphertext: Vec<u8>,
        client_data_json: Vec<u8>,
    },

    /// Verify a FIDO2 assertion for MFA or step-up auth (authenticated).
    /// `credential_id`: raw bytes from the authenticator.
    /// `auth_data` + `signature`: from the FIDO2 assertion.
    /// `client_data_json`: raw clientDataJSON from the authenticator.
    VerifyFido2Assertion {
        session_token: String,
        credential_id: Vec<u8>,
        auth_data: Vec<u8>,
        signature: Vec<u8>,
        client_data_json: Vec<u8>,
    },

    // ── Quick Unlock (Phase 4) ───────────────────────────────────────────────

    /// Get a fresh challenge for Quick Unlock (PRF-based biometric).
    GetQuickUnlockChallenge,

    /// Unlock the vault using a previously enrolled Quick Unlock credential.
    /// The browser provides the DBK (PRF output) plus an assertion signature
    /// bound to the issued challenge.
    QuickUnlock {
        credential_id: Vec<u8>,
        auth_data: Vec<u8>,
        signature: Vec<u8>,
        client_data_json: Vec<u8>,
        dbk: Vec<u8>,
    },

    // ── Authenticated ────────────────────────────────────────────────────────

    /// Enroll the current device for Quick Unlock using a WebAuthn PRF output (DBK).
    /// The daemon derives the KEK from the provided password, wraps it with this DBK,
    /// and stores it in the sidecar.
    QuickUnlockEnroll {
        session_token: String,
        password: Vec<u8>,
        credential_id: Vec<u8>,
        pub_key_cbor: Vec<u8>,
        dbk: Vec<u8>,
    },

    /// Revoke Quick Unlock for the current device (or all devices if unspecified).
    QuickUnlockRevoke {
        session_token: String,
    },

    /// Enroll a new recovery key.
    EnrollRecoveryKey {
        session_token: String,
        recovery_key: Vec<u8>,
    },

    /// Unlock the vault using a recovery key.
    UnlockWithRecoveryKey {
        recovery_key: Vec<u8>,
    },

    /// Lock the vault: zeroize VMK, close DB, revoke all sessions.
    Lock { session_token: String },

    /// List all folders, ordered by `sort_order`.
    ListFolders { session_token: String },

    /// Create a new folder.
    AddFolder {
        session_token: String,
        name: String,
        description: Option<String>,
        icon_svg: Option<String>,
    },

    /// Update an existing folder.
    UpdateFolder {
        session_token: String,
        id: Uuid,
        name: String,
        description: Option<String>,
        icon_svg: Option<String>,
    },

    /// Delete a folder.  `move_credentials_to`: if Some, reassign credentials
    /// in this folder to the given folder; otherwise delete them.
    DeleteFolder {
        session_token: String,
        id: Uuid,
        move_credentials_to: Option<Uuid>,
    },

    /// Update the `sort_order` of every folder in one transaction.
    /// `ordered_ids`: folder UUIDs in the desired display order (index = new sort_order).
    ReorderFolders {
        session_token: String,
        ordered_ids: Vec<Uuid>,
    },

    /// List all credentials, optionally filtered by folder.
    ListCredentials {
        session_token: String,
        folder_id: Option<Uuid>,
    },

    /// Decrypt and return a single credential's JSON blob.
    GetCredential {
        session_token: String,
        id: Uuid,
    },

    /// Encrypt and store a new credential.
    /// `blob`: plaintext JSON object matching the credential schema.
    AddCredential {
        session_token: String,
        folder_id: Option<Uuid>,
        blob: Vec<u8>,
    },

    /// Re-encrypt a credential with a fresh DEK (key rotation) and new plaintext.
    UpdateCredential {
        session_token: String,
        id: Uuid,
        folder_id: Option<Uuid>,
        blob: Vec<u8>,
    },

    /// Delete a credential and its encrypted DEK.
    DeleteCredential {
        session_token: String,
        id: Uuid,
    },

    /// Retrieve the asset holder JSON blob (emails, phone numbers, U2F key names).
    GetAssetHolder { session_token: String },

    /// Replace the asset holder with new plaintext JSON.
    UpdateAssetHolder {
        session_token: String,
        blob: Vec<u8>,
    },

    /// Return the current 6-digit TOTP code for a credential's stored OTP secret.
    GetOtpCode {
        session_token: String,
        credential_id: Uuid,
    },

    // ── FIDO2 / Passkey management (authenticated) ───────────────────────────

    /// List all registered FIDO2/U2F credentials stored in the vault.
    ListFido2Keys { session_token: String },

    /// Register a new FIDO2/U2F hardware key.
    /// `device_path`: path returned by `ListFido2Devices`.
    /// `resident_key`: if `true`, creates a passkey (resident key / discoverable credential).
    /// `passkey_vmk_wrap`: when `resident_key` is true, the encrypted VMK copy
    ///   (XChaCha20-Poly1305 ciphertext + 24-byte nonce) to store in the DB,
    ///   pre-computed by the daemon from the assertion during registration.
    RegisterFido2 {
        session_token: String,
        device_path: String,
        name: Option<String>,
        resident_key: bool,
    },

    /// Remove a registered FIDO2 credential by its internal UUID.
    RemoveFido2 {
        session_token: String,
        id: String,
    },

    /// Register a new PQC Authenticator (Level 5).
    RegisterPqc {
        session_token: String,
        name: Option<String>,
        verifying_key: Vec<u8>,
        encapsulation_key: Vec<u8>,
    },

    // ── Vault-level TOTP 2FA (authenticated) ─────────────────────────────────

    /// Begin TOTP setup: generates a new TOTP secret, stores it (unconfirmed)
    /// in the vault, and returns the base32 secret + `otpauth://` URI.
    SetupVaultTotp { session_token: String },

    /// Confirm TOTP setup by verifying the first code from the authenticator app.
    /// Must be called after `SetupVaultTotp`; makes the TOTP requirement active.
    ConfirmVaultTotp {
        session_token: String,
        code: String,
    },

    /// Disable and remove the vault-level TOTP requirement.
    /// Requires a valid current code to prevent accidental removal.
    RemoveVaultTotp {
        session_token: String,
        code: String,
    },

    /// Returns whether vault-level TOTP is active.
    GetVaultTotpStatus { session_token: String },

    // ── HIBP breach check (authenticated) ────────────────────────────────────

    /// Check whether a plaintext password appears in the local HIBP Cuckoo filter.
    /// `password_bytes`: raw UTF-8 bytes of the password to check.
    /// Returns `PwnedStatus` — daemon never stores or logs the plaintext password.
    CheckPasswordBreached {
        session_token: String,
        password_bytes: Vec<u8>,
    },

    // ── Audit log (authenticated) ─────────────────────────────────────────────

    /// Return the most recent audit log entries (newest first), up to `limit` rows.
    GetAuditLog {
        session_token: String,
        limit: u32,
    },

    /// Verify the BLAKE3 integrity chain of the entire audit log.
    /// Returns `Ok` if intact, `Error` with a description if tampered.
    VerifyAuditChain { session_token: String },

    // ── Backup-code unlock (authenticated alternative to TOTP) ────────────────

    /// Unlock the vault using a one-time backup code instead of a TOTP code.
    /// The backup code is consumed and cannot be reused.
    UnlockWithBackupCode {
        password: Vec<u8>,
        yubikey_response: Option<Vec<u8>>,
        backup_code: String,
    },

    // ── User profile management (authenticated) ───────────────────────────────

    /// Return the current user profile (name, email, optional profile picture).
    GetProfile { session_token: String },

    /// Update the user's name and email address.
    UpdateProfile {
        session_token: String,
        first_name: String,
        last_name: String,
        email: String,
    },

    /// Update the user's master password (re-encrypts the entire vault DB with SQLCipher REKEY).
    ChangePassword {
        session_token: String,
        old_password: Vec<u8>,
        new_password: Vec<u8>,
    },

    /// Verify the master password without making any changes.
    /// Returns Ok if the password is correct, Error(InvalidPassword) otherwise.
    VerifyMasterPassword {
        session_token: String,
        password: Vec<u8>,
    },

    /// Update MFA and password login settings in the sidecar header.
    UpdateLoginPolicy {
        session_token: String,
        password_login_enabled: bool,
        totp_enabled: bool,
        email_otp_enabled: bool,
        duress_max_attempts: u32,
    },

    /// upload a new profile picture.
    /// `image_bytes`: raw JPEG or PNG bytes (max 2 MiB).
    /// The daemon validates magic bytes, strips EXIF by re-encoding through the
    /// `image` crate, then stores the result encrypted with the VMK.
    UploadProfilePicture {
        session_token: String,
        image_bytes: Vec<u8>,
    },

    /// Clear the stored profile picture so the UI falls back to initials.
    /// Idempotent: succeeds even when no picture is set.
    RemoveProfilePicture {
        session_token: String,
    },
}

// ── Response variants ─────────────────────────────────────────────────────────

/// Responses from the daemon to the frontend client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", deny_unknown_fields)]
pub enum Response {
    /// Successful ping reply.
    Pong,

    /// Vault status.
    Status { locked: bool },

    /// Vault unlocked; client must include `session_token` in subsequent requests.
    /// `wipe_ticket_ciphertext`: store this in the browser.
    /// `wipe_ticket_nonce`: store this in the browser.
    Unlocked {
        session_token: String,
        wipe_ticket_ciphertext: Vec<u8>,
        wipe_ticket_nonce: Vec<u8>,
    },

    /// Metadata for the login page (MFA status, password policy).
    LoginHints {
        password_login_enabled: bool,
        totp_enabled: bool,
        email_otp_enabled: bool,
        recovery_key_active: bool,
        /// List of registered FIDO2/Passkey credential IDs.
        fido2_ids: Vec<Vec<u8>>,
        /// Quick unlock credentials (encrypted KEKs) for this device to attempt to unwrap.
        #[serde(default)]
        quick_unlock_credentials: Vec<crate::vault::state::QuickUnlockCred>,
    },

    /// Vault is now locked.
    Locked,

    /// Serialized list of `FolderRow` structs.
    Folders(Vec<u8>),

    /// Serialized list of `CredentialMeta` structs (IDs + non-secret metadata only).
    Credentials(Vec<u8>),

    /// Decrypted credential JSON blob.
    Credential(Vec<u8>),

    /// Decrypted asset holder JSON blob.
    AssetHolder(Vec<u8>),

    /// 6-digit TOTP code string.
    OtpCode(String),

    /// New resource UUID returned after a successful create.
    Created { id: Uuid },

    /// Successful mutation (update / delete / reorder) with no data payload.
    Ok,

    /// List of connected FIDO2 device paths.
    Fido2Devices(Vec<String>),

    /// Serialized list of `Fido2CredRow` structs.
    Fido2Keys(Vec<u8>),

    /// 32-byte passkey challenge. Client passes this to the authenticator
    /// via `get_assertion` and sends the result back in `UnlockWithPasskey`.
    PasskeyChallenge(Vec<u8>),

    /// 32-byte PQC challenge.
    PqcChallenge(Vec<u8>),

    /// 32-byte Quick Unlock challenge.
    QuickUnlockChallenge(Vec<u8>),

    /// TOTP setup information (before confirmation).
    TotpSetup {
        /// Base32-encoded TOTP secret.
        secret_b32: String,
        /// `otpauth://totp/...` URI for QR code generation.
        otp_uri: String,
        /// One-time backup codes (show once; stored as Argon2id hashes in vault).
        backup_codes: Vec<String>,
    },

    /// Whether vault-level TOTP is currently active.
    VaultTotpStatus { active: bool },

    /// Serialised list of `AuditEntry` structs (JSON).
    AuditLog(Vec<u8>),

    /// Result of an offline HIBP breach check.
    PwnedStatus {
        /// `true` = password probably in HIBP dataset; `false` = definitely clean.
        pwned: bool,
        /// `true` = the local HIBP filter was available and queried.
        /// `false` = filter not found; result is unknown (treat as unverified).
        filter_available: bool,
    },

    /// User profile data.
    Profile {
        first_name: String,
        last_name: String,
        email: String,
        /// Raw PNG bytes of the profile picture, or absent if not set.
        #[serde(skip_serializing_if = "Option::is_none")]
        profile_pic: Option<Vec<u8>>,
        /// Unix timestamp of the last master password change.
        #[serde(skip_serializing_if = "Option::is_none")]
        password_changed_at: Option<u64>,
    },

    /// Forensic wipe completed — all vault files destroyed. Process exits immediately after.
    WipeComplete,

    /// Error response.
    Error { code: u32, message: String },
}

// ── Frame I/O ─────────────────────────────────────────────────────────────────

/// Read one length-prefixed msgpack frame from a `UnixStream`.
/// Wire format: 4-byte big-endian `u32` length, then `length` bytes of msgpack body.
pub async fn read_frame(
    stream: &mut tokio::net::UnixStream,
) -> Result<Vec<u8>, crate::error::VaultError> {
    use tokio::io::AsyncReadExt;
    use tokio::time::{timeout, Duration};
    
    let mut len_buf = [0u8; 4];
    timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf)).await
        .map_err(|_| crate::error::VaultError::Ipc("read timeout (length)".into()))?
        .map_err(|e| crate::error::VaultError::Io(e))?;
    
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(crate::error::VaultError::Ipc(format!(
            "frame too large: {len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }
    
    // Mitigate Slowloris memory exhaustion: read in chunks with overall deadline
    let mut body = Vec::with_capacity(std::cmp::min(len, 65536));
    let mut remaining = len;
    let mut chunk = [0u8; 8192];
    
    let read_body = async {
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, chunk.len());
            stream.read_exact(&mut chunk[..to_read]).await?;
            body.extend_from_slice(&chunk[..to_read]);
            remaining -= to_read;
        }
        Ok::<_, std::io::Error>(())
    };

    timeout(Duration::from_secs(5), read_body).await
        .map_err(|_| crate::error::VaultError::Ipc("read timeout (body)".into()))?
        .map_err(|e| crate::error::VaultError::Io(e))?;

    Ok(body)
}

/// Write one length-prefixed msgpack frame to a `UnixStream`.
pub async fn write_frame(
    stream: &mut tokio::net::UnixStream,
    body: &[u8],
) -> Result<(), crate::error::VaultError> {
    use tokio::io::AsyncWriteExt;
    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(body).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_request_serializes() {
        let req = Request::Ping;
        let bytes = rmp_serde::to_vec(&req).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn lock_request_roundtrip() {
        let req = Request::Lock { session_token: "abc".into() };
        let bytes = rmp_serde::to_vec_named(&req).unwrap();
        let decoded: Request = rmp_serde::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, Request::Lock { .. }));
    }

    #[test]
    fn unlock_request_roundtrip() {
        let req = Request::Unlock { password: b"pw".to_vec(), yubikey_response: None, totp_code: None };
        let bytes = rmp_serde::to_vec_named(&req).unwrap();
        let decoded: Request = rmp_serde::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, Request::Unlock { .. }));
    }

    #[test]
    fn status_response_roundtrip() {
        let resp = Response::Status { locked: true };
        let bytes = rmp_serde::to_vec_named(&resp).unwrap();
        let decoded: Response = rmp_serde::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, Response::Status { locked: true }));
    }

    #[test]
    fn error_response_roundtrip() {
        let resp = Response::Error { code: 401, message: "session expired".into() };
        let bytes = rmp_serde::to_vec_named(&resp).unwrap();
        let decoded: Response = rmp_serde::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, Response::Error { code: 401, .. }));
    }

    #[test]
    fn frame_size_constant_is_sane() {
        assert!(MAX_FRAME_SIZE > 0);
        assert!(MAX_FRAME_SIZE < u32::MAX as usize);
    }

    /// D-06: deny_unknown_fields — a Request frame with extra keys must be rejected.
    #[test]
    fn ipc_strict_unknown_field_request() {
        // Build a well-formed Lock request, then inject a spurious "evil" field
        // into the payload map using raw msgpack bytes via rmpv.
        use rmpv::{Value, Utf8String};
        let payload = Value::Map(vec![
            (Value::String(Utf8String::from("session_token")), Value::String(Utf8String::from("tok"))),
            (Value::String(Utf8String::from("evil_extra")),    Value::String(Utf8String::from("injected"))),
        ]);
        let frame = Value::Map(vec![
            (Value::String(Utf8String::from("cmd")),     Value::String(Utf8String::from("Lock"))),
            (Value::String(Utf8String::from("payload")), payload),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &frame).unwrap();
        let result: Result<Request, _> = rmp_serde::from_slice(&buf);
        assert!(result.is_err(), "Request with extra payload field must fail deserialization");
    }

    /// D-06: deny_unknown_fields — a Response frame with extra keys must be rejected.
    #[test]
    fn ipc_strict_unknown_field_response() {
        use rmpv::{Value, Utf8String};
        let data = Value::Map(vec![
            (Value::String(Utf8String::from("locked")),     Value::Boolean(false)),
            (Value::String(Utf8String::from("evil_extra")), Value::Boolean(true)),
        ]);
        let frame = Value::Map(vec![
            (Value::String(Utf8String::from("status")), Value::String(Utf8String::from("Status"))),
            (Value::String(Utf8String::from("data")),   data),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &frame).unwrap();
        let result: Result<Response, _> = rmp_serde::from_slice(&buf);
        assert!(result.is_err(), "Response with extra data field must fail deserialization");
    }
}

