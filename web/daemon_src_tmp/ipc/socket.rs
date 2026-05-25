use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use tracing::{info, warn};
use rand_core::RngCore;
use zeroize::Zeroize;

use crate::auth::{fido2::{self as fido2_auth, DeviceBackend, FidoDevice}, totp};
use crate::crypto::hibp;
use crate::error::VaultError;
use crate::vault::{assets, audit, credentials, fido2_db, folders, pqc_db, state::{self, DaemonState, IDLE_TIMEOUT_SECS}, totp_db, user_profile};
use super::protocol::{self, Request, Response};

pub struct SocketListener {
    inner: UnixListener,
    state: Arc<DaemonState>,
}

impl SocketListener {
    /// Bind a new Unix domain socket at `path`.
    /// Removes a stale socket file if one exists.
    pub async fn bind(path: &Path, state: Arc<DaemonState>) -> Result<Self, VaultError> {
        // C-09: Ensure runtime socket directory has 0o700 permissions.
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
            } else {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        info!(path = %path.display(), "Unix socket bound");
        Ok(Self { inner: listener, state })
    }

    /// Accept connections in a loop; verify peercred on each.
    /// Spawns the idle auto-lock background task on start.
    pub async fn run(self) -> Result<(), VaultError> {
        let state = Arc::clone(&self.state);

        // Idle auto-lock: check every 60 seconds.
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            loop {
                ticker.tick().await;
                if !state.is_locked() && state.idle_secs() >= IDLE_TIMEOUT_SECS {
                    info!("idle timeout ({IDLE_TIMEOUT_SECS}s): locking vault");
                    state.lock();
                }
            }
        });

        use tokio::sync::Semaphore;
        let conn_limit = Arc::new(Semaphore::new(100)); // Max 100 concurrent IPC connections

        loop {
            let (stream, _addr) = self.inner.accept().await?;

            // H-07: Cap unauthenticated connections to 16 globally.
            if self.state.pre_auth_count.load(Ordering::Relaxed) >= 16 {
                warn!("Denying connection: global pre-auth cap (16) reached");
                continue;
            }
            self.state.pre_auth_count.fetch_add(1, Ordering::Relaxed);

            let permit = match conn_limit.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break Ok(()),
            };
            let uid = Self::peer_uid(&stream)?;
            static CONN_COUNTER: AtomicU64 = AtomicU64::new(1);
            let conn_id = CONN_COUNTER.fetch_add(1, Ordering::Relaxed);
            info!(uid, conn_id, "client connected");
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle_connection(stream, state, uid, conn_id).await {
                    warn!(err = %e, uid, "connection error");
                }
            });
        }
    }

    /// Extract the UID from SO_PEERCRED.
    fn peer_uid(stream: &UnixStream) -> Result<u32, VaultError> {
        let cred = getsockopt(stream, PeerCredentials)
            .map_err(|e| VaultError::Ipc(format!("SO_PEERCRED failed: {e}")))?;
        Ok(cred.uid())
    }
}

/// Maximum consecutive authentication failures per connection before dropping it (D-09).
const MAX_CONN_AUTH_FAILURES: u32 = 3;

struct PreAuthGuard(Arc<std::sync::atomic::AtomicU32>);
impl Drop for PreAuthGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// ── Connection handler ────────────────────────────────────────────────────────

async fn handle_connection(
    mut stream: UnixStream,
    state: Arc<DaemonState>,
    uid: u32,
    conn_id: u64,
) -> Result<(), VaultError> {
    let mut conn_auth_failures: u32 = 0;
    let mut auth_guard = Some(PreAuthGuard(state.pre_auth_count.clone()));

    loop {
        let frame = match protocol::read_frame(&mut stream).await {
            Ok(f) => f,
            Err(_) => break, // client disconnected or I/O error
        };

        let request: Request = match rmp_serde::from_slice(&frame) {
            Ok(r) => r,
            Err(e) => {
                // #23-FIX: malformed frames count toward the per-connection failure threshold.
                conn_auth_failures += 1;
                if conn_auth_failures >= MAX_CONN_AUTH_FAILURES {
                    warn!(uid, conn_auth_failures, "dropping connection after malformed frame threshold");
                    break;
                }
                let _ = send(&mut stream, Response::Error { code: 400, message: format!("bad request: {e}") }).await;
                continue;
            }
        };

        // SLA C1 + P4 + B5: dispatch under a panic guard AND a server-side
        // deadline. Panic → 500; deadline exceeded → DeadlineExceeded. The
        // in_flight / last_completion atomics power the progress-driven
        // watchdog.
        //
        // The 120 s deadline is the server-imposed maximum; clients may set
        // their own (shorter) per-RPC timeouts. End-to-end client-propagated
        // deadlines require a protocol bump and remain in the §4 backlog (B5).
        // 120 s accommodates the Argon2id duress-verify path which is
        // intentionally slow and CPU-bound (~90 s on a small VM).
        const DISPATCH_DEADLINE_SECS: u64 = 120;
        state.in_flight_requests.fetch_add(1, Ordering::Relaxed);
        let state_for_dispatch = Arc::clone(&state);
        let join_fut = tokio::spawn(async move {
            dispatch(&state_for_dispatch, uid, conn_id, request).await
        });
        let response = match tokio::time::timeout(
            std::time::Duration::from_secs(DISPATCH_DEADLINE_SECS),
            join_fut,
        ).await {
            Ok(Ok(r)) => r,
            Ok(Err(join_err)) => {
                let detail = if join_err.is_panic() {
                    let payload = join_err.into_panic();
                    if let Some(s) = payload.downcast_ref::<&str>() { s.to_string() }
                    else if let Some(s) = payload.downcast_ref::<String>() { s.clone() }
                    else { "unknown panic".to_string() }
                } else {
                    "task cancelled".to_string()
                };
                tracing::error!(uid, conn_id, panic = %detail, "dispatch PANIC — returning 500, daemon continues");
                Response::Error { code: 500, message: "internal error".into() }
            }
            Err(_elapsed) => {
                tracing::warn!(uid, conn_id, "dispatch DEADLINE_EXCEEDED ({}s) — returning 504", DISPATCH_DEADLINE_SECS);
                Response::Error { code: 504, message: "deadline exceeded".into() }
            }
        };
        state.in_flight_requests.fetch_sub(1, Ordering::Relaxed);
        state.last_completion_secs.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0),
            Ordering::Relaxed,
        );

        // H-07: successfully authenticated connections no longer count against the pre-auth cap.
        if let Response::Unlocked { .. } = &response {
            let _ = auth_guard.take();
        }

        // #23-FIX: count ALL error responses (not just 401) toward per-connection threshold.
        if let Response::Error { .. } = &response {
            conn_auth_failures += 1;
            if conn_auth_failures >= MAX_CONN_AUTH_FAILURES {
                warn!(uid, conn_auth_failures, "dropping connection after auth failure threshold");
                let _ = send(&mut stream, response).await;
                break;
            }
        }
        if send(&mut stream, response).await.is_err() {
            break;
        }
    }
    Ok(())
}

async fn send(stream: &mut UnixStream, resp: Response) -> Result<(), VaultError> {
    let bytes = rmp_serde::to_vec_named(&resp)
        .map_err(|e| VaultError::Ipc(format!("serialize response: {e}")))?;
    protocol::write_frame(stream, &bytes).await
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

async fn dispatch(state: &DaemonState, uid: u32, conn_id: u64, request: Request) -> Response {
    match request {
        // ── Unauthenticated ──────────────────────────────────────────────────
        Request::Ping => Response::Pong,

        Request::GetStatus => Response::Status { locked: state.is_locked() },

        Request::GetLoginHints => match state.get_login_hints() {
            Ok(r) => r,
            Err(e) => err(500, e),
        },

        Request::Unlock { password, yubikey_response, totp_code } => {
            let yk: Option<[u8; 20]> = yubikey_response.and_then(|v| v.try_into().ok());
            match state.unlock(&password, yk.as_ref(), uid, conn_id) {
                Err(e) => Response::Error { code: 1, message: e.to_string() },
                Ok(sess) => {
                    // Check vault-level TOTP if active — must happen *after* unlock
                    // because we need the DB and VMK to read the TOTP secret.
                    let totp_ok = state.with_vmk(|vmk| {
                        let guard = state.db.lock().unwrap();
                        if let Some(conn) = guard.as_ref() {
                            if totp_db::is_active(conn) {
                                match totp_code.as_deref() {
                                    None => Err(VaultError::Auth("TOTP code required".into())),
                                    Some(code) => totp_db::verify_code(conn, vmk, code),
                                }
                            } else {
                                Ok(true)
                            }
                        } else {
                            Ok(true)
                        }
                    });
                    match totp_ok {
                        Err(e) => {
                            // TOTP check failed — re-lock and reject
                            state.lock();
                            Response::Error { code: 401, message: e.to_string() }
                        }
                        Ok(false) => {
                            state.lock();
                            Response::Error { code: 401, message: "invalid TOTP code".into() }
                        }
                        Ok(true) => {
                            let _ = state.audit_log("UNLOCK", Some(&sess.user_id));
                            let ticket = state.wipe_ticket_bytes().unwrap_or_default();
                            let vmk_guard = state.vmk_read_guard();
                            let (ct, nonce) = if let Some(vmk) = vmk_guard.as_ref() {
                                let mut vmk_bytes = [0u8; 32];
                                vmk_bytes.copy_from_slice(&vmk.as_bytes());
                                let res = state.encrypt_wipe_ticket(&ticket, &vmk_bytes).unwrap_or((vec![], vec![]));
                                vmk_bytes.zeroize();
                                res
                            } else { (vec![], vec![]) };
                            Response::Unlocked { session_token: sess.token, wipe_ticket_ciphertext: ct, wipe_ticket_nonce: nonce }
                        }
                    }
                }
            }
        }

        // ── FIDO2 unauthenticated ────────────────────────────────────────────
        Request::ListFido2Devices { session_token } => {
            auth_then!(state, uid, session_token, {
                let backend = FidoDevice::new();
                match backend.list_devices() {
                    Ok(paths) => Response::Fido2Devices(paths),
                    Err(e) => err(500, e),
                }
            })
        }

        Request::GetPasskeyChallenge => {
            let challenge = state.new_passkey_challenge();
            Response::PasskeyChallenge(challenge.to_vec())
        }

        Request::GetPqcChallenge => {
            let challenge = state.new_pqc_challenge();
            Response::PasskeyChallenge(challenge.to_vec())
        }

        Request::GetQuickUnlockChallenge => {
            let challenge = state.new_quick_unlock_challenge();
            Response::QuickUnlockChallenge(challenge.to_vec())
        }

        Request::UnlockWithPasskey { credential_id, auth_data, signature, client_data_json } => {
            match state.unlock_with_passkey(&credential_id, &auth_data, &signature, &client_data_json, uid, conn_id) {
                Ok(sess) => {
                    let _ = state.audit_log("UNLOCK_PASSKEY", Some(&sess.user_id));
                    let ticket = state.wipe_ticket_bytes().unwrap_or_default();
                    let vmk_guard = state.vmk_read_guard();
                    let (ct, nonce) = if let Some(vmk) = vmk_guard.as_ref() {
                        let mut vmk_bytes = [0u8; 32];
                        vmk_bytes.copy_from_slice(&vmk.as_bytes());
                        let res = state.encrypt_wipe_ticket(&ticket, &vmk_bytes).unwrap_or((vec![], vec![]));
                        vmk_bytes.zeroize();
                        res
                    } else { (vec![], vec![]) };
                    Response::Unlocked { session_token: sess.token, wipe_ticket_ciphertext: ct, wipe_ticket_nonce: nonce }
                }
                Err(e) => err(401, e),
            }
        }

        Request::UnlockWithPqc { credential_id, signature, kem_ciphertext, client_data_json } => {
            match state.unlock_with_pqc(uid, &credential_id, &signature, &kem_ciphertext, &client_data_json, conn_id) {
                Ok(sess) => {
                    let _ = state.audit_log("UNLOCK_PQC", Some(&sess.user_id));
                    let ticket = state.wipe_ticket_bytes().unwrap_or_default();
                    let vmk_guard = state.vmk_read_guard();
                    let (ct, nonce) = if let Some(vmk) = vmk_guard.as_ref() {
                        let mut vmk_bytes = [0u8; 32];
                        vmk_bytes.copy_from_slice(&vmk.as_bytes());
                        let res = state.encrypt_wipe_ticket(&ticket, &vmk_bytes).unwrap_or((vec![], vec![]));
                        vmk_bytes.zeroize();
                        res
                    } else { (vec![], vec![]) };
                    Response::Unlocked { session_token: sess.token, wipe_ticket_ciphertext: ct, wipe_ticket_nonce: nonce }
                }
                Err(e) => err(401, e),
            }
        }

        Request::QuickUnlock { credential_id, auth_data, signature, client_data_json, dbk } => {
            match state.quick_unlock(&credential_id, &auth_data, &signature, &client_data_json, &dbk, uid, conn_id) {
                Ok(sess) => {
                    let _ = state.audit_log("UNLOCK_QUICK", Some(&sess.user_id));
                    let ticket = state.wipe_ticket_bytes().unwrap_or_default();
                    let vmk_guard = state.vmk_read_guard();
                    let (ct, nonce) = if let Some(vmk) = vmk_guard.as_ref() {
                        let mut vmk_bytes = [0u8; 32];
                        vmk_bytes.copy_from_slice(&vmk.as_bytes());
                        let res = state.encrypt_wipe_ticket(&ticket, &vmk_bytes).unwrap_or((vec![], vec![]));
                        vmk_bytes.zeroize();
                        res
                    } else { (vec![], vec![]) };
                    Response::Unlocked { session_token: sess.token, wipe_ticket_ciphertext: ct, wipe_ticket_nonce: nonce }
                }
                Err(e) => err(401, e),
            }
        }

        // ── Forensic self-destruct (unauthenticated, ticket-gated) ──────────
        Request::ForensicWipe { wipe_ticket_ciphertext, wipe_ticket_nonce } => {
            let res = state.with_vmk(|vmk| {
                let ticket = state.decrypt_wipe_ticket(&wipe_ticket_ciphertext, &wipe_ticket_nonce, vmk)?;
                state.forensic_wipe(&ticket)
            });
            match res {
                Err(e) => Response::Error { code: 403, message: e.to_string() },
                Ok(()) => {
                    // Schedule process exit after the response frame has been sent.
                    // 300 ms is enough for the frame to flush through the WS proxy
                    // to the browser before the socket closes.
                    tokio::spawn(async {
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                        std::process::exit(0);
                    });
                    Response::WipeComplete
                }
            }
        }

        // ── Authenticated — validate session token first ─────────────────────
        Request::QuickUnlockEnroll { session_token, password, credential_id, pub_key_cbor, dbk } => {
            auth_then!(state, uid, session_token, {
                match state.quick_unlock_enroll(&password, &credential_id, &pub_key_cbor, &dbk) {
                    Ok(_) => Response::Ok,
                    Err(e) => err(500, e),
                }
            })
        }

        Request::QuickUnlockRevoke { session_token } => {
            auth_then!(state, uid, session_token, {
                match state.quick_unlock_revoke() {
                    Ok(_) => Response::Ok,
                    Err(e) => err(500, e),
                }
            })
        }

        Request::VerifyFido2Assertion { session_token, credential_id, auth_data, signature, client_data_json } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, _vmk, conn, _v_uuid, {
                    // Use a local Result-returning closure so `?` propagates cleanly.
                    let result: Result<Response, VaultError> = (|| {
                        let row = fido2_db::get_by_credential_id(conn, &credential_id)?;
                        
                        use sha2::{Sha256, Digest};
                        let cdh: [u8; 32] = Sha256::digest(&client_data_json).into();
                        let assertion = fido2_auth::AssertOutput {
                            credential_id: credential_id.clone(),
                            auth_data: auth_data.clone(),
                            signature: signature.clone(),
                        };
                        
                        let backend = FidoDevice::new();
                        backend.verify_assertion(&row.public_key_cbor, &assertion, &cdh, "localhost", true)?;

                        // Verify signature counter (anti-cloning)
                        if auth_data.len() >= 37 {
                            let mut count_bytes = [0u8; 4];
                            count_bytes.copy_from_slice(&auth_data[33..37]);
                            let new_count = u32::from_be_bytes(count_bytes);
                            if new_count > 0 && new_count <= row.sign_count {
                                return Err(VaultError::Auth("signature counter regression".into()));
                            }
                            fido2_db::update_sign_count(conn, &row.id, new_count)?;
                        }

                        Ok(Response::Ok)
                    })();
                    match result {
                        Ok(r) => r,
                        Err(e) => err(401, e),
                    }
                })
            })
        }

        Request::Lock { session_token } => {
            if let Err(e) = state.sessions.validate(&session_token, uid) {
                return Response::Error { code: 401, message: e.to_string() };
            }
            let _ = state.audit_log("LOCK", None);
            state.lock();
            Response::Locked
        }

        Request::ListFolders { session_token } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, v_uuid, {
                    match folders::list(conn, vmk, &v_uuid) {
                        Ok(list) => match serde_json::to_vec(&list) {
                            Ok(bytes) => Response::Folders(bytes),
                            Err(e) => err(500, VaultError::Crypto(e.to_string())),
                        },
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::AddFolder { session_token, name, description, icon_svg } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, v_uuid, {
                    match folders::add(conn, vmk, &v_uuid, &name, description.as_deref(), icon_svg.as_deref()) {
                        Ok(id) => {
                            let _ = audit::log(conn, vmk, "FOLDER_ADD", Some(&id.to_string()));
                            Response::Created { id }
                        }
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::UpdateFolder { session_token, id, name, description, icon_svg } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, v_uuid, {
                    match folders::update(conn, vmk, &v_uuid, id, &name, description.as_deref(), icon_svg.as_deref()) {
                        Ok(()) => {
                            let _ = audit::log(conn, vmk, "FOLDER_UPDATE", Some(&id.to_string()));
                            Response::Ok
                        }
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::DeleteFolder { session_token, id, move_credentials_to } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match folders::delete(conn, id, move_credentials_to) {
                        Ok(()) => {
                            let _ = audit::log(conn, vmk, "FOLDER_DELETE", Some(&id.to_string()));
                            Response::Ok
                        }
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::ReorderFolders { session_token, ordered_ids } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match folders::reorder(conn, &ordered_ids) {
                        Ok(()) => Response::Ok,
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::ListCredentials { session_token, folder_id } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match credentials::list(conn, folder_id) {
                        Ok(list) => match serde_json::to_vec(&list) {
                            Ok(bytes) => Response::Credentials(bytes),
                            Err(e) => err(500, VaultError::Crypto(e.to_string())),
                        },
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::GetCredential { session_token, id } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match credentials::get(conn, vmk, id) {
                        Ok(blob) => Response::Credential(blob),
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::AddCredential { session_token, folder_id, blob } => {
            auth_then!(state, uid, session_token, {
                let vault_uuid = state.vault_uuid.lock().unwrap().clone()
                    .unwrap_or_default();
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    let bi_key = state.blind_index_key(vmk);
                    match credentials::add(conn, vmk, &bi_key, &vault_uuid, folder_id, &blob) {
                        Ok(id) => {
                            let _ = audit::log(conn, vmk, "CRED_ADD", Some(&id.to_string()));
                            Response::Created { id }
                        }
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::UpdateCredential { session_token, id, folder_id, blob } => {
            auth_then!(state, uid, session_token, {
                let vault_uuid = state.vault_uuid.lock().unwrap().clone()
                    .unwrap_or_default();
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    let bi_key = state.blind_index_key(vmk);
                    match credentials::update(conn, vmk, &bi_key, &vault_uuid, id, folder_id, &blob) {
                        Ok(()) => {
                            let _ = audit::log(conn, vmk, "CRED_UPDATE", Some(&id.to_string()));
                            Response::Ok
                        }
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::DeleteCredential { session_token, id } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match credentials::delete(conn, id) {
                        Ok(()) => {
                            let _ = audit::log(conn, vmk, "CRED_DELETE", Some(&id.to_string()));
                            Response::Ok
                        }
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::GetAssetHolder { session_token } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match assets::get(conn, vmk) {
                        Ok(Some(blob)) => Response::AssetHolder(blob),
                        Ok(None) => Response::AssetHolder(b"{}".to_vec()),
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::UpdateAssetHolder { session_token, blob } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match assets::update(conn, vmk, &blob) {
                        Ok(()) => {
                            let _ = audit::log(conn, vmk, "ASSET_UPDATE", None);
                            Response::Ok
                        }
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::GetOtpCode { session_token, credential_id } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    // Decrypt the credential to extract the OTP secret
                    match credentials::get(conn, vmk, credential_id) {
                        Err(e) => err(500, e),
                        Ok(blob) => {
                            match serde_json::from_slice::<serde_json::Value>(&blob) {
                                Err(e) => err(500, VaultError::Crypto(e.to_string())),
                                Ok(json) => {
                                    match json.get("otp_secret").and_then(|v| v.as_str()) {
                                        None => err(404, VaultError::Auth("no OTP secret on credential".into())),
                                        Some(secret) => {
                                            let algo_str = json.get("otp_algorithm").and_then(|v| v.as_str()).unwrap_or("SHA1");
                                            let digits = json.get("otp_digits").and_then(|v| v.as_u64()).unwrap_or(6) as usize;
                                            let algorithm = match algo_str {
                                                "SHA256" => totp_rs::Algorithm::SHA256,
                                                "SHA512" => totp_rs::Algorithm::SHA512,
                                                _ => totp_rs::Algorithm::SHA1,
                                            };
                                            match totp::current_code(secret, algorithm, digits) {
                                                Ok(code) => Response::OtpCode(code),
                                                Err(e) => err(500, e),
                                            }
                                        },
                                    }
                                }
                            }
                        }
                    }
                })
            })
        }

        // ── FIDO2 / Passkey management (authenticated) ───────────────────────

        Request::ListFido2Keys { session_token } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match fido2_db::list(conn) {
                        Ok(keys) => match serde_json::to_vec(&keys) {
                            Ok(bytes) => Response::Fido2Keys(bytes),
                            Err(e) => err(500, VaultError::Crypto(e.to_string())),
                        },
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::RegisterFido2 { session_token, device_path, name, resident_key } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    // Use a local Result-returning closure so `?` propagates cleanly.
                    let result: Result<Response, VaultError> = (|| {
                        let vault_uuid = state.vault_uuid.lock().unwrap().clone()
                            .unwrap_or_else(|| "default".into());
                        let challenge = state.new_passkey_challenge();
                        let user_id = vault_uuid.as_bytes().to_vec();

                        let backend = FidoDevice::new();
                        let reg = backend.make_credential(
                            &device_path, "vault.local", &user_id, &challenge, resident_key,
                        )?;

                        // For passkeys, derive wrap key and encrypt a copy of the VMK
                        let (enc_vmk, vmk_nonce): (Option<Vec<u8>>, Option<Vec<u8>>) = if resident_key {
                            let header = state.read_header()?;
                            let wrap_key = fido2_auth::derive_vmk_wrap_key(
                                &reg.auth_data, &reg.credential_id, header.kem_suite,
                            )?;
                            
                            let vmk: [u8; 32] = state.with_vmk(|v| Ok(*v))?;
                            let (ct, nonce) = crate::crypto::xchacha20::encrypt(&wrap_key, &vmk, b"passkey-vmk-aad-v1")?;

                            (Some(ct), Some(nonce.to_vec()))
                        } else {
                            (None, None)
                        };

                        let id = fido2_db::add(
                            conn,
                            &reg.credential_id,
                            &reg.public_key_cbor,
                            None,
                            resident_key,
                            enc_vmk.as_deref(),
                            vmk_nonce.as_deref(),
                            name.as_deref(),
                        )?;

                        // Passkeys: also persist to sidecar for passwordless unlock.
                        // F1-FIX: include public_key_cbor so unlock can verify assertions.
                        if resident_key {
                            if let (Some(ct), Some(nonce)) = (&enc_vmk, &vmk_nonce) {
                                let _ = state.add_passkey_to_sidecar(
                                    &reg.credential_id, ct, nonce, &reg.public_key_cbor,
                                );
                            }
                        }
                        let _ = audit::log(conn, vmk, "FIDO2_REGISTER", Some(&id.to_string()));
                        Ok(Response::Created { id })
                    })();
                    match result {
                        Ok(r) => r,
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::RemoveFido2 { session_token, id } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match fido2_db::remove(conn, &id) {
                        Ok(()) => {
                            let _ = audit::log(conn, vmk, "FIDO2_REMOVE", Some(&id));
                            Response::Ok
                        }
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::RegisterPqc { session_token, name, verifying_key, encapsulation_key } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    let result: Result<Response, VaultError> = (|| {
                        // 1. Generate daemon's static KEM seed for this authenticator
                        let mut dk_seed = [0u8; 64];
                        rand_core::OsRng.fill_bytes(&mut dk_seed);
                        
                        // 2. Encrypt seed with VMK
                        let (enc_seed, nonce) = crate::crypto::aes_gcm::encrypt(vmk, &dk_seed, b"pqc-dk-seed-aad-v1")?;
                        
                        // 3. Credential ID is SHA3-512(verifying_key)
                        use sha3::{Sha3_512, Digest};
                        let cred_id = Sha3_512::digest(&verifying_key).to_vec();

                        let id = pqc_db::add(conn, &cred_id, &verifying_key, &encapsulation_key, &enc_seed, &nonce, name.as_deref())?;

                        // Update sidecar for passwordless
                        let mut header = state.read_header()?;
                        if header.pqc_credentials.len() >= 16 {
                            return Err(VaultError::Auth("too many PQC credentials (max 16)".into()));
                        }
                        header.pqc_credentials.push(state::PqcSidecarEntry {
                            credential_id_hex: hex::encode(&cred_id),
                            verifying_key_hex: hex::encode(&verifying_key),
                            dk_seed_hex: hex::encode(&enc_seed),
                            dk_nonce_hex: hex::encode(&nonce),
                        });
                        state.write_header(&header)?;

                        let _ = audit::log(conn, vmk, "PQC_REGISTER", Some(&id.to_string()));
                        Ok(Response::Created { id })
                    })();
                    match result {
                        Ok(r) => r,
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        // ── Vault-level TOTP 2FA (authenticated) ─────────────────────────────

        Request::SetupVaultTotp { session_token } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match totp_db::begin_setup(conn, vmk, "vault", "VaultManager") {
                        Ok(info) => Response::TotpSetup {
                            secret_b32: info.secret_b32,
                            otp_uri: info.otp_uri,
                            backup_codes: info.backup_codes,
                        },
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::ConfirmVaultTotp { session_token, code } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match totp_db::confirm_setup(conn, vmk, &code) {
                        Ok(()) => {
                            let _ = audit::log(conn, vmk, "TOTP_ENABLE", None);
                            Response::Ok
                        }
                        Err(e) => err(400, e),
                    }
                })
            })
        }

        Request::RemoveVaultTotp { session_token, code } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match totp_db::remove(conn, vmk, &code) {
                        Ok(()) => {
                            let _ = audit::log(conn, vmk, "TOTP_DISABLE", None);
                            Response::Ok
                        }
                        Err(e) => err(400, e),
                    }
                })
            })
        }

        Request::GetVaultTotpStatus { session_token } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    Response::VaultTotpStatus { active: totp_db::is_active(conn) }
                })
            })
        }

        // ── HIBP breach check ─────────────────────────────────────────────────

        // ── Audit log ─────────────────────────────────────────────────────────

        Request::GetAuditLog { session_token, limit } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match audit::list(conn, limit) {
                        Ok(entries) => match serde_json::to_vec(&entries) {
                            Ok(bytes) => Response::AuditLog(bytes),
                            Err(e) => err(500, VaultError::Crypto(e.to_string())),
                        },
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::VerifyAuditChain { session_token } => {
            auth_then!(state, uid, session_token, {
                let _vmk = match state.with_vmk(|v| Ok(*v)) {
                    Ok(v) => v,
                    Err(e) => return err(401, e),
                };
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match audit::verify_chain(conn, &vmk) {
                        Ok(()) => Response::Ok,
                        Err(e) => err(409, e),
                    }
                })
            })
        }

        // ── HIBP breach check ─────────────────────────────────────────────────

        Request::CheckPasswordBreached { session_token, mut password_bytes } => {
            use zeroize::Zeroize;
            let resp = auth_then!(state, uid, session_token, {
                // Locate the HIBP filter from vault_meta (stored at setup time)
                let filter_path_opt: Option<String> = {
                    let guard = state.db.lock().unwrap();
                    guard.as_ref().and_then(|conn| {
                        conn.query_row(
                            "SELECT value FROM vault_meta WHERE key = 'hibp_filter_path'",
                            [],
                            |r| r.get(0),
                        ).ok()
                    })
                };
                match filter_path_opt {
                    None => Response::PwnedStatus { pwned: false, filter_available: false },
                    Some(path_str) => {
                        let path = std::path::Path::new(&path_str);
                        match hibp::check_password(path, &password_bytes) {
                            Ok(pwned) => Response::PwnedStatus { pwned, filter_available: true },
                            Err(_) => Response::PwnedStatus { pwned: false, filter_available: false },
                        }
                    }
                }
            });
            // Scrub the caller's plaintext as soon as the filter has consumed it;
            // the SHA-1 inside `check_password` is the only place these bytes
            // ever needed to be readable.
            password_bytes.zeroize();
            resp
        }

        // ── Backup-code unlock ────────────────────────────────────────────────

        Request::UnlockWithBackupCode { password, yubikey_response, backup_code } => {
            if backup_code.len() > 64 {
                return Response::Error { code: 400, message: "backup code too long".into() };
            }
            let yk: Option<[u8; 20]> = yubikey_response.and_then(|v| v.try_into().ok());
            match state.unlock(&password, yk.as_ref(), uid, conn_id) {
                Err(e) => Response::Error { code: 401, message: e.to_string() },
                Ok(sess) => {
                    // Backup code replaces TOTP — verify against stored hashes
                    let result = state.with_vmk(|vmk| {
                        let guard = state.db.lock().unwrap();
                        match guard.as_ref() {
                            None => Err(VaultError::Auth("vault locked after unlock (internal)".into())),
                            Some(conn) => {
                                if !totp_db::is_active(conn) {
                                    // TOTP not configured — backup codes don't apply
                                    return Err(VaultError::Auth("TOTP not configured; use normal Unlock".into()));
                                }
                                totp_db::verify_backup_code(conn, vmk, &backup_code)
                            }
                        }
                    });
                    match result {
                        Err(e) => {
                            state.lock();
                            state.record_failed_unlock(uid, conn_id);
                            Response::Error { code: 401, message: e.to_string() }
                        }
                        Ok(false) => {
                            state.lock();
                            state.record_failed_unlock(uid, conn_id);
                            Response::Error { code: 401, message: "invalid or already-used backup code".into() }
                        }
                        Ok(true) => {
                            state.reset_unlock_counter(uid, conn_id);
                            let _ = state.audit_log("UNLOCK_BACKUP_CODE", Some(&sess.user_id));
                            let ticket = state.wipe_ticket_bytes().unwrap_or_default();
                            let vmk_guard = state.vmk_read_guard();
                            let (ct, nonce) = if let Some(vmk) = vmk_guard.as_ref() {
                                let mut vmk_bytes = [0u8; 32];
                                vmk_bytes.copy_from_slice(&vmk.as_bytes());
                                let res = state.encrypt_wipe_ticket(&ticket, &vmk_bytes).unwrap_or((vec![], vec![]));
                                vmk_bytes.zeroize();
                                res
                            } else { (vec![], vec![]) };
                            Response::Unlocked { session_token: sess.token, wipe_ticket_ciphertext: ct, wipe_ticket_nonce: nonce }
                        }
                    }
                }
            }
        }

        // ── User profile ──────────────────────────────────────────────────────

        Request::GetProfile { session_token } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match user_profile::get(conn, vmk) {
                        Ok(None) => Response::Profile {
                            first_name: String::new(),
                            last_name: String::new(),
                            email: String::new(),
                            profile_pic: None,
                            password_changed_at: None,
                        },
                        Ok(Some(p)) => Response::Profile {
                            first_name: p.first_name,
                            last_name: p.last_name,
                            email: p.email,
                            profile_pic: p.profile_pic,
                            password_changed_at: p.password_changed_at,
                        },
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::UpdateProfile { session_token, first_name, last_name, email } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match user_profile::update(conn, vmk, &first_name, &last_name, &email) {
                        Ok(()) => {
                            let _ = audit::log(conn, vmk, "PROFILE_UPDATE", None);
                            Response::Ok
                        }
                        Err(e) => err(500, e),
                    }
                })
            })
        }

        Request::ChangePassword { session_token, old_password, new_password } => {
            auth_then!(state, uid, session_token, {
                match state.change_password(&old_password, &new_password, None, uid, conn_id) {
                    Ok(()) => {
                        // M-43 fix: revoke all other sessions for this user.
                        let v_uuid = state.vault_uuid_str();
                        state.sessions.revoke_all_except(&v_uuid, &session_token);
                        
                        with_vmk_db!(state, vmk, conn, _v_uuid, {
                            let _ = audit::log(conn, vmk, "PASSWORD_CHANGE", None);
                            Response::Ok
                        })
                    }
                    Err(e) => err(500, e),
                }
            })
        }

        Request::VerifyMasterPassword { session_token, password } => {
            auth_then!(state, uid, session_token, {
                match state.verify_master_password(&password, uid, conn_id) {
                    Ok(()) => Response::Ok,
                    Err(_) => Response::Error { code: 401, message: "InvalidPassword".into() },
                }
            })
        }

        Request::UpdateLoginPolicy { session_token, password_login_enabled, totp_enabled, email_otp_enabled } => {
            auth_then!(state, uid, session_token, {
                match state.update_login_policy(password_login_enabled, totp_enabled, email_otp_enabled) {
                    Ok(()) => Response::Ok,
                    Err(e) => err(500, e),
                }
            })
        }

        Request::UploadProfilePicture { session_token, image_bytes } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match user_profile::upload_picture(conn, vmk, &image_bytes) {
                        Ok(()) => {
                            let _ = audit::log(conn, vmk, "PROFILE_PIC_UPDATE", None);
                            Response::Ok
                        }
                        Err(e) => err(400, e),
                    }
                })
            })
        }

        Request::RemoveProfilePicture { session_token } => {
            auth_then!(state, uid, session_token, {
                with_vmk_db!(state, vmk, conn, _v_uuid, {
                    match user_profile::remove_picture(conn) {
                        Ok(()) => {
                            let _ = audit::log(conn, vmk, "PROFILE_PIC_REMOVE", None);
                            Response::Ok
                        }
                        Err(e) => err(500, e),
                    }
                })
            })
        }
    }
}

// ── Helper macros ─────────────────────────────────────────────────────────────

/// Validate session token, then evaluate `$body`. Returns Error{401} on
/// failure. Activity touches (session idle slide + vault idle timer) happen
/// AFTER `$body` produces a response — a slow handler therefore does not
/// count as user activity, closing the TOCTOU that would otherwise let a
/// client keep the session alive indefinitely via long requests.
macro_rules! auth_then {
    ($state:expr, $uid:expr, $token:expr, $body:block) => {{
        if let Err(e) = $state.sessions.validate(&$token, $uid) {
            Response::Error { code: 401, message: e.to_string() }
        } else {
            let __resp: Response = $body;
            $state.touch();
            $state.sessions.touch(&$token, crate::auth::session::DEFAULT_TTL_SECS);
            __resp
        }
    }};
}

/// Acquire both VMK and DB. Returns Error{503} if either is unavailable.
/// `$body` must evaluate to `Response`.
macro_rules! with_vmk_db {
    ($state:expr, $vmk:ident, $conn:ident, $vault_uuid:ident, $body:block) => {{
        let $vault_uuid = $state.vault_uuid_str();
        match $state.with_vmk(|$vmk| {
            #[allow(unused_variables)]
            let _vmk_ref = &$vmk;
            let guard = $state.db.lock().unwrap();
            match guard.as_ref() {
                None => Err(VaultError::Auth("vault is locked".into())),
                Some($conn) => Ok::<_, crate::error::VaultError>($body),
            }
        }) {
            Ok(r) => r,
            Err(e) => Response::Error { code: 503, message: e.to_string() },
        }
    }};
}

use auth_then;
use with_vmk_db;

// ── Small helpers ─────────────────────────────────────────────────────────────

fn err(code: u32, e: impl std::fmt::Display) -> Response {
    Response::Error { code, message: e.to_string() }
}
