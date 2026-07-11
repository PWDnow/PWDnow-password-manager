use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};
use rand_core::RngCore;
use zeroize::Zeroize;

use crate::auth::{fido2::{self as fido2_auth, DeviceBackend, FidoDevice}, totp};
use crate::crypto::hibp;
use crate::error::VaultError;
use crate::vault::{assets, audit, credentials, fido2_db, folders, pqc_db, state::{self, DaemonState}, totp_db, user_profile};

pub mod vault_proto {
    tonic::include_proto!("vault");
}

use vault_proto::vault_service_server::{VaultService, VaultServiceServer};

macro_rules! auth_then {
    ($state:expr, $uid:expr, $token:expr, $body:block) => {{
        if let Err(e) = $state.sessions.validate(&$token, $uid) {
            return Err(tonic::Status::unauthenticated(e.to_string()));
        } else {
            let __resp = $body;
            $state.touch();
            $state.sessions.touch(&$token, crate::auth::session::DEFAULT_TTL_SECS);
            __resp
        }
    }};
}

macro_rules! with_vmk_db {
    ($state:expr, $vmk:ident, $conn:ident, $vault_uuid:ident, $body:block) => {{
        let $vault_uuid = $state.vault_uuid_str();
        let res = $state.with_vmk(|$vmk| {
            #[allow(unused_variables)]
            let _vmk_ref = &$vmk;
            let guard = $state.db.lock().unwrap();
            match guard.as_ref() {
                None => Err(crate::error::VaultError::Auth("vault is locked".into())),
                Some($conn) => Ok($body),
            }
        });
        match res {
            Ok(r) => r,
            Err(e) => Err(tonic::Status::unavailable(e.to_string())),
        }
    }};
}

fn err(code: tonic::Code, e: impl std::fmt::Display) -> tonic::Status {
    tonic::Status::new(code, e.to_string())
}

pub struct GrpcServer {
    state: Arc<DaemonState>,
}

#[tonic::async_trait]
impl VaultService for GrpcServer {
    async fn ping(&self, _: Request<vault_proto::PingRequest>) -> Result<Response<vault_proto::PingResponse>, Status> {
        Ok(Response::new(vault_proto::PingResponse {}))
    }

    async fn get_status(&self, _: Request<vault_proto::GetStatusRequest>) -> Result<Response<vault_proto::StatusResponse>, Status> {
        Ok(Response::new(vault_proto::StatusResponse {
            locked: self.state.is_locked(),
        }))
    }

    async fn get_login_hints(&self, _: Request<vault_proto::GetLoginHintsRequest>) -> Result<Response<vault_proto::LoginHintsResponse>, Status> {
        match self.state.get_login_hints() {
            Ok(crate::ipc::protocol::Response::LoginHints { password_login_enabled, totp_enabled, email_otp_enabled, fido2_ids, quick_unlock_credentials, recovery_key_active }) => {
                Ok(Response::new(vault_proto::LoginHintsResponse {
                    password_login_enabled,
                    totp_enabled,
                    email_otp_enabled,
                    fido2_ids,
                    quick_unlock_credentials: quick_unlock_credentials.into_iter().map(|c| vault_proto::QuickUnlockCred { credential_id_hex: c.credential_id_hex, enc_kek: c.enc_kek, nonce: c.nonce, pub_key_cbor_hex: c.pub_key_cbor_hex, created_at: c.created_at }).collect(),
                    recovery_key_active
                }))
            }
            Err(e) => Err(err(tonic::Code::Internal, e)),
            _ => Err(err(tonic::Code::Internal, "Unexpected response")),
        }
    }

    async fn unlock(&self, request: Request<vault_proto::UnlockRequest>) -> Result<Response<vault_proto::UnlockedResponse>, Status> {
        let req = request.into_inner();
        let uid = 1000;
        let conn_id = 1;
        let yk: Option<[u8; 20]> = req.yubikey_response.and_then(|v| if v.is_empty() { None } else { v.try_into().ok() });
        match self.state.unlock(&req.password, yk.as_ref(), uid, conn_id) {
            Err(e) => Err(err(tonic::Code::Unauthenticated, e)),
            Ok(sess) => {
                let totp_ok = self.state.with_vmk(|vmk| {
                    let guard = self.state.db.lock().unwrap();
                    if let Some(conn) = guard.as_ref() {
                        if totp_db::is_active(conn) {
                            let tc = req.totp_code.as_ref().map(|s| s.as_str());
                            match tc {
                                None | Some("") => Err(VaultError::Auth("TOTP code required".into())),
                                Some(code) => totp_db::verify_code(conn, vmk, code),
                            }
                        } else { Ok(true) }
                    } else { Ok(true) }
                });
                match totp_ok {
                    Err(e) => {
                        // D1 fix: record a TOTP-specific failure (independent
                        // exponential lockout, not cleared by lock()) and
                        // re-lock the vault state without wiping either
                        // lockout tracker.
                        self.state.record_totp_failure(uid, conn_id);
                        self.state.lock_keep_lockout();
                        Err(err(tonic::Code::Unauthenticated, e))
                    }
                    Ok(false) => {
                        self.state.record_totp_failure(uid, conn_id);
                        self.state.lock_keep_lockout();
                        Err(err(tonic::Code::Unauthenticated, "invalid TOTP code"))
                    }
                    Ok(true) => {
                        // D3 fix: only now — once both factors have verified —
                        // clear the unlock-failure and TOTP-failure counters.
                        self.state.complete_unlock(uid, conn_id);
                        let _ = self.state.audit_log("UNLOCK", Some(&sess.user_id));
                        let ticket = self.state.wipe_ticket_bytes().unwrap_or_default();
                        let vmk_guard = self.state.vmk_read_guard();
                        let (ct, nonce) = if let Some(vmk) = vmk_guard.as_ref() {
                            let mut vmk_bytes = [0u8; 32];
                            vmk_bytes.copy_from_slice(&vmk.as_bytes());
                            let res = self.state.encrypt_wipe_ticket(&ticket, &vmk_bytes).unwrap_or((vec![], vec![]));
                            vmk_bytes.zeroize();
                            res
                        } else { (vec![], vec![]) };
                        Ok(Response::new(vault_proto::UnlockedResponse {
                            session_token: sess.token,
                            wipe_ticket_ciphertext: ct,
                            wipe_ticket_nonce: nonce,
                        }))
                    }
                }
            }
        }
    }

    async fn forensic_wipe(&self, request: Request<vault_proto::ForensicWipeRequest>) -> Result<Response<vault_proto::WipeCompleteResponse>, Status> {
        let req = request.into_inner();
        let ticket_res: Result<Vec<u8>, VaultError> = self.state.with_vmk(|vmk|
            self.state.decrypt_wipe_ticket(&req.wipe_ticket_ciphertext, &req.wipe_ticket_nonce, vmk));
        let res = ticket_res.and_then(|ticket| self.state.forensic_wipe(&ticket));
        match res {
            Err(e) => Err(err(tonic::Code::PermissionDenied, e)),
            Ok(()) => {
                tokio::spawn(async {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    std::process::exit(0);
                });
                Ok(Response::new(vault_proto::WipeCompleteResponse {}))
            }
        }
    }

    async fn get_passkey_challenge(&self, _: Request<vault_proto::GetPasskeyChallengeRequest>) -> Result<Response<vault_proto::PasskeyChallengeResponse>, Status> {
        let challenge = self.state.new_passkey_challenge();
        Ok(Response::new(vault_proto::PasskeyChallengeResponse {
            challenge: challenge.to_vec(),
        }))
    }

    async fn get_pqc_challenge(&self, _: Request<vault_proto::GetPqcChallengeRequest>) -> Result<Response<vault_proto::PqcChallengeResponse>, Status> {
        let challenge = self.state.new_pqc_challenge();
        Ok(Response::new(vault_proto::PqcChallengeResponse {
            challenge: challenge.to_vec(),
        }))
    }

    async fn unlock_with_passkey(&self, request: Request<vault_proto::UnlockWithPasskeyRequest>) -> Result<Response<vault_proto::UnlockedResponse>, Status> {
        let req = request.into_inner();
        match self.state.unlock_with_passkey(&req.credential_id, &req.auth_data, &req.signature, &req.client_data_json, 1000, 1) {
            Ok(sess) => {
                let _ = self.state.audit_log("UNLOCK_PASSKEY", Some(&sess.user_id));
                let ticket = self.state.wipe_ticket_bytes().unwrap_or_default();
                let vmk_guard = self.state.vmk_read_guard();
                let (ct, nonce) = if let Some(vmk) = vmk_guard.as_ref() {
                    let mut vmk_bytes = [0u8; 32];
                    vmk_bytes.copy_from_slice(&vmk.as_bytes());
                    let res = self.state.encrypt_wipe_ticket(&ticket, &vmk_bytes).unwrap_or((vec![], vec![]));
                    vmk_bytes.zeroize();
                    res
                } else { (vec![], vec![]) };
                Ok(Response::new(vault_proto::UnlockedResponse {
                    session_token: sess.token,
                    wipe_ticket_ciphertext: ct,
                    wipe_ticket_nonce: nonce,
                }))
            }
            Err(e) => Err(err(tonic::Code::Unauthenticated, e)),
        }
    }

    async fn unlock_with_pqc(&self, request: Request<vault_proto::UnlockWithPqcRequest>) -> Result<Response<vault_proto::UnlockedResponse>, Status> {
        let req = request.into_inner();
        match self.state.unlock_with_pqc(1000, &req.credential_id, &req.signature, &req.kem_ciphertext, &req.client_data_json, 1) {
            Ok(sess) => {
                let _ = self.state.audit_log("UNLOCK_PQC", Some(&sess.user_id));
                let ticket = self.state.wipe_ticket_bytes().unwrap_or_default();
                let vmk_guard = self.state.vmk_read_guard();
                let (ct, nonce) = if let Some(vmk) = vmk_guard.as_ref() {
                    let mut vmk_bytes = [0u8; 32];
                    vmk_bytes.copy_from_slice(&vmk.as_bytes());
                    let res = self.state.encrypt_wipe_ticket(&ticket, &vmk_bytes).unwrap_or((vec![], vec![]));
                    vmk_bytes.zeroize();
                    res
                } else { (vec![], vec![]) };
                Ok(Response::new(vault_proto::UnlockedResponse {
                    session_token: sess.token,
                    wipe_ticket_ciphertext: ct,
                    wipe_ticket_nonce: nonce,
                }))
            }
            Err(e) => Err(err(tonic::Code::Unauthenticated, e)),
        }
    }

    async fn list_fido2_devices(&self, request: Request<vault_proto::ListFido2DevicesRequest>) -> Result<Response<vault_proto::Fido2DevicesResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            let backend = FidoDevice::new();
            match backend.list_devices() {
                Ok(paths) => Ok(Response::new(vault_proto::Fido2DevicesResponse { paths })),
                Err(e) => Err(err(tonic::Code::Internal, e)),
            }
        })
    }

    async fn verify_fido2_assertion(&self, request: Request<vault_proto::VerifyFido2AssertionRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, _vmk, conn, _v_uuid, {
                let row = fido2_db::get_by_credential_id(conn, &req.credential_id)?;
                use sha2::{Sha256, Digest};
                let cdh: [u8; 32] = Sha256::digest(&req.client_data_json).into();
                let assertion = fido2_auth::AssertOutput {
                    credential_id: req.credential_id.clone(),
                    auth_data: req.auth_data.clone(),
                    signature: req.signature.clone(),
                };
                let backend = FidoDevice::new();
                backend.verify_assertion(&row.public_key_cbor, &assertion, &cdh, "localhost", true)?;

                if req.auth_data.len() >= 37 {
                    let mut count_bytes = [0u8; 4];
                    count_bytes.copy_from_slice(&req.auth_data[33..37]);
                    let new_count = u32::from_be_bytes(count_bytes);
                    if new_count > 0 && new_count <= row.sign_count {
                        return Err(VaultError::Auth("signature counter regression".into()));
                    }
                    fido2_db::update_sign_count(conn, &row.id, new_count)?;
                }
                Ok(Response::new(vault_proto::OkResponse {}))
            })
        })
    }

    async fn get_quick_unlock_challenge(&self, _: Request<vault_proto::GetQuickUnlockChallengeRequest>) -> Result<Response<vault_proto::QuickUnlockChallengeResponse>, Status> {
        let challenge = self.state.new_quick_unlock_challenge();
        Ok(Response::new(vault_proto::QuickUnlockChallengeResponse {
            challenge: challenge.to_vec(),
        }))
    }

    async fn quick_unlock(&self, request: Request<vault_proto::QuickUnlockRequest>) -> Result<Response<vault_proto::UnlockedResponse>, Status> {
        let req = request.into_inner();
        match self.state.quick_unlock(&req.credential_id, &req.auth_data, &req.signature, &req.client_data_json, &req.dbk, 1000, 1) {
            Ok(sess) => {
                let _ = self.state.audit_log("UNLOCK_QUICK", Some(&sess.user_id));
                let ticket = self.state.wipe_ticket_bytes().unwrap_or_default();
                let vmk_guard = self.state.vmk_read_guard();
                let (ct, nonce) = if let Some(vmk) = vmk_guard.as_ref() {
                    let mut vmk_bytes = [0u8; 32];
                    vmk_bytes.copy_from_slice(&vmk.as_bytes());
                    let res = self.state.encrypt_wipe_ticket(&ticket, &vmk_bytes).unwrap_or((vec![], vec![]));
                    vmk_bytes.zeroize();
                    res
                } else { (vec![], vec![]) };
                Ok(Response::new(vault_proto::UnlockedResponse {
                    session_token: sess.token,
                    wipe_ticket_ciphertext: ct,
                    wipe_ticket_nonce: nonce,
                }))
            }
            Err(e) => Err(err(tonic::Code::Unauthenticated, e)),
        }
    }

    async fn quick_unlock_enroll(&self, request: Request<vault_proto::QuickUnlockEnrollRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            match self.state.quick_unlock_enroll(&req.password, &req.credential_id, &req.pub_key_cbor, &req.dbk) {
                Ok(_) => Ok(Response::new(vault_proto::OkResponse {})),
                Err(e) => Err(err(tonic::Code::Internal, e)),
            }
        })
    }

    async fn quick_unlock_revoke(&self, request: Request<vault_proto::QuickUnlockRevokeRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            match self.state.quick_unlock_revoke() {
                Ok(_) => Ok(Response::new(vault_proto::OkResponse {})),
                Err(e) => Err(err(tonic::Code::Internal, e)),
            }
        })
    }

    async fn enroll_recovery_key(&self, request: Request<vault_proto::EnrollRecoveryKeyRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            match self.state.enroll_recovery_key(&req.recovery_key) {
                Ok(_) => Ok(Response::new(vault_proto::OkResponse {})),
                Err(e) => Err(err(tonic::Code::Internal, e)),
            }
        })
    }

    async fn unlock_with_recovery_key(&self, request: Request<vault_proto::UnlockWithRecoveryKeyRequest>) -> Result<Response<vault_proto::UnlockedResponse>, Status> {
        let req = request.into_inner();
        match self.state.unlock_with_recovery_key(&req.recovery_key, 1000, 1) {
            Err(e) => {
                self.state.record_failed_unlock(1000, 1);
                Err(err(tonic::Code::Unauthenticated, e))
            }
            Ok(sess) => {
                let _ = self.state.audit_log("UNLOCK_RECOVERY", Some(&sess.user_id));
                let ticket = self.state.wipe_ticket_bytes().unwrap_or_default();
                let vmk_guard = self.state.vmk_read_guard();
                let (ct, nonce) = if let Some(vmk) = vmk_guard.as_ref() {
                    let mut vmk_bytes = [0u8; 32];
                    vmk_bytes.copy_from_slice(&vmk.as_bytes());
                    let res = self.state.encrypt_wipe_ticket(&ticket, &vmk_bytes).unwrap_or((vec![], vec![]));
                    vmk_bytes.zeroize();
                    res
                } else { (vec![], vec![]) };
                Ok(Response::new(vault_proto::UnlockedResponse {
                    session_token: sess.token,
                    wipe_ticket_ciphertext: ct,
                    wipe_ticket_nonce: nonce,
                }))
            }
        }
    }

    async fn lock(&self, request: Request<vault_proto::LockRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        if let Err(e) = self.state.sessions.validate(&req.session_token, 1000) {
            return Err(err(tonic::Code::Unauthenticated, e));
        }
        let _ = self.state.audit_log("LOCK", None);
        self.state.lock();
        Ok(Response::new(vault_proto::OkResponse {}))
    }

    async fn list_folders(&self, request: Request<vault_proto::ListFoldersRequest>) -> Result<Response<vault_proto::FoldersResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, v_uuid, {
                match folders::list(conn, vmk, &v_uuid) {
                    Ok(list) => match serde_json::to_vec(&list) {
                        Ok(bytes) => Ok(Response::new(vault_proto::FoldersResponse { data: bytes })),
                        Err(e) => Err(err(tonic::Code::Internal, VaultError::Crypto(e.to_string()))),
                    },
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn add_folder(&self, request: Request<vault_proto::AddFolderRequest>) -> Result<Response<vault_proto::CreatedResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, v_uuid, {
                match folders::add(conn, vmk, &v_uuid, &req.name, req.description.as_deref(), req.icon_svg.as_deref()) {
                    Ok(id) => {
                        let _ = audit::log(conn, vmk, "FOLDER_ADD", Some(&id.to_string()));
                        Ok(Response::new(vault_proto::CreatedResponse { id: id.to_string() }))
                    }
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn update_folder(&self, request: Request<vault_proto::UpdateFolderRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, v_uuid, {
                match folders::update(conn, vmk, &v_uuid, uuid::Uuid::parse_str(&req.id).map_err(|e| crate::error::VaultError::Ipc(e.to_string()))?, &req.name, req.description.as_deref(), req.icon_svg.as_deref()) {
                    Ok(()) => {
                        let _ = audit::log(conn, vmk, "FOLDER_UPDATE", Some(req.id.as_str()));
                        Ok(Response::new(vault_proto::OkResponse {}))
                    }
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn delete_folder(&self, request: Request<vault_proto::DeleteFolderRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match folders::delete(conn, uuid::Uuid::parse_str(&req.id).map_err(|e| crate::error::VaultError::Ipc(e.to_string()))?, req.move_credentials_to.as_deref().filter(|s| !s.is_empty()).map(|s| uuid::Uuid::parse_str(s)).transpose().map_err(|e| crate::error::VaultError::Ipc(e.to_string()))?) {
                    Ok(()) => {
                        let _ = audit::log(conn, vmk, "FOLDER_DELETE", Some(req.id.as_str()));
                        Ok(Response::new(vault_proto::OkResponse {}))
                    }
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn reorder_folders(&self, request: Request<vault_proto::ReorderFoldersRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match folders::reorder(conn, &req.ordered_ids.iter().map(|s| uuid::Uuid::parse_str(s)).collect::<Result<Vec<_>, _>>().map_err(|e| crate::error::VaultError::Ipc(e.to_string()))?) {
                    Ok(()) => Ok(Response::new(vault_proto::OkResponse {})),
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn list_credentials(&self, request: Request<vault_proto::ListCredentialsRequest>) -> Result<Response<vault_proto::CredentialsResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match credentials::list(conn, req.folder_id.as_deref().filter(|s| !s.is_empty()).map(|s| uuid::Uuid::parse_str(s)).transpose().map_err(|e| crate::error::VaultError::Ipc(e.to_string()))?) {
                    Ok(list) => match serde_json::to_vec(&list) {
                        Ok(bytes) => Ok(Response::new(vault_proto::CredentialsResponse { data: bytes })),
                        Err(e) => Err(err(tonic::Code::Internal, VaultError::Crypto(e.to_string()))),
                    },
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn get_credential(&self, request: Request<vault_proto::GetCredentialRequest>) -> Result<Response<vault_proto::CredentialResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match credentials::get(conn, vmk, uuid::Uuid::parse_str(&req.id).map_err(|e| crate::error::VaultError::Ipc(e.to_string()))?) {
                    Ok(blob) => Ok(Response::new(vault_proto::CredentialResponse { data: blob })),
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn add_credential(&self, request: Request<vault_proto::AddCredentialRequest>) -> Result<Response<vault_proto::CreatedResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            let vault_uuid = self.state.vault_uuid.lock().unwrap().clone().unwrap_or_default();
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                let bi_key = self.state.blind_index_key(vmk);
                match credentials::add(conn, vmk, &bi_key, &vault_uuid, req.folder_id.as_deref().filter(|s| !s.is_empty()).map(|s| uuid::Uuid::parse_str(s)).transpose().map_err(|e| crate::error::VaultError::Ipc(e.to_string()))?, &req.blob) {
                    Ok(id) => {
                        let _ = audit::log(conn, vmk, "CRED_ADD", Some(&id.to_string()));
                        Ok(Response::new(vault_proto::CreatedResponse { id: id.to_string() }))
                    }
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn update_credential(&self, request: Request<vault_proto::UpdateCredentialRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            let vault_uuid = self.state.vault_uuid.lock().unwrap().clone().unwrap_or_default();
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                let bi_key = self.state.blind_index_key(vmk);
                match credentials::update(conn, vmk, &bi_key, &vault_uuid, uuid::Uuid::parse_str(&req.id).map_err(|e| crate::error::VaultError::Ipc(e.to_string()))?, req.folder_id.as_deref().filter(|s| !s.is_empty()).map(|s| uuid::Uuid::parse_str(s)).transpose().map_err(|e| crate::error::VaultError::Ipc(e.to_string()))?, &req.blob) {
                    Ok(()) => {
                        let _ = audit::log(conn, vmk, "CRED_UPDATE", Some(req.id.as_str()));
                        Ok(Response::new(vault_proto::OkResponse {}))
                    }
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn delete_credential(&self, request: Request<vault_proto::DeleteCredentialRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match credentials::delete(conn, uuid::Uuid::parse_str(&req.id).map_err(|e| crate::error::VaultError::Ipc(e.to_string()))?) {
                    Ok(()) => {
                        let _ = audit::log(conn, vmk, "CRED_DELETE", Some(req.id.as_str()));
                        Ok(Response::new(vault_proto::OkResponse {}))
                    }
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn get_asset_holder(&self, request: Request<vault_proto::GetAssetHolderRequest>) -> Result<Response<vault_proto::AssetHolderResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match assets::get(conn, vmk) {
                    Ok(Some(blob)) => Ok(Response::new(vault_proto::AssetHolderResponse { data: blob })),
                    Ok(None) => Ok(Response::new(vault_proto::AssetHolderResponse { data: b"{}".to_vec() })),
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn update_asset_holder(&self, request: Request<vault_proto::UpdateAssetHolderRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match assets::update(conn, vmk, &req.blob) {
                    Ok(()) => {
                        let _ = audit::log(conn, vmk, "ASSET_UPDATE", None);
                        Ok(Response::new(vault_proto::OkResponse {}))
                    }
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn get_otp_code(&self, request: Request<vault_proto::GetOtpCodeRequest>) -> Result<Response<vault_proto::OtpCodeResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match credentials::get(conn, vmk, uuid::Uuid::parse_str(&req.credential_id).map_err(|e| crate::error::VaultError::Ipc(e.to_string()))?) {
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                    Ok(blob) => {
                        match serde_json::from_slice::<serde_json::Value>(&blob) {
                            Err(e) => Err(err(tonic::Code::Internal, VaultError::Crypto(e.to_string()))),
                            Ok(json) => {
                                match json.get("otp_secret").and_then(|v| v.as_str()) {
                                    None => Err(err(tonic::Code::NotFound, VaultError::Auth("no OTP secret on credential".into()))),
                                    Some(secret) => {
                                        let algo_str = json.get("otp_algorithm").and_then(|v| v.as_str()).unwrap_or("SHA1");
                                        let digits = json.get("otp_digits").and_then(|v| v.as_u64()).unwrap_or(6) as usize;
                                        let algorithm = match algo_str {
                                            "SHA256" => totp_rs::Algorithm::SHA256,
                                            "SHA512" => totp_rs::Algorithm::SHA512,
                                            _ => totp_rs::Algorithm::SHA1,
                                        };
                                        match totp::current_code(secret, algorithm, digits) {
                                            Ok(code) => Ok(Response::new(vault_proto::OtpCodeResponse { code })),
                                            Err(e) => Err(err(tonic::Code::Internal, e)),
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

    async fn list_fido2_keys(&self, request: Request<vault_proto::ListFido2KeysRequest>) -> Result<Response<vault_proto::Fido2KeysResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match fido2_db::list(conn) {
                    Ok(keys) => match serde_json::to_vec(&keys) {
                        Ok(bytes) => Ok(Response::new(vault_proto::Fido2KeysResponse { data: bytes })),
                        Err(e) => Err(err(tonic::Code::Internal, VaultError::Crypto(e.to_string()))),
                    },
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn register_fido2(&self, request: Request<vault_proto::RegisterFido2Request>) -> Result<Response<vault_proto::CreatedResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                let vault_uuid = self.state.vault_uuid.lock().unwrap().clone().unwrap_or_else(|| "default".into());
                let challenge = self.state.new_passkey_challenge();
                let user_id = vault_uuid.as_bytes().to_vec();

                let backend = FidoDevice::new();
                let reg = backend.make_credential(&req.device_path, "vault.local", &user_id, &challenge, req.resident_key)?;

                let (enc_vmk, vmk_nonce): (Option<Vec<u8>>, Option<Vec<u8>>) = if req.resident_key {
                    let header = self.state.read_header()?;
                    let wrap_key = fido2_auth::derive_vmk_wrap_key(&reg.auth_data, &reg.credential_id, header.kem_suite)?;
                    let vmk_val: [u8; 32] = self.state.with_vmk(|v| Ok(*v))?;
                    let (ct, nonce) = crate::crypto::xchacha20::encrypt(&wrap_key, &vmk_val, b"passkey-vmk-aad-v1")?;
                    (Some(ct), Some(nonce.to_vec()))
                } else { (None, None) };

                let id = fido2_db::add(
                    conn,
                    &reg.credential_id,
                    &reg.public_key_cbor,
                    None,
                    req.resident_key,
                    enc_vmk.as_deref(),
                    vmk_nonce.as_deref(),
                    req.name.as_deref(),
                )?;

                if req.resident_key {
                    if let (Some(ct), Some(nonce)) = (&enc_vmk, &vmk_nonce) {
                        let _ = self.state.add_passkey_to_sidecar(&reg.credential_id, ct, nonce, &reg.public_key_cbor);
                    }
                }
                let _ = audit::log(conn, vmk, "FIDO2_REGISTER", Some(&id.to_string()));
                Ok(Response::new(vault_proto::CreatedResponse { id: id.to_string() }))
            })
        })
    }

    async fn remove_fido2(&self, request: Request<vault_proto::RemoveFido2Request>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match fido2_db::remove(conn, &req.id) {
                    Ok(()) => {
                        let _ = audit::log(conn, vmk, "FIDO2_REMOVE", Some(req.id.as_str()));
                        Ok(Response::new(vault_proto::OkResponse {}))
                    }
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn register_pqc(&self, request: Request<vault_proto::RegisterPqcRequest>) -> Result<Response<vault_proto::CreatedResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                let mut dk_seed = [0u8; 64];
                rand_core::OsRng.fill_bytes(&mut dk_seed);
                let (enc_seed, nonce) = crate::crypto::aes_gcm::encrypt(vmk, &dk_seed, b"pqc-dk-seed-aad-v1")?;
                use sha3::{Sha3_512, Digest};
                let cred_id = Sha3_512::digest(&req.verifying_key).to_vec();

                let id = pqc_db::add(conn, &cred_id, &req.verifying_key, &req.encapsulation_key, &enc_seed, &nonce, req.name.as_deref())?;

                let mut header = self.state.read_header()?;
                if header.pqc_credentials.len() >= 16 {
                    return Err(VaultError::Auth("too many PQC credentials (max 16)".into()));
                }
                header.pqc_credentials.push(state::PqcSidecarEntry {
                    credential_id_hex: hex::encode(&cred_id),
                    verifying_key_hex: hex::encode(&req.verifying_key),
                    dk_seed_hex: hex::encode(&enc_seed),
                    dk_nonce_hex: hex::encode(&nonce),
                });
                self.state.write_header(&header)?;

                let _ = audit::log(conn, vmk, "PQC_REGISTER", Some(&id.to_string()));
                Ok(Response::new(vault_proto::CreatedResponse { id: id.to_string() }))
            })
        })
    }

    async fn setup_vault_totp(&self, request: Request<vault_proto::SetupVaultTotpRequest>) -> Result<Response<vault_proto::TotpSetupResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match totp_db::begin_setup(conn, vmk, "vault", "VaultManager") {
                    Ok(info) => Ok(Response::new(vault_proto::TotpSetupResponse {
                        secret_b32: info.secret_b32,
                        otp_uri: info.otp_uri,
                        backup_codes: info.backup_codes,
                    })),
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn confirm_vault_totp(&self, request: Request<vault_proto::ConfirmVaultTotpRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match totp_db::confirm_setup(conn, vmk, &req.code) {
                    Ok(()) => {
                        let _ = audit::log(conn, vmk, "TOTP_ENABLE", None);
                        Ok(Response::new(vault_proto::OkResponse {}))
                    }
                    Err(e) => Err(err(tonic::Code::InvalidArgument, e)),
                }
            })
        })
    }

    async fn remove_vault_totp(&self, request: Request<vault_proto::RemoveVaultTotpRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match totp_db::remove(conn, vmk, &req.code) {
                    Ok(()) => {
                        let _ = audit::log(conn, vmk, "TOTP_DISABLE", None);
                        Ok(Response::new(vault_proto::OkResponse {}))
                    }
                    Err(e) => Err(err(tonic::Code::InvalidArgument, e)),
                }
            })
        })
    }

    async fn get_vault_totp_status(&self, request: Request<vault_proto::GetVaultTotpStatusRequest>) -> Result<Response<vault_proto::VaultTotpStatusResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                Ok(Response::new(vault_proto::VaultTotpStatusResponse { active: totp_db::is_active(conn) }))
            })
        })
    }

    async fn check_password_breached(&self, request: Request<vault_proto::CheckPasswordBreachedRequest>) -> Result<Response<vault_proto::PwnedStatusResponse>, Status> {
        let mut req = request.into_inner();
        let resp = auth_then!(self.state, 1000, req.session_token, {
            let filter_path_opt: Option<String> = {
                let guard = self.state.db.lock().unwrap();
                guard.as_ref().and_then(|conn| {
                    conn.query_row("SELECT value FROM vault_meta WHERE key = 'hibp_filter_path'", [], |r| r.get(0)).ok()
                })
            };
            match filter_path_opt {
                None => Ok(Response::new(vault_proto::PwnedStatusResponse { pwned: false, filter_available: false })),
                Some(path_str) => {
                    let path = std::path::Path::new(&path_str);
                    match hibp::check_password(path, &req.password_bytes) {
                        Ok(pwned) => Ok(Response::new(vault_proto::PwnedStatusResponse { pwned, filter_available: true })),
                        Err(_) => Ok(Response::new(vault_proto::PwnedStatusResponse { pwned: false, filter_available: false })),
                    }
                }
            }
        });
        req.password_bytes.zeroize();
        resp
    }

    async fn get_audit_log(&self, request: Request<vault_proto::GetAuditLogRequest>) -> Result<Response<vault_proto::AuditLogResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match audit::list(conn, req.limit) {
                    Ok(entries) => match serde_json::to_vec(&entries) {
                        Ok(bytes) => Ok(Response::new(vault_proto::AuditLogResponse { data: bytes })),
                        Err(e) => Err(err(tonic::Code::Internal, VaultError::Crypto(e.to_string()))),
                    },
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn verify_audit_chain(&self, request: Request<vault_proto::VerifyAuditChainRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            let _vmk = match self.state.with_vmk(|v| Ok(*v)) {
                Ok(v) => v,
                Err(e) => return Err(err(tonic::Code::Unauthenticated, e)),
            };
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match audit::verify_chain(conn, &vmk) {
                    Ok(()) => Ok(Response::new(vault_proto::OkResponse {})),
                    Err(e) => Err(err(tonic::Code::FailedPrecondition, e)),
                }
            })
        })
    }

    async fn unlock_with_backup_code(&self, request: Request<vault_proto::UnlockWithBackupCodeRequest>) -> Result<Response<vault_proto::UnlockedResponse>, Status> {
        let req = request.into_inner();
        if req.backup_code.len() > 64 {
            return Err(err(tonic::Code::InvalidArgument, "backup code too long"));
        }
        let yk: Option<[u8; 20]> = req.yubikey_response.and_then(|v| if v.is_empty() { None } else { v.try_into().ok() });
        match self.state.unlock(&req.password, yk.as_ref(), 1000, 1) {
            Err(e) => Err(err(tonic::Code::Unauthenticated, e)),
            Ok(sess) => {
                let result = self.state.with_vmk(|vmk| {
                    let guard = self.state.db.lock().unwrap();
                    match guard.as_ref() {
                        None => Err(VaultError::Auth("vault locked after unlock (internal)".into())),
                        Some(conn) => {
                            if !totp_db::is_active(conn) {
                                return Err(VaultError::Auth("TOTP not configured; use normal Unlock".into()));
                            }
                            totp_db::verify_backup_code(conn, vmk, &req.backup_code)
                        }
                    }
                });
                match result {
                    Err(e) => {
                        self.state.lock();
                        self.state.record_failed_unlock(1000, 1);
                        Err(err(tonic::Code::Unauthenticated, e))
                    }
                    Ok(false) => {
                        self.state.lock();
                        self.state.record_failed_unlock(1000, 1);
                        Err(err(tonic::Code::Unauthenticated, "invalid or already-used backup code"))
                    }
                    Ok(true) => {
                        self.state.reset_unlock_counter(1000, 1);
                        let _ = self.state.audit_log("UNLOCK_BACKUP_CODE", Some(&sess.user_id));
                        let ticket = self.state.wipe_ticket_bytes().unwrap_or_default();
                        let vmk_guard = self.state.vmk_read_guard();
                        let (ct, nonce) = if let Some(vmk) = vmk_guard.as_ref() {
                            let mut vmk_bytes = [0u8; 32];
                            vmk_bytes.copy_from_slice(&vmk.as_bytes());
                            let res = self.state.encrypt_wipe_ticket(&ticket, &vmk_bytes).unwrap_or((vec![], vec![]));
                            vmk_bytes.zeroize();
                            res
                        } else { (vec![], vec![]) };
                        Ok(Response::new(vault_proto::UnlockedResponse {
                            session_token: sess.token,
                            wipe_ticket_ciphertext: ct,
                            wipe_ticket_nonce: nonce,
                        }))
                    }
                }
            }
        }
    }

    async fn get_profile(&self, request: Request<vault_proto::GetProfileRequest>) -> Result<Response<vault_proto::ProfileResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match user_profile::get(conn, vmk) {
                    Ok(None) => Ok(Response::new(vault_proto::ProfileResponse {
                        first_name: String::new(),
                        last_name: String::new(),
                        email: String::new(),
                        profile_pic: None,
                        password_changed_at: None,
                    })),
                    Ok(Some(p)) => Ok(Response::new(vault_proto::ProfileResponse {
                        first_name: p.first_name,
                        last_name: p.last_name,
                        email: p.email,
                        profile_pic: p.profile_pic,
                        password_changed_at: p.password_changed_at,
                    })),
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn update_profile(&self, request: Request<vault_proto::UpdateProfileRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match user_profile::update(conn, vmk, &req.first_name, &req.last_name, &req.email) {
                    Ok(()) => {
                        let _ = audit::log(conn, vmk, "PROFILE_UPDATE", None);
                        Ok(Response::new(vault_proto::OkResponse {}))
                    }
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }

    async fn change_password(&self, request: Request<vault_proto::ChangePasswordRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            match self.state.change_password(&req.old_password, &req.new_password, None, 1000, 1) {
                Ok(()) => {
                    let v_uuid = self.state.vault_uuid_str();
                    self.state.sessions.revoke_all_except(&v_uuid, &req.session_token);
                    with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                        let _ = audit::log(conn, vmk, "PASSWORD_CHANGE", None);
                        Ok(Response::new(vault_proto::OkResponse {}))
                    })
                }
                Err(e) => Err(err(tonic::Code::Internal, e)),
            }
        })
    }

    async fn verify_master_password(&self, request: Request<vault_proto::VerifyMasterPasswordRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            match self.state.verify_master_password(&req.password, 1000, 1) {
                Ok(()) => Ok(Response::new(vault_proto::OkResponse {})),
                Err(e) => Err(err(tonic::Code::Unauthenticated, e)),
            }
        })
    }

    async fn update_login_policy(&self, request: Request<vault_proto::UpdateLoginPolicyRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            match self.state.update_login_policy(req.password_login_enabled, req.totp_enabled, req.email_otp_enabled, req.duress_max_attempts) {
                Ok(_) => Ok(Response::new(vault_proto::OkResponse {})),
                Err(e) => Err(err(tonic::Code::Internal, e)),
            }
        })
    }

    async fn upload_profile_picture(&self, request: Request<vault_proto::UploadProfilePictureRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match user_profile::upload_picture(conn, vmk, &req.image_bytes) {
                    Ok(()) => {
                        let _ = audit::log(conn, vmk, "PROFILE_PIC_UPDATE", None);
                        Ok(Response::new(vault_proto::OkResponse {}))
                    }
                    Err(e) => Err(err(tonic::Code::InvalidArgument, e)),
                }
            })
        })
    }

    async fn remove_profile_picture(&self, request: Request<vault_proto::RemoveProfilePictureRequest>) -> Result<Response<vault_proto::OkResponse>, Status> {
        let req = request.into_inner();
        auth_then!(self.state, 1000, req.session_token, {
            with_vmk_db!(self.state, vmk, conn, _v_uuid, {
                match user_profile::remove_picture(conn) {
                    Ok(()) => {
                        let _ = audit::log(conn, vmk, "PROFILE_PIC_REMOVE", None);
                        Ok(Response::new(vault_proto::OkResponse {}))
                    }
                    Err(e) => Err(err(tonic::Code::Internal, e)),
                }
            })
        })
    }
}

/// Constant-time byte comparison — avoids a timing oracle on the auth token.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}

/// Resolve the gRPC peer-auth token. Precedence:
///   1. `DAEMON_GRPC_TOKEN` env var (production / K8s Secret).
///   2. `<vault_dir>/grpc.token` file (persisted across restarts in dev).
///   3. a freshly generated 32-byte hex token, written to `<vault_dir>/grpc.token` (0600).
///
/// This replaces the Unix-socket `SO_PEERCRED` UID check that was dropped in the
/// gRPC migration: only a process that can read the 0600 token file (i.e. the
/// vault owner) — or that is handed the token out-of-band via the env var — can
/// call the daemon.
fn resolve_auth_token(vault_dir: &std::path::Path) -> String {
    if let Ok(t) = std::env::var("DAEMON_GRPC_TOKEN") {
        let t = t.trim().to_string();
        if !t.is_empty() { return t; }
    }
    let token_path = vault_dir.join("grpc.token");
    if let Ok(t) = std::fs::read_to_string(&token_path) {
        let t = t.trim().to_string();
        if !t.is_empty() { return t; }
    }
    let mut buf = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut buf);
    let tok = hex::encode(buf);
    // Best-effort persist at 0600 so the same-UID web proxy can read it.
    match std::fs::write(&token_path, &tok) {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600));
            }
            tracing::info!(path = %token_path.display(), "generated gRPC peer-auth token");
        }
        Err(e) => tracing::warn!(err = %e, "could not persist gRPC token file; using ephemeral token"),
    }
    tok
}

pub async fn start_server(state: Arc<DaemonState>, addr: String) -> Result<(), Box<dyn std::error::Error>> {
    let sock_addr: std::net::SocketAddr = addr.parse()?;

    let vault_dir = state.vault_path.parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let token = resolve_auth_token(&vault_dir);

    let server = GrpcServer { state };

    tracing::info!(addr = %sock_addr, "gRPC server listening (token-authenticated)");

    // Peer-auth interceptor: every RPC must carry a matching `x-daemon-token`
    // metadata entry. Replaces the dropped SO_PEERCRED check.
    //
    // NOTE: transport is still plaintext (loopback-only). Distributed deployments
    // that cross the network MUST layer (hybrid PQC) mTLS on top — see
    // docs/superpowers/plans/horizontal-scalability-cnsa2.md, Phase 1.
    let interceptor = move |req: tonic::Request<()>| -> Result<tonic::Request<()>, tonic::Status> {
        match req.metadata().get("x-daemon-token").and_then(|v| v.to_str().ok()) {
            Some(v) if ct_eq(v.as_bytes(), token.as_bytes()) => Ok(req),
            _ => Err(tonic::Status::unauthenticated("invalid or missing daemon token")),
        }
    };

    Server::builder()
        .add_service(VaultServiceServer::with_interceptor(server, interceptor))
        .serve(sock_addr)
        .await?;

    Ok(())
}
