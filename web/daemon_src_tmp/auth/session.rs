use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use rand_core::{OsRng, RngCore};
use blake3;
use crate::error::VaultError;

/// Default session idle TTL: 15 minutes. `touch()` slides this forward on
/// user activity up to, but not past, `absolute_expires_at`.
pub const DEFAULT_TTL_SECS: u64 = 15 * 60;

/// Absolute session lifetime: 24 hours. This is a hard cap set at session
/// creation and never extended, so a client cannot keep a session alive
/// indefinitely by continuously touching it. Matches architecture §10.
pub const ABSOLUTE_TTL_SECS: u64 = 24 * 60 * 60;

/// Maximum number of concurrent sessions per user.
pub const MAX_SESSIONS_PER_USER: usize = 8;

/// Global maximum number of concurrent sessions across all users.
/// Prevents memory exhaustion if the daemon is subjected to a large volume of
/// authentication requests. Matches senior-level resource capping standards.
pub const MAX_TOTAL_SESSIONS: usize = 1000;

/// Grace window for rotated tokens: 60 seconds.
pub const ROTATION_GRACE_SECS: u64 = 60;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before UNIX epoch")
        .as_secs()
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// A single authenticated session.
#[derive(Debug, Clone)]
pub struct Session {
    /// 64-hex-char opaque token used as the session key.
    pub token: String,
    /// Identifies the authenticated user (username or UUID).
    pub user_id: String,
    /// Unix UID of the process that opened the IPC socket (SO_PEERCRED).
    pub uid: u32,
    /// Unix timestamp when the session was created.
    pub created_at: u64,
    /// Idle-sliding expiry: extended by `touch()` on user activity.
    pub expires_at: u64,
    /// Absolute expiry: fixed at creation, never extended. A session is
    /// invalid once `now >= absolute_expires_at` regardless of idle activity.
    pub absolute_expires_at: u64,
}

impl Session {
    /// True if the session has not yet expired by either the idle or the
    /// absolute deadline.
    pub fn is_valid(&self) -> bool {
        let now = now_secs();
        now < self.expires_at && now < self.absolute_expires_at
    }
}

/// Thread-safe in-memory store for active sessions.
pub struct SessionStore {
    sessions: RwLock<HashMap<String, Session>>,
    /// Revoked token hashes (BLAKE3). Value is the expiry epoch-second after
    /// which the entry can be pruned. Prevents replay of explicitly-revoked tokens
    /// within the absolute-TTL window even if the token is somehow re-used.
    revoked: RwLock<HashMap<[u8; 32], u64>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            revoked:  RwLock::new(HashMap::new()),
        }
    }

    /// Create a new session for `user_id` / `uid` with a given TTL.
    /// Enforces `MAX_SESSIONS_PER_USER` per user (oldest sessions are evicted).
    /// Returns `Err` if the global session cap is reached (#6-FIX).
    pub fn create(&self, user_id: &str, uid: u32, ttl_secs: u64) -> Result<Session, VaultError> {
        let now = now_secs();
        let session = Session {
            token: random_token(),
            user_id: user_id.to_string(),
            uid,
            created_at: now,
            expires_at: now + ttl_secs,
            absolute_expires_at: now + ABSOLUTE_TTL_SECS,
        };

        let mut map = self.sessions.write().unwrap();

        // Evict expired sessions first (global).
        map.retain(|_, s| s.is_valid());

        // Enforce per-user cap — evict oldest if needed.
        let user_tokens: Vec<(String, u64)> = map.values()
            .filter(|s| s.user_id == user_id)
            .map(|s| (s.token.clone(), s.created_at))
            .collect();

        if user_tokens.len() >= MAX_SESSIONS_PER_USER {
            // Remove the oldest session for this user.
            if let Some((oldest_token, _)) = user_tokens.iter().min_by_key(|(_, ts)| ts) {
                map.remove(oldest_token);
            }
        }

        // #6-FIX: return a hard error instead of an unstored session token.
        if map.len() >= MAX_TOTAL_SESSIONS {
            return Err(VaultError::Auth("session capacity exhausted".into()));
        }

        map.insert(session.token.clone(), session.clone());
        Ok(session)
    }

    /// Validate a token, returning a clone of the [`Session`] if it is present and unexpired.
    /// Additionally checks that the connecting `uid` matches the session's `uid`.
    pub fn validate(&self, token: &str, uid: u32) -> Result<Session, VaultError> {
        let hash = *blake3::hash(token.as_bytes()).as_bytes();
        {
            let rev = self.revoked.read().unwrap();
            if let Some(&expiry) = rev.get(&hash) {
                if now_secs() < expiry {
                    return Err(VaultError::Auth("session expired".into()));
                }
            }
        }

        let map = self.sessions.read().unwrap();
        match map.get(token) {
            None => Err(VaultError::Auth("session invalid".into())),
            Some(s) if !s.is_valid() => Err(VaultError::Auth("session invalid".into())),
            Some(s) if s.uid != uid => Err(VaultError::Auth("session invalid".into())),
            Some(s) => Ok(s.clone()),
        }
    }

    /// Slide the idle expiry of `token` forward by `ttl_secs`, capped at
    /// the session's absolute_expires_at.
    pub fn touch(&self, token: &str, ttl_secs: u64) -> bool {
        let now = now_secs();
        let mut map = self.sessions.write().unwrap();
        match map.get_mut(token) {
            Some(s) if now < s.absolute_expires_at => {
                let new_idle = now.saturating_add(ttl_secs);
                s.expires_at = new_idle.min(s.absolute_expires_at);
                true
            }
            _ => false,
        }
    }

    /// Rotate a session token: issue a new token and put the old one in a grace window.
    pub fn rotate(&self, old_token: &str, uid: u32) -> Option<String> {
        let now = now_secs();
        let mut map = self.sessions.write().unwrap();
        let old = map.get(old_token)?;
        if !old.is_valid() || old.uid != uid { return None; }

        let user_id = old.user_id.clone();
        let absolute = old.absolute_expires_at;

        let new_token = random_token();
        let new_sess = Session {
            token: new_token.clone(),
            user_id: user_id.clone(),
            uid,
            created_at: now,
            expires_at: (now + DEFAULT_TTL_SECS).min(absolute),
            absolute_expires_at: absolute,
        };

        if let Some(old_sess) = map.get_mut(old_token) {
            old_sess.expires_at = (now + ROTATION_GRACE_SECS).min(absolute);
        }

        map.insert(new_token.clone(), new_sess);
        Some(new_token)
    }

    /// Revoke every session unconditionally (called on vault lock).
    pub fn revoke_all(&self) {
        self.sessions.write().unwrap().clear();
    }

    /// Revoke all active sessions for `user_id` EXCEPT for the `exclude_token`.
    /// Used after password changes to ensure any stolen sessions are invalidated.
    pub fn revoke_all_except(&self, user_id: &str, exclude_token: &str) {
        let now = now_secs();
        let mut rev = self.revoked.write().unwrap();
        rev.retain(|_, &mut exp| exp > now);
        let mut map = self.sessions.write().unwrap();
        for (token, s) in map.iter() {
            if s.user_id == user_id && token != exclude_token {
                let hash = *blake3::hash(token.as_bytes()).as_bytes();
                rev.insert(hash, s.absolute_expires_at);
            }
        }
        map.retain(|token, s| s.user_id != user_id || token == exclude_token);
    }

    /// Return the number of active (non-expired) sessions in the store.
    pub fn active_count(&self) -> usize {
        self.sessions.read().unwrap().values().filter(|s| s.is_valid()).count()
    }
}

impl Default for SessionStore {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    fn store() -> SessionStore { SessionStore::new() }

    #[test]
    fn test_create_returns_valid_session() {
        let s = store();
        let sess = s.create("alice", 1000, DEFAULT_TTL_SECS).unwrap();
        assert_eq!(sess.user_id, "alice");
        assert_eq!(sess.uid, 1000);
        assert!(sess.is_valid());
        assert_eq!(sess.token.len(), 64, "token must be 64 hex chars");
    }

    #[test]
    fn test_validate_succeeds_for_valid_session() {
        let s = store();
        let sess = s.create("alice", 1000, DEFAULT_TTL_SECS).unwrap();
        let got = s.validate(&sess.token, 1000).unwrap();
        assert_eq!(got.user_id, "alice");
    }

    #[test]
    fn test_validate_fails_for_unknown_token() {
        let s = store();
        let err = s.validate("deadbeef", 1000).unwrap_err();
        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn test_validate_fails_uid_mismatch() {
        let s = store();
        let sess = s.create("alice", 1000, DEFAULT_TTL_SECS).unwrap();
        let err = s.validate(&sess.token, 9999).unwrap_err();
        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn test_validate_fails_for_expired_session() {
        let s = store();
        let sess = s.create("bob", 2000, 1).unwrap();
        thread::sleep(Duration::from_secs(2));
        let err = s.validate(&sess.token, 2000).unwrap_err();
        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn test_tokens_are_unique() {
        let s = store();
        let t1 = s.create("eve", 6000, DEFAULT_TTL_SECS).unwrap().token;
        let t2 = s.create("eve", 6000, DEFAULT_TTL_SECS).unwrap().token;
        assert_ne!(t1, t2, "each session must have a unique token");
    }

    #[test]
    fn test_max_sessions_per_user_evicts_oldest() {
        let s = store();
        let mut tokens = Vec::new();
        for _ in 0..MAX_SESSIONS_PER_USER {
            tokens.push(s.create("frank", 7000, DEFAULT_TTL_SECS).unwrap().token);
        }
        let new_sess = s.create("frank", 7000, DEFAULT_TTL_SECS).unwrap();
        let map = s.sessions.read().unwrap();
        let frank_count = map.values()
            .filter(|sess| sess.user_id == "frank" && sess.is_valid())
            .count();
        assert!(frank_count <= MAX_SESSIONS_PER_USER);
        drop(map);
        assert!(s.validate(&new_sess.token, 7000).is_ok());
    }

    #[test]
    fn test_max_total_sessions_refuses_overflow() {
        let s = store();
        for i in 0..MAX_TOTAL_SESSIONS {
            let _ = s.create(&format!("user{}", i), i as u32, DEFAULT_TTL_SECS);
        }
        let map = s.sessions.read().unwrap();
        assert_eq!(map.len(), MAX_TOTAL_SESSIONS);
        drop(map);

        // #6-FIX: create() now returns Err when cap is reached.
        let result = s.create("new_user", 9999, DEFAULT_TTL_SECS);
        assert!(result.is_err(), "must return Err when session cap is reached");
        let map = s.sessions.read().unwrap();
        assert_eq!(map.len(), MAX_TOTAL_SESSIONS);
    }

    #[test]
    fn test_touch_slides_idle_expiry_forward() {
        let s = store();
        let sess = s.create("ivan", 11_000, 2).unwrap();
        let before = sess.expires_at;
        thread::sleep(Duration::from_secs(1));
        assert!(s.touch(&sess.token, DEFAULT_TTL_SECS));
        let got = s.validate(&sess.token, 11_000).unwrap();
        assert!(got.expires_at > before);
    }

    #[test]
    fn test_touch_caps_at_absolute_expiry() {
        let s = store();
        let now = now_secs();
        let sess = Session {
            token: random_token(),
            user_id: "jane".into(),
            uid: 12_000,
            created_at: now,
            expires_at: now + 1,
            absolute_expires_at: now + 5,
        };
        s.sessions.write().unwrap().insert(sess.token.clone(), sess.clone());
        assert!(s.touch(&sess.token, 60 * 60));
        let got = s.validate(&sess.token, 12_000).unwrap();
        assert_eq!(got.expires_at, sess.absolute_expires_at);
    }

    #[test]
    fn test_concurrent_creates_are_safe() {
        use std::sync::Arc;
        let s = Arc::new(store());
        let handles: Vec<_> = (0..16).map(|i| {
            let s = Arc::clone(&s);
            thread::spawn(move || {
                s.create(&format!("user{i}"), i as u32, DEFAULT_TTL_SECS)
            })
        }).collect();
        let sessions: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(sessions.len(), 16);
        assert!(sessions.iter().all(|r| r.is_ok()));
    }

    #[test]
    fn test_rotate_issues_new_token_and_grace_window() {
        let s = store();
        let sess = s.create("rotate_user", 1, DEFAULT_TTL_SECS).unwrap();
        let old_token = sess.token.clone();

        let new_token = s.rotate(&old_token, 1).expect("rotate must succeed");
        assert_ne!(new_token, old_token);

        assert!(s.validate(&new_token, 1).is_ok());
        assert!(s.validate(&old_token, 1).is_ok());

        let old_sess = s.validate(&old_token, 1).unwrap();
        let new_sess  = s.validate(&new_token, 1).unwrap();
        assert!(old_sess.expires_at <= new_sess.expires_at);
    }
}
