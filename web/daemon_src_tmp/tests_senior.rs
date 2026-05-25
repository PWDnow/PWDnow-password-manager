#[cfg(test)]
mod senior_tests {
    use crate::vault::state::DaemonState;
    use crate::auth::session::{SessionStore, DEFAULT_TTL_SECS};
    use std::path::PathBuf;

    #[test]
    fn test_invalid_token_format() {
        let store = SessionStore::new();
        let res = store.validate("not-hex-at-all", 1000);
        assert!(res.is_err());
    }

    #[test]
    fn test_session_rotation_integrity() {
        let store = SessionStore::new();
        let sess = store.create("user1", 1000, DEFAULT_TTL_SECS).unwrap();
        let old_token = sess.token.clone();
        
        let new_token = store.rotate(&old_token, 1000).expect("Rotation failed");
        assert_ne!(old_token, new_token);
        
        // Both should be valid during grace period
        assert!(store.validate(&old_token, 1000).is_ok());
        assert!(store.validate(&new_token, 1000).is_ok());
    }

    #[test]
    fn test_vault_forensic_wipe_security() {
        let db_path = PathBuf::from("/tmp/wipe_test.db");
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file("/tmp/wipe_test.db.meta");
        let state = DaemonState::new(db_path.clone());

        // Create vault
        let sess = state.unlock(b"password-wipe-security-test!", None, 1000, 0).unwrap();
        let _ = sess;
        let ticket = state.wipe_ticket_bytes().expect("No wipe ticket issued");

        assert!(db_path.exists());

        // Wipe it
        state.forensic_wipe(&ticket).expect("Wipe failed");

        assert!(!db_path.exists(), "DB file still exists after wipe");
        assert!(state.is_locked());
    }

    // C-03 regression: lockout must be per-UID, not global.
    // Prior to the fix, a single AtomicU32 locked ALL users after 6 failures
    // from any one account — a trivial DoS. The lockout_map keyed by UID must
    // isolate failures so uid=1 lockout cannot block uid=2 from unlocking.
    #[test]
    fn test_brute_force_lockout_is_per_uid() {
        let db_path = PathBuf::from("/tmp/lockout_test.db");
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file("/tmp/lockout_test.db.meta");
        let state = DaemonState::new(db_path.clone());

        // Initialise the vault so unlock_existing has a header to work with.
        state.unlock(b"lockout-test-password!", None, 1000, 0).unwrap();

        // Simulate 5 consecutive failures for uid=1000 (index-5 triggers a 30s lock).
        for _ in 0..5 {
            state.record_failed_unlock(1000, 0);
        }

        // uid=1000 must now be locked out regardless of correct password.
        let err_1000 = state.unlock(b"lockout-test-password!", None, 1000, 0)
            .expect_err("uid=1000 should be locked out after 5 failures");
        let msg = format!("{err_1000:?}");
        assert!(msg.contains("locked"), "Expected lockout error for uid=1000, got: {msg}");

        // uid=9999 has zero failures — it must NOT be refused for lockout reasons.
        // The unlock may still succeed (correct password) or fail for a non-lockout reason
        // (e.g. the vault was already open); what matters is the error is NOT "locked out".
        let res_9999 = state.unlock(b"lockout-test-password!", None, 9999, 0);
        if let Err(ref e) = res_9999 {
            let msg2 = format!("{e:?}");
            assert!(!msg2.contains("locked out"),
                "uid=9999 must not be locked out due to uid=1000 failures, got: {msg2}");
        }

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file("/tmp/lockout_test.db.meta");
    }
}
