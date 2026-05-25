use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Instant, Duration};
use crate::error::VaultError;

const LOCKOUT_SCHEDULE_SECS: &[u64] = &[0, 0, 0, 0, 0, 30, 60, 120, 300, 600];

pub struct LockoutTracker {
    map: Mutex<HashMap<u32, (u32, Instant)>>,
}

impl LockoutTracker {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_unlock_lockout(&self, uid: u32) -> Result<(), VaultError> {
        let mut map = self.map.lock().unwrap();
        let now = Instant::now();
        // Prune for this uid if expired
        if let Some(&(_, expiry)) = map.get(&uid) {
            if now >= expiry {
                map.remove(&uid);
            } else {
                return Err(VaultError::Auth("locked out".into()));
            }
        }
        Ok(())
    }

    pub fn record_failed_unlock(&self, uid: u32) -> u32 {
        let mut map = self.map.lock().unwrap();
        let now = Instant::now();
        let entry = map.entry(uid).or_insert((0, now));
        entry.0 += 1;
        let count = entry.0;
        let secs = LOCKOUT_SCHEDULE_SECS[count.min(LOCKOUT_SCHEDULE_SECS.len() as u32 - 1) as usize];
        if secs > 0 {
            entry.1 = now + Duration::from_secs(secs);
        }
        count
    }

    pub fn reset_lockout(&self, uid: u32) {
        let mut map = self.map.lock().unwrap();
        map.remove(&uid);
    }

    pub fn clear(&self) {
        let mut map = self.map.lock().unwrap();
        map.clear();
    }

    pub fn prune(&self) {
        let mut map = self.map.lock().unwrap();
        let now = Instant::now();
        map.retain(|_, &mut (_, expiry)| expiry > now);
    }
}
