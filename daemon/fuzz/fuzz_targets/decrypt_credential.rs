
#a![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!((data: &u8]) {
    // Template for fuzzing decrypt_credential.
    // Requires vault_daemon to expose decrypt_credential in tests.
});
