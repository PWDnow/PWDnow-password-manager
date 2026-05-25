
#a![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!((data: &u8]) {
    let _: Result<vault_daemon::ipc::protocol::Request, _> = rmp_serde::from_slice(data);
});
