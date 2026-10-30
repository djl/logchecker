//! EAC and XLD checksum verification.
#![no_main]

use libfuzzer_sys::fuzz_target;
use logchecker::checksum::{eac, xld};

fuzz_target!(|data: &[u8]| {
    let _ = eac::entry_statuses(data);
    let _ = xld::check(data);
});
