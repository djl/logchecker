//! The whole `analyze` path: decoding, translation, EAC/XLD/whipper parsing, scoring and the
//! checksum checks.
#![no_main]

use libfuzzer_sys::fuzz_target;
use logchecker::logchecker::Logchecker;
use std::sync::LazyLock;

static PATH: LazyLock<String> =
    LazyLock::new(|| format!("{}/logchecker-fuzz-{}.log", std::env::temp_dir().display(), std::process::id()));

fuzz_target!(|data: &[u8]| {
    std::fs::write(&*PATH, data).unwrap();
    let mut lc = Logchecker::new();
    lc.new_file(&PATH).unwrap();
    lc.parse();
    let _ = lc.details_json();
});
