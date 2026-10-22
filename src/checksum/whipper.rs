//! Port of Check/Checksum/Whipper.php: SHA-256 over every line but the last.

use super::xld::{SHA256_STANDARD_STATE, hex, sha256_with_state};
use super::{CHECKSUM_INVALID, CHECKSUM_MISSING, CHECKSUM_OK};
use regex::bytes::Regex;
use std::sync::LazyLock;

pub fn validate(data: &[u8]) -> &'static str {
    static HASH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"SHA-256 hash: ([A-Z0-9]+)\z").unwrap());
    // Trimmed, so PCRE's `$` can only mean end of string.
    let log = crate::php::trim_bytes(data);
    let Some(caps) = HASH.captures(log) else {
        return CHECKSUM_MISSING;
    };
    let body = match log.iter().rposition(|&b| b == b'\n') {
        Some(pos) => &log[..pos],
        None => &[][..],
    };
    let expected = String::from_utf8_lossy(&caps[1]).to_lowercase();
    if hex(&sha256_with_state(body, SHA256_STANDARD_STATE)) == expected {
        CHECKSUM_OK
    } else {
        CHECKSUM_INVALID
    }
}
