//! Port of Check/Checksum/EAC.php (itself a port of eac_logchecker.py).
//! Validates the Rijndael-256 CBC checksum EAC appends to its logs.

use super::rijndael::Rijndael256;
use super::{CHECKSUM_INVALID, CHECKSUM_MISSING, CHECKSUM_OK};
use regex::Regex;
use std::sync::LazyLock;

const EAC_KEY: [u8; 32] = [
    0x93, 0x78, 0x71, 0x6c, 0xf1, 0x3e, 0x42, 0x65, 0xae, 0x55, 0x33, 0x8e, 0x94, 0x0b, 0x37, 0x61,
    0x84, 0xda, 0x38, 0x9e, 0x50, 0x64, 0x77, 0x26, 0xb3, 0x5f, 0x6f, 0x34, 0x1e, 0xe3, 0xef, 0xd9,
];

// EAC crashes if there are more than 2^13 characters in a line.
const MAX_LINE_LENGTH: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    No,
    Bad,
}

pub fn validate(data: &[u8]) -> &'static str {
    let statuses = entry_statuses(data);
    // Collapse the per-entry statuses, with BAD > NO > OK.
    if statuses.contains(&Status::Bad) {
        CHECKSUM_INVALID
    } else if statuses.contains(&Status::No) {
        CHECKSUM_MISSING
    } else if statuses.contains(&Status::Ok) {
        CHECKSUM_OK
    } else {
        CHECKSUM_MISSING
    }
}

/// Status of every log entry in the file. A decode failure or an overlong line is one `No`,
/// as in eac_logchecker.py.
pub fn entry_statuses(data: &[u8]) -> Vec<Status> {
    match get_logs(data) {
        Some(logs) => logs.iter().map(|(text, modified)| verify(text, *modified)).collect(),
        None => vec![Status::No],
    }
}

fn decode_utf16le(data: &[u8]) -> Option<String> {
    if !data.len().is_multiple_of(2) {
        return None;
    }
    let units = data.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]]));
    char::decode_utf16(units).collect::<Result<String, _>>().ok()
}

/// Decode the log and split it into (text, modified) entries.
fn get_logs(data: &[u8]) -> Option<Vec<(String, bool)>> {
    static SPLIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\n\n==== .* [A-Z0-9]+ ====").unwrap());
    static SEPARATOR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^-]-{60}[^-]").unwrap());

    let mut text = decode_utf16le(data)?;
    if let Some(rest) = text.strip_prefix('\u{FEFF}') {
        text = rest.to_string();
    }
    // The checksum strips newlines anyway, so normalise them for our regexes.
    let mut text = text.replace("\r\n", "\n");
    // Null bytes screw it up.
    if let Some(pos) = text.find('\0') {
        text.truncate(pos);
    }
    if text.split('\n').any(|line| line.chars().count() + 1 > MAX_LINE_LENGTH) {
        return None;
    }

    // preg_split with DELIM_CAPTURE, then drop blank pieces.
    let mut segments = Vec::new();
    let mut last = 0;
    for m in SPLIT.find_iter(&text) {
        segments.push(&text[last..m.start()]);
        segments.push(m.as_str());
        last = m.end();
    }
    segments.push(&text[last..]);
    segments.retain(|s| !crate::php::trim(s).is_empty());

    let count = segments.len();
    if count <= 1 {
        return Some(vec![(segments.first().unwrap_or(&"").to_string(), false)]);
    }
    let length = if count % 2 == 1 { count - 1 } else { count };
    let mut logs = Vec::new();
    for i in (0..length).step_by(2) {
        let mut log_text = format!("{}{}", segments[i], segments[i + 1]);
        let mut modified = false;
        if i > 0 {
            match SEPARATOR.find(&log_text) {
                Some(m) => log_text.replace_range(m.range(), ""),
                None => modified = true,
            }
        }
        logs.push((log_text, modified));
    }
    logs.extend(segments[length..].iter().map(|s| (s.to_string(), false)));
    Some(logs)
}

fn verify(text: &str, modified: bool) -> Status {
    static CHECKSUM_LINE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\n\n==== (.*) ([A-Z0-9]+) ====").unwrap());

    if text.is_empty() {
        return Status::No;
    }
    let mut has_version = false;
    for line in text.split('\n') {
        if line.starts_with("Exact Audio Copy") {
            has_version = true;
        } else if line.starts_with(|c: char| c.is_ascii_alphabetic()) {
            break;
        }
    }
    let Some(caps) = CHECKSUM_LINE.captures(text) else {
        return Status::No;
    };
    let needle = format!("\n\n==== {}", &caps[1]);
    let (unsigned, rest) = text.split_once(&needle).unwrap();
    let old_checksum = crate::php::trim(rest).split_ascii_whitespace().next().unwrap_or("");
    if !has_version {
        return Status::No;
    }
    if modified || old_checksum != checksum(unsigned) {
        Status::Bad
    } else {
        Status::Ok
    }
}

/// Rijndael-256, CBC, zero IV, zero padding over the UTF-16LE text without newlines or BOMs.
/// The checksum is the final ciphertext block, as upper-case hex.
fn checksum(unsigned: &str) -> String {
    let plain: Vec<u8> = unsigned
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\u{FEFF}' | '\u{FFFE}'))
        .flat_map(|c| {
            let mut buf = [0u16; 2];
            c.encode_utf16(&mut buf).iter().flat_map(|u| u.to_le_bytes()).collect::<Vec<_>>()
        })
        .collect();
    let cipher = Rijndael256::new(&EAC_KEY);
    let mut state = [0u8; 32];
    for chunk in plain.chunks(32) {
        for (s, p) in state.iter_mut().zip(chunk) {
            *s ^= p;
        }
        cipher.encrypt_block(&mut state);
    }
    state.iter().map(|b| format!("{b:02X}")).collect()
}
