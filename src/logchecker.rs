//! Port of Logchecker.php. Logs are byte strings, as in PHP; every pattern that PHP runs
//! without `/u` is a `(?-u)` byte regex, so `.`, `\w`, `\s` and `(?i)` stay ASCII/byte-wise.

use crate::checksum::{self, CHECKSUM_INVALID, CHECKSUM_MISSING, CHECKSUM_OK};
use crate::php::{self, Num, cmp_str_num, loose_eq, version_compare};
use crate::ripper::{self, Ripper};
use crate::translator;
use regex::bytes::{Captures, Regex};
use std::collections::HashSet;
use std::sync::LazyLock;

// Upstream Logchecker master commit this tracks; see the README.
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (upstream ca56547)");

macro_rules! re {
    ($p:literal) => {{
        static RE: std::sync::LazyLock<regex::bytes::Regex> =
            std::sync::LazyLock::new(|| regex::bytes::Regex::new(concat!("(?-u)", $p)).unwrap());
        &*RE
    }};
}
pub(crate) use re;

pub(crate) const FAKE_DRIVES: [&[u8]; 2] = [b"Generic DVD-ROM", b"Generic DVD-ROM SCSI CdRom Device"];

static ALL_DRIVES: LazyLock<Vec<(String, String)>> = LazyLock::new(|| {
    let rows: Vec<serde_json::Value> = serde_json::from_str(include_str!("../resources/drives.json")).unwrap();
    rows.iter()
        .map(|r| {
            let offset = match &r[1] {
                serde_json::Value::String(s) => s.clone(),
                v => v.to_string(),
            };
            (r[0].as_str().unwrap().to_string(), offset)
        })
        .collect()
});

/// PHP `$Matches`: unmatched groups read as "".
pub(crate) struct M<'a>(Captures<'a>);

impl M<'_> {
    pub(crate) fn g(&self, i: usize) -> &[u8] {
        self.0.get(i).map_or(&[][..], |m| m.as_bytes())
    }
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// PHP truthiness of a string.
fn truthy(s: &[u8]) -> bool {
    !(s.is_empty() || s == b"0")
}

/// preg_replace with a `${n}` template; limit 0 = unlimited. Returns (result, count).
fn rep(re: &Regex, s: &[u8], template: &str, limit: usize) -> (Vec<u8>, usize) {
    rep_cb(re, s, limit, |m| {
        let mut out = Vec::new();
        m.0.expand(template.as_bytes(), &mut out);
        out
    })
}

/// preg_replace_callback; limit 0 = unlimited.
pub(crate) fn rep_cb(re: &Regex, s: &[u8], limit: usize, mut f: impl FnMut(&M) -> Vec<u8>) -> (Vec<u8>, usize) {
    let mut out = Vec::with_capacity(s.len());
    let mut last = 0;
    let mut count = 0;
    for caps in re.captures_iter(s) {
        if limit != 0 && count == limit {
            break;
        }
        let m = caps.get(0).unwrap();
        out.extend_from_slice(&s[last..m.start()]);
        out.extend(f(&M(caps)));
        last = m.end();
        count += 1;
    }
    out.extend_from_slice(&s[last..]);
    (out, count)
}

fn r(re: &Regex, s: &[u8], template: &str) -> Vec<u8> {
    rep(re, s, template, 0).0
}

fn r1(re: &Regex, s: &[u8], template: &str) -> Vec<u8> {
    rep(re, s, template, 1).0
}

pub fn str_replace(s: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return s.to_vec();
    }
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i..].starts_with(from) {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    out
}

pub(crate) fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

/// preg_split, optionally with PREG_SPLIT_DELIM_CAPTURE.
fn split(re: &Regex, s: &[u8], capture: bool) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut last = 0;
    for caps in re.captures_iter(s) {
        let m = caps.get(0).unwrap();
        out.push(s[last..m.start()].to_vec());
        if capture {
            for i in 1..caps.len() {
                out.push(caps.get(i).map_or(vec![], |g| g.as_bytes().to_vec()));
            }
        }
        last = m.end();
    }
    out.push(s[last..].to_vec());
    out
}

fn lower(s: &[u8]) -> Vec<u8> {
    s.to_ascii_lowercase()
}

fn points(d: &[u8], is_one: bool) -> Vec<u8> {
    cat(&[b" (-", d, b" point", if is_one { b"" } else { b"s" }, b")"])
}

#[derive(Clone, Default)]
struct Track {
    decrease: i64,
    bad: Vec<Vec<u8>>,
}

/// An insertion-ordered map with PHP array overwrite semantics.
fn upsert<K: PartialEq, V>(v: &mut Vec<(K, V)>, k: K, val: V) {
    match v.iter_mut().find(|(kk, _)| *kk == k) {
        Some(slot) => slot.1 = val,
        None => v.push((k, val)),
    }
}

pub struct Logchecker {
    log: Vec<u8>,
    /// The file as read, for the checksum: re-reading the path breaks on pipes.
    file: Vec<u8>,
    log_path: Option<String>,
    logs: Vec<Vec<u8>>,
    language: String,
    tracks: Vec<Vec<(Vec<u8>, Track)>>,
    checksum_status: &'static str,
    score: i64,
    details: Vec<Vec<u8>>,
    /// The lines in `details`, for PHP's in_array duplicate checks.
    seen: HashSet<Vec<u8>>,
    offsets: Vec<String>,
    drive_found: bool,
    drives: Vec<String>,
    secure_mode: bool,
    non_secure_mode: Option<Vec<u8>>,
    bad_track: Vec<Vec<u8>>,
    decrease_score_track: i64,
    ripper: Option<Ripper>,
    ripper_version: Option<Vec<u8>>,
    track_number: Vec<u8>,
    combined: Option<usize>,
    curr_log: usize,
    range: bool,
    xld_secure_ripper: bool,
}

impl Default for Logchecker {
    fn default() -> Self {
        Self::new()
    }
}

impl Logchecker {
    pub fn new() -> Self {
        Logchecker {
            log: vec![],
            file: vec![],
            log_path: None,
            logs: vec![],
            language: "en".into(),
            tracks: vec![],
            checksum_status: CHECKSUM_OK,
            score: 100,
            details: vec![],
            seen: HashSet::new(),
            offsets: vec![],
            drive_found: false,
            drives: vec![],
            secure_mode: true,
            non_secure_mode: None,
            bad_track: vec![],
            decrease_score_track: 0,
            ripper: None,
            ripper_version: None,
            track_number: vec![],
            combined: None,
            curr_log: 0,
            range: false,
            xld_secure_ripper: false,
        }
    }

    pub fn new_file(&mut self, path: &str) -> std::io::Result<()> {
        *self = Self::new();
        self.file = std::fs::read(path)?;
        self.log = self.file.clone();
        self.log_path = Some(path.to_string());
        Ok(())
    }

    pub(crate) fn raw_log(&self) -> &[u8] {
        &self.log
    }
    pub(crate) fn set_log(&mut self, log: Vec<u8>) {
        self.log = log;
    }
    pub(crate) fn file(&self) -> &[u8] {
        &self.file
    }
    pub(crate) fn set_ripper_version(&mut self, v: Option<Vec<u8>>) {
        self.ripper_version = v;
    }
    pub(crate) fn set_checksum_state(&mut self, s: &'static str) {
        self.checksum_status = s;
    }
    pub(crate) fn drives(&self) -> &[String] {
        &self.drives
    }
    pub(crate) fn offsets(&self) -> &[String] {
        &self.offsets
    }

    pub fn get_log(&self) -> &[u8] {
        &self.log
    }
    pub fn get_ripper(&self) -> Option<Ripper> {
        self.ripper
    }
    pub fn get_ripper_version(&self) -> Option<&[u8]> {
        self.ripper_version.as_deref()
    }
    pub fn get_language(&self) -> &str {
        &self.language
    }
    pub fn get_score(&self) -> i64 {
        self.score
    }
    pub fn get_details(&self) -> &[Vec<u8>] {
        &self.details
    }
    pub fn get_checksum_state(&self) -> &'static str {
        self.checksum_status
    }
    pub fn is_combined_log(&self) -> bool {
        self.combined.is_some_and(|c| c > 0)
    }

    /// The `details` JSON object the analyze command writes (AnalyzeCommand.php).
    /// None where PHP's json_encode fails (invalid UTF-8).
    pub fn details_json(&self) -> Option<serde_json::Value> {
        let s = |b: &[u8]| String::from_utf8(b.to_vec()).ok();
        let mut details = vec![];
        for d in &self.details {
            details.push(serde_json::Value::String(s(d)?));
        }
        let version = match &self.ripper_version {
            Some(v) => serde_json::Value::String(s(v)?),
            None => serde_json::Value::Null,
        };
        Some(serde_json::json!({
            "ripper": self.ripper.map(Ripper::as_str),
            "version": version,
            "language": self.language,
            "combined": self.is_combined_log(),
            "score": self.score,
            "checksum": self.checksum_status,
            "details": details,
        }))
    }

    pub fn parse(&mut self) {
        match crate::charset::decode_encoding(&self.log) {
            Ok(log) => self.log = log,
            Err(()) => {
                self.score = 0;
                self.account(b"Could not detect log encoding, log is corrupt.", 0, None, false, false);
                return;
            }
        }
        match ripper::get_ripper(&self.log) {
            Some(r) => self.ripper = Some(r),
            None => {
                self.score = 0;
                self.account(b"Unknown log file, could not determine ripper.", 0, None, false, false);
                self.ripper = Some(Ripper::Unknown);
                return;
            }
        }
        if self.ripper == Some(Ripper::Whipper) {
            crate::whipper::parse(self);
        } else {
            self.legacy_parse();
        }
    }

    fn legacy_parse(&mut self) {
        if self.ripper == Some(Ripper::Eac) {
            // Translator's /u regexes fail on invalid UTF-8, which PHP reports as "unknown language".
            let lang = std::str::from_utf8(&self.log).ok().and_then(translator::get_language);
            match lang {
                Some(lang) => {
                    if lang.code != "en" {
                        self.language = lang.code.clone();
                        let msg = format!("Translated log from {} ({}) to English.", lang.name, lang.name_english);
                        self.account(msg.as_bytes(), 0, None, false, true);
                        let text = std::str::from_utf8(&self.log).unwrap();
                        self.log = translator::translate(text, &lang.code).expect("translation file").into_bytes();
                    }
                }
                None => {
                    self.language = "en".into();
                    self.account(b"Could not determine language. Assuming English.", 0, None, false, true);
                }
            }
        }

        self.log.retain(|&b| b != b'\r');

        // Some foreign logs omit "Log checksum" (probably bad translation files), so only
        // English logs must have it.
        let eac_checksum: &Regex = if self.language == "en" {
            re!(r"(?i)(====[ ]+Log checksum [\d\w ]+[ ]+====)")
        } else {
            re!(r"(?i)(====[ ]+[\d\w ]+[ ]+====)")
        };
        let xld_signature = re!(r"(?i)([\-]+BEGIN XLD SIGNATURE[\S\n\-]+END XLD SIGNATURE[\-]+)");

        // Split the log apart. slots[key] mirrors the PHP array's integer keys; a key that is
        // unset and later written again moves to the end, which `recreated` holds.
        let mut slots: Vec<Option<Vec<u8>>> = if eac_checksum.is_match(&self.log) {
            split(re!(r"(?i)(\n====[ ]+[\d\w ]+[ ]+====)"), &self.log, true).into_iter().map(Some).collect()
        } else if xld_signature.is_match(&self.log) {
            split(re!(r"(?i)(\n[\-]+BEGIN XLD SIGNATURE[\S\n\-]+END XLD SIGNATURE[\-]+)"), &self.log, true)
                .into_iter()
                .map(Some)
                .collect()
        } else {
            self.checksum_status = CHECKSUM_MISSING;
            split(re!(r"(?i)(\nEnd of status report)"), &self.log, true)
                .into_iter()
                .map(|l| (!re!(r"(?i)---- CUETools DB Plugin V.+").is_match(&l)).then_some(l))
                .collect()
        };
        let mut recreated = vec![];

        // PHP's foreach iterates a snapshot, but the body only edits keys it has already visited.
        for key in 0..slots.len() {
            let Some(log) = &slots[key] else { continue };
            let log = php::trim_bytes(log).to_vec();
            let append = if log.is_empty() || re!(r"(?i)^\-+$").is_match(&log) {
                slots[key] = None;
                continue;
            } else if self.checksum_status != CHECKSUM_OK {
                re!(r"(?i)End of status report").is_match(&log)
            } else {
                eac_checksum.is_match(&log) || re!(r"(?i)[\-]+BEGIN XLD SIGNATURE").is_match(&log)
            };
            if append {
                match key.checked_sub(1).and_then(|k| slots[k].as_mut()) {
                    Some(prev) => prev.extend_from_slice(&log),
                    None => recreated.push(log),
                }
                slots[key] = None;
            }
        }
        self.logs = slots.into_iter().flatten().chain(recreated).collect();
        if self.logs.len() > 1 {
            self.combined = Some(self.logs.len());
        }

        let mut file_checksum = None;
        for idx in 0..self.logs.len() {
            let mut log = self.logs[idx].clone();
            self.tracks.push(vec![]);
            self.curr_log = idx + 1;
            if let Some(c) = re!(r"(?i)Exact Audio Copy (.+) from").captures(&log) {
                let v = &c[1];
                if truthy(v) {
                    let start = v.iter().position(|&b| b != b'V').unwrap_or(v.len());
                    let rv = v[start..].to_vec();
                    let version_check = String::from_utf8_lossy(rv.split(|&b| b == b' ').next().unwrap()).into_owned();
                    if version_compare(&version_check, "1.0") < 0 {
                        self.checksum_status = CHECKSUM_MISSING;
                        if cmp_str_num(&rv, Num::Float(0.95)).is_le() {
                            // EAC 0.95 and before was missing a handful of stuff for full log validation.
                            self.account(b"EAC version older than 0.99", 30, None, false, false);
                        }
                    } else if !eac_checksum.is_match(&log) {
                        // Above version 1 and no checksum
                        self.checksum_status = CHECKSUM_MISSING;
                    }
                    self.ripper_version = Some(rv);
                } else {
                    self.checksum_status = CHECKSUM_MISSING;
                    self.account(b"EAC version older than 0.99", 30, None, false, false);
                }
            } else if re!(r"(?i)EAC extraction logfile from").is_match(&log) {
                self.checksum_status = CHECKSUM_MISSING;
                self.account(b"EAC version older than 0.99", 30, None, false, false);
            }

            if let Some(c) = re!(r"(?i)X Lossless Decoder version (\d+) \((.+)\)").captures(&log) {
                let rv = c[1].to_vec();
                if version_compare(&String::from_utf8_lossy(&rv), "20121222") >= 0 && !xld_signature.is_match(&log) {
                    self.checksum_status = CHECKSUM_MISSING;
                }
                self.ripper_version = Some(rv);
            }
            log = r1(
                re!(r"(?i)Exact Audio Copy (.+) from (.+)"),
                &log,
                r#"Exact Audio Copy <span class="log1">${1}</span> from <span class="log1">${2}</span>"#,
            );
            let (l, eac) = rep(
                re!(r"(?i)EAC extraction logfile from (.+)\n+(.+)"),
                &log,
                "<span class='good'>EAC extraction logfile from <span class='log5'>${1}</span></span>\n\n<span class=\"log4\">${2}</span>",
                1,
            );
            log = r1(
                re!(r"(?i)X Lossless Decoder version (.+) \((.+)\)"),
                &l,
                r#"X Lossless Decoder version <span class="log1">${1}</span> (<span class="log1">${2}</span>)"#,
            );
            let (l, xld) = rep(
                re!(r"(?i)XLD extraction logfile from (.+)\n+(.+)"),
                &log,
                "<span class='good'>XLD extraction logfile from <span class='log5'>${1}</span></span>\n\n<span class=\"log4\">${2}</span>",
                1,
            );
            log = l;
            let (eac, xld) = (eac > 0, xld > 0);

            if !eac && !xld {
                if let Some(n) = self.combined {
                    self.clear_details();
                    self.push_detail(format!("Combined Log ({n})").into_bytes());
                    self.push_detail(
                        format!("Unrecognized log file ({})! Feel free to report for manual review.", self.curr_log)
                            .into_bytes(),
                    );
                } else {
                    self.push_detail(b"Unrecognized log file! Feel free to report for manual review.".to_vec());
                }
                self.score = 0;
                return;
            }

            if self.checksum_status == CHECKSUM_OK
                && self.log_path.as_deref().is_some_and(|p| truthy(p.as_bytes())) {
                    // The result only depends on the file, so check it once, not once per log.
                    self.checksum_status = *file_checksum.get_or_insert_with(|| {
                        checksum::validate(&self.file, self.ripper.unwrap()).unwrap_or(CHECKSUM_MISSING)
                    });
                }

            let class = if self.checksum_status == CHECKSUM_OK { "good" } else { "bad" };
            let template = format!("<span class='{class}'>${{1}}</span>");
            let (l, eac_count) = rep(eac_checksum, &log, &template, 1);
            let (l, xld_count) = rep(xld_signature, &l, &template, 1);
            log = l;
            // EAC will at least output "no checksum" for some malformed logs with checksums
            if (eac_count > 0 || xld_count > 0) && self.checksum_status == CHECKSUM_MISSING {
                self.checksum_status = CHECKSUM_INVALID;
            }

            if eac
                && (re!(r"(?i)Used output format[ ]+:[ ]+[a-z0-9 ]+MP3").is_match(&log)
                    || re!(r"(?i)Command line compressor[ ]+:.+(MP3|lame)\.exe").is_match(&log))
            {
                if self.combined.is_some() {
                    self.push_detail(format!("Skipping Log ({}), MP3 Rip", self.curr_log).into_bytes());
                } else {
                    self.account(b"Invalid Log (MP3)", 100, None, false, false);
                }
                self.logs[idx] = log;
                continue;
            }

            let (l, n) = rep_cb(re!(r"(?i)Used drive( *): (.+)"), &log, 1, |m| self.drive(m));
            log = l;
            if n == 0 {
                self.account(b"Could not verify used drive", 1, None, false, false);
            }
            let (l, n) = rep_cb(re!(r"(?i)Media type( *): (.+)"), &log, 1, |m| self.media_type_xld(m));
            log = l;
            let new_xld = self
                .ripper_version
                .as_deref()
                .is_some_and(|v| truthy(v) && cmp_str_num(v, Num::Int(20130127)).is_ge());
            if xld && new_xld && n == 0 {
                self.account(b"Could not verify media type", 1, None, false, false);
            }
            let (l, n) = rep_cb(re!(r"(?i)Read mode( *): ([a-z]+)(.*)?"), &log, 1, |m| self.read_mode(m));
            log = l;
            if n == 0 && eac {
                self.account(b"Could not verify read mode", 1, None, false, false);
            }
            let (l, ripper_mode) = rep_cb(re!(r"(?i)Ripper mode( *): (.*)"), &log, 1, |m| self.ripper_mode_xld(m));
            let (l, paranoia) =
                rep_cb(re!(r"(?i)Use cdparanoia mode( *): (.*)"), &l, 1, |m| self.cdparanoia_mode_xld(m));
            log = l;
            if ripper_mode == 0 && paranoia == 0 && xld {
                self.account(b"Could not verify read mode", 1, None, false, false);
            }
            let (l, n) = rep_cb(re!(r"(?i)Max retry count( *): (\d+)"), &log, 1, |m| self.max_retry_count(m));
            log = l;
            if n == 0 && xld {
                self.account(b"Could not verify max retry count", 0, None, false, false);
            }
            let (l, a) =
                rep_cb(re!(r"(?i)Utilize accurate stream( *): (Yes|No)"), &log, 1, |m| self.accurate_stream(m));
            let (l, b) = rep_cb(re!(r"(?i), (|NO )accurate stream"), &l, 1, |m| self.accurate_stream_eac_pre9(m));
            log = l;
            if a == 0 && b == 0 && !self.non_secure() && eac {
                self.account(b"Could not verify accurate stream", 20, None, false, false);
            }
            let (l, a) =
                rep_cb(re!(r"(?i)Defeat audio cache( *): (Yes|No)"), &log, 1, |m| self.defeat_audio_cache(m));
            let (l, b) =
                rep_cb(re!(r"(?i) (|NO )disable cache"), &l, 1, |m| self.defeat_audio_cache_eac_pre99(m));
            log = l;
            if a == 0 && b == 0 && !self.non_secure() && eac {
                self.account(b"Could not verify defeat audio cache", 1, None, false, false);
            }
            let (l, n) =
                rep_cb(re!(r"(?i)Disable audio cache( *): (.*)"), &log, 1, |m| self.defeat_audio_cache_xld(m));
            log = l;
            if n == 0 && xld {
                self.account(b"Could not verify defeat audio cache", 1, None, false, false);
            }
            let (l, a) = rep_cb(re!(r"(?i)Make use of C2 pointers( *): (Yes|No)"), &log, 1, |m| self.c2_pointers(m));
            let (l, b) = rep_cb(re!(r"(?i)with (|NO )C2"), &l, 1, |m| self.c2_pointers_eac_pre99(m));
            log = l;
            if a == 0 && b == 0 && !self.non_secure() {
                self.account(b"Could not verify C2 pointers", 1, None, false, false);
            }
            let (l, n) =
                rep_cb(re!(r"(?i)Read offset correction( *): ([+-]?[0-9]+)"), &log, 1, |m| self.read_offset(m));
            log = l;
            if n == 0 {
                self.account(b"Could not verify read offset", 1, None, false, false);
            }
            let (l, n) = rep(
                re!(r"(?i)(Combined read/write offset correction\s*:\s+\d+)"),
                &log,
                r#"<span class="bad">${1}</span>"#,
                1,
            );
            log = l;
            if n > 0 {
                self.account(b"Combined read/write offset cannot be verified", 4, None, false, false);
            }
            // xld alternate offset table
            log = r1(
                re!(r"(?i)(List of \w+ offset correction values) *(\n+)(( *.*confidence .*\) ?\n)+)"),
                &log,
                "<span class=\"log5\">${1}</span>${2}<span class=\"log4\">${3}</span>\n",
            );
            log = r1(
                re!(r"(?i)(List of \w+ offset correction values) *\n( *\# +\| +Absolute +\| +Relative +\| +Confidence) *\n( *\-+) *\n(( *\d+ +\| +\-?\+?\d+ +\| +\-?\+?\d+ +\| +\d+ *\n)+)"),
                &log,
                "<span class=\"log5\">${1}</span>\n<span class=\"log4\">${2}\n${3}\n${4}\n</span>",
            );
            log = r1(
                re!(r"(?i)Overread into Lead-In and Lead-Out( +): (Yes|No)"),
                &log,
                r#"<span class="log5">Overread into Lead-In and Lead-Out${1}</span>: <span class="log4">${2}</span>"#,
            );
            let (l, n) = rep_cb(re!(r"(?i)Fill up missing offset samples with silence( +): (Yes|No)"), &log, 1, |m| {
                self.fill_offset_samples(m)
            });
            log = l;
            if n == 0 && eac {
                self.account(b"Could not verify missing offset samples", 1, None, false, false);
            }
            let (l, n) =
                rep_cb(re!(r"(?i)Delete leading and trailing silent blocks([ \w]*)( +): (Yes|No)"), &log, 1, |m| {
                    self.delete_silent_blocks(m)
                });
            log = l;
            if n == 0 && eac {
                self.account(b"Could not verify silent blocks", 1, None, false, false);
            }
            let (l, n) = rep_cb(re!(r"(?i)Null samples used in CRC calculations( +): (Yes|No)"), &log, 1, |m| {
                self.null_samples(m)
            });
            log = l;
            if n == 0 && eac {
                self.account(b"Could not verify null samples", 0, None, false, false);
            }
            log = rep_cb(re!(r"(?i)Normalize to( +): ([0-9% ]+)"), &log, 1, |m| self.normalize_eac(m)).0;
            log = r1(
                re!(r"(?i)Used interface( +): ([^\n]+)"),
                &log,
                r#"<span class="log5">Used interface${1}</span>: <span class="log4">${2}</span>"#,
            );
            let (l, n) = rep_cb(re!(r"(?i)Gap handling( +): ([^\n]+)"), &log, 1, |m| self.gap_handling(m));
            log = l;
            if n == 0 && eac {
                self.account(b"Could not verify gap handling", 10, None, false, false);
            }
            let (l, n) = rep_cb(re!(r"(?i)Gap status( +): (.*)"), &log, 1, |m| self.gap_handling_xld(m));
            log = l;
            if n == 0 && xld {
                self.account(b"Could not verify gap status", 10, None, false, false);
            }
            log = r1(
                re!(r"(?i)Used output format( *): ([^\n]+)"),
                &log,
                r#"<span class="log5">Used output format${1}</span>: <span class="log4">${2}</span>"#,
            );
            log = r1(
                re!(r"(?i)Sample format( +): ([^\n]+)"),
                &log,
                r#"<span class="log5">Sample format${1}</span>: <span class="log4">${2}</span>"#,
            );
            log = r1(
                re!(r"(?i)Selected bitrate( +): ([^\n]+)"),
                &log,
                r#"<span class="log5">Selected bitrate${1}</span>: <span class="log4">${2}</span>"#,
            );
            log = r1(re!(r"(?i)( +)(\d+ kBit/s)"), &log, r#"${1}<span class="log4">${2}</span>"#);
            log = r1(
                re!(r"(?i)Quality( +): ([^\n]+)"),
                &log,
                r#"<span class="log5">Quality${1}</span>: <span class="log4">${2}</span>"#,
            );
            let (l, n) = rep_cb(re!(r"(?i)Add ID3 tag( +): (Yes|No)"), &log, 1, |m| self.add_id3_tag(m));
            log = l;
            if n == 0 && eac {
                self.account(b"Could not verify id3 tag setting", 0, None, false, false);
            }
            let (l, n) =
                rep(re!(r"(?i)(Use compression offset\s+:\s+\d+)"), &log, r#"<span class="bad">${1}</span>"#, 1);
            log = l;
            if n > 0 {
                self.account(b"Ripped with compression offset", 0, Some(0), false, false);
            }
            log = r1(
                re!(r"(?i)Command line compressor( +): ([^\n]+)"),
                &log,
                r#"<span class="log5">Command line compressor${1}</span>: <span class="log4">${2}</span>"#,
            );
            log = r(
                re!(r"Additional command line options([^\n]{70,110} )"),
                &log,
                "Additional command line options${1}<br>",
            );
            log = r1(
                re!(r"(?i)( *)Additional command line options( +): (.+)\n"),
                &log,
                "<span class=\"log5\">Additional command line options${2}</span>: <span class=\"log4\">${3}</span>\n",
            );
            // XLD Range
            let (l, xld_range) =
                rep(re!(r"(?i)\n(All Tracks\n(?: *))(Filename)"), &log, "\n${1}<span class=\"bad\">${2}</span>", 1);
            log = l;
            // xld album gain
            let (l, n) = rep(
                re!(r"(?i)All Tracks(\s*\n)((?:.*)\n)?(\s*Album gain\s+:) (.*)?\n(\s*Peak\s+:) (.*)?"),
                &log,
                "<span class=\"log5\">All Tracks</span>${1}${2}<strong>${3} <span class=\"log3\">${4}</span>\n${5} <span class=\"log3\">${6}</span></strong>",
                1,
            );
            log = l;
            if n == 0 && xld {
                self.account(b"Could not verify album gain", 0, None, false, false);
            }
            // pre-0.99
            log = r1(re!(r"(?i)Other options( +):"), &log, r#"<span class="log5">Other options${1}</span>:"#);
            log = r1(
                re!(r"(?i)\n( *)Native Win32 interface(.+)"),
                &log,
                "\n${1}<span class=\"log4\">Native Win32 interface${2}</span>",
            );
            // 0.99
            log = str_replace(
                &log,
                b"TOC of the extracted CD",
                b"<span class=\"log4 log5\">TOC of the extracted CD</span>",
            );
            log = r(
                re!(r"(?i)( +)Track( +)\|( +)Start( +)\|( +)Length( +)\|( +)Start sector( +)\|( +)End sector( ?)"),
                &log,
                "<strong>${0}</strong>",
            );
            log = r(re!(r"-{10,100}"), &log, "<strong>${0}</strong>");
            log = rep_cb(
                re!(r"(?i)( +)([0-9]{1,3})( +)\|( +)(([0-9]{1,3}:)?[0-9]{2}[\.:][0-9]{2})( +)\|( +)(([0-9]{1,3}:)?[0-9]{2}[\.:][0-9]{2})( +)\|( +)([0-9]{1,10})( +)\|( +)([0-9]{1,10})( +)\n"),
                &log,
                0,
                toc,
            )
            .0;
            log = str_replace(
                &log,
                b"None of the tracks are present in the AccurateRip database",
                b"<span class=\"badish\">None of the tracks are present in the AccurateRip database</span>",
            );
            log = str_replace(
                &log,
                b"Disc not found in AccurateRip DB.",
                b"<span class=\"badish\">Disc not found in AccurateRip DB.</span>",
            );
            log = r(re!(r"(?i)No errors occurr?ed"), &log, r#"<span class="good">No errors occurred</span>"#);
            log = r(re!(r"(?i)(There were errors) ?\n"), &log, "<span class=\"bad\">${1}</span>\n");
            log = r(re!(r"(?i)(Some inconsistencies found) ?\n"), &log, "<span class=\"badish\">${1}</span>\n");
            log = r(re!(r"(?i)End of status report"), &log, r#"<span class="good">End of status report</span>"#);
            log = r(
                re!(r"(?i)Track(\s*)Ripping Status(\s*)\[Disc ID: ([0-9a-f]{8}-[0-9a-f]{8})\]"),
                &log,
                r#"<strong>Track</strong>${1}<strong>Ripping Status</strong>${2}<strong>Disc ID: </strong><span class="log1">${3}</span>"#,
            );
            log = r(re!(r"(?i)(All Tracks Accurately Ripped\.?)"), &log, r#"<span class="good">${1}</span>"#);
            log = r(re!(r"(?i)\d+ track.* +accurately ripped\.? *\n"), &log, r#"<span class="good">${0}</span>"#);
            log = r(
                re!(r"(?i)\d+ track.* +not present in the AccurateRip database\.? *\n"),
                &log,
                r#"<span class="badish">${0}</span>"#,
            );
            log = r(re!(r"(?i)\d+ track.* +canceled\.? *\n"), &log, r#"<span class="bad">${0}</span>"#);
            log = r(
                re!(r"(?i)\d+ track.* +could not be verified as accurate\.? *\n"),
                &log,
                r#"<span class="badish">${0}</span>"#,
            );
            log = r(
                re!(r"(?i)Some tracks could not be verified as accurate\.? *\n"),
                &log,
                r#"<span class="badish">${0}</span>"#,
            );
            log = r(
                re!(r"(?i)No tracks could be verified as accurate\.? *\n"),
                &log,
                r#"<span class="badish">${0}</span>"#,
            );
            log = r(re!(r"(?i)You may have a different pressing.*\n"), &log, r#"<span class="goodish">${0}</span>"#);
            // xld accurip summary
            log = rep_cb(
                re!(r"(?i)(Track +\d+ +: +)(OK +)\(A?R?\d?,? ?confidence +(\d+).*?\)(.*)\n"),
                &log,
                0,
                ar_summary_conf_xld,
            )
            .0;
            log = rep_cb(re!(r"(?i)(Track +\d+ +: +)(NG|Not Found).*?\n"), &log, 0, ar_summary_conf_xld).0;
            // Status line
            log = r1(re!(r"(?i)( *.{2} ?)(\d+ track\(s\).*)\n"), &log, "${1}<span class=\"log4\">${2}</span>\n");
            // accurip summary (range)
            log = r(re!(r"(?i)\n( *AccurateRip summary\.?)"), &log, "\n<span class=\"log4 log5\">${1}</span>");
            log = rep_cb(
                re!(r"(?i)(Track +\d+ +.*?accurately ripped\.? *)(\(confidence +)(\d+)\)(.*)\n"),
                &log,
                0,
                ar_summary_conf,
            )
            .0;
            log = r(re!(r"(?i)(Track +\d+ +.*?in database *)\n"), &log, "<span class=\"badish\">${1}</span>\n");
            log = r(
                re!(r"(?i)(Track +\d+ +.*?(could not|cannot) be verified as accurate.*)\n"),
                &log,
                "<span class=\"badish\">${1}</span>\n",
            );
            // range rip
            let (l, range1) = rep(re!(r"(?i)\n( *Selected range)"), &log, "\n<span class=\"bad\">${1}</span>", 1);
            let (l, range2) =
                rep(re!(r"(?i)\n( *Range status and errors)"), &l, "\n<span class=\"bad\">${1}</span>", 1);
            log = l;
            if range1 > 0 || range2 > 0 || xld_range > 0 {
                self.range = true;
                self.account(b"Range rip detected", 30, None, false, false);
            }

            let mut formatted_track_listing = Vec::new();
            let mut track_listing = Vec::new();
            let mut track_bodies: Vec<Vec<u8>> = vec![];
            let mut full_tracks: Vec<Vec<u8>> = vec![];
            const LOG_ENDS: [&[u8]; 7] = [
                b"None of the tracks are present in the AccurateRip database",
                b"No errors occurred",
                b"All tracks accurately ripped",
                b"No tracks could be verified as accurate",
                b"track(s) not present in the AccurateRip database",
                b"End of status report",
                b"There were errors",
            ];
            // Drop trailing summary lines: PHP walks back from the end of the listing.
            let cut = |listing: &[u8]| -> i64 {
                let lines: Vec<&[u8]> = listing.split(|&b| b == b'\n').collect();
                let mut i = lines.len() as i64 - 1;
                'outer: while i >= 0 {
                    for end in LOG_ENDS {
                        if lines[i as usize].ends_with(end) {
                            i -= 1;
                            break 'outer;
                        }
                    }
                    if re!(r"(?i)[ \t]+ [a-z]").is_match(lines[i as usize]) {
                        break;
                    }
                    i -= 1;
                }
                i
            };
            // XLD range rips still print individual tracks, they just lack filenames.
            if !self.range || xld {
                if let Some(m) = re!(r"(?i)\nTrack( +)([0-9]{1,3})([\s\S]+)").find(&log) {
                    let listing = m.as_bytes().to_vec();
                    let i = cut(&listing);
                    let lines: Vec<&[u8]> = listing.split(|&b| b == b'\n').collect();
                    track_listing = lines[..(i + 1).max(0) as usize].join(&b'\n');
                    let sep = re!(r"(?i)\nTrack( +)([0-9]{1,3})");
                    full_tracks = split(sep, &track_listing, true);
                    full_tracks.remove(0);
                    track_bodies = split(sep, &track_listing, false);
                    track_bodies.remove(0);
                }
            } else if let Some(m) = re!(r"(?i)\n( *)Filename +(.*)([\s\S]+)").find(&log) {
                // Range rip. PHP computes the cut here but never applies it.
                track_listing = m.as_bytes().to_vec();
                let sep = re!(r"(?i)\n( *)Filename +(.*)");
                full_tracks = split(sep, &track_listing, true);
                full_tracks.remove(0);
                track_bodies = split(sep, &track_listing, false);
                track_bodies.remove(0);
            }

            for (key, body) in track_bodies.into_iter().enumerate() {
                let spaces = full_tracks[key * 3].clone();
                let track_number = full_tracks[key * 3 + 1].clone();
                self.track_number = track_number.clone();
                self.decrease_score_track = 0;
                self.bad_track = vec![];
                let mut body = if !self.range {
                    cat(&[b"<span class=\"log5\">Track</span>", &spaces, b"<span class=\"log4 log1\">", &track_number, b"</span>", &body])
                } else {
                    cat(&[&spaces, b"<span class=\"log5\">Filename</span> <span class=\"log4 log3\">", &track_number, b"</span>", &body])
                };
                // match newline for xld multifile encodes
                let (b, n) = rep(
                    re!(r"(?is)Filename ((.+)?\.(wav|flac|ape))\n"),
                    &body,
                    "<span class=\"log4\">Filename <span class=\"log3\">${1}</span></span>\n",
                    0,
                );
                body = b;
                if n == 0 && !self.range {
                    // EAC truncates file names that would exceed 243 characters, so we'll just mark
                    // it as fine, as it almost always is.
                    let long = eac
                        && re!(r"(?i)Filename (.+)\n").captures(&body).is_some_and(|c| c[1].len() >= 243);
                    if long {
                        body = r(
                            re!(r"(?i)Filename ((.+)?)\n"),
                            &body,
                            "<span class=\"log4\">Filename <span class=\"log3\">${1}</span></span>\n",
                        );
                        self.account_track(b"Could not verify filename, too long", None);
                    } else {
                        self.account_track(b"Could not verify filename or file extension", dec(1));
                    }
                }
                let (b, n) = rep(re!(r"(?i)( *)(File write error)\n"), &body, "${1}<span class=\"bad\">${2}</span>\n", 0);
                body = b;
                if n > 0 {
                    self.account_track(b"File write error", dec(20));
                }
                // xld track gain
                body = r(
                    re!(r"(?i)( *Track gain\s+:) (.*)?\n(\s*Peak\s+:) (.*)?"),
                    &body,
                    "<strong>${1} <span class=\"log3\">${2}</span>\n${3} <span class=\"log3\">${4}</span></strong>",
                );
                body = r(re!(r"(?i)( +)(Statistics *)\n"), &body, "${1}<span class=\"log5\">${2}</span>\n");
                let stats: [(&Regex, &[u8], u8); 11] = [
                    (re!(r"(?i)(Read error)( +:) (\d+)"), b"Could not verify read errors", 0),
                    (re!(r"(?i)(Skipped \(treated as error\))( +:) (\d+)"), b"Could not verify skipped errors", 1),
                    (re!(r"(?i)(Edge jitter error \(maybe fixed\))( +:) (\d+)"), b"Could not verify edge jitter errors", 1),
                    (re!(r"(?i)(Atom jitter error \(maybe fixed\))( +:) (\d+)"), b"Could not verify atom jitter errors", 1),
                    (re!(r"(?i)(Jitter error \(maybe fixed\))( +:) (\d+)"), b"Could not verify jitter errors", 2),
                    (re!(r"(?i)(Retry sector count)( +:) (\d+)"), b"Could not verify retry sector count", 2),
                    (re!(r"(?i)(Damaged sector count)( +:) (\d+)"), b"Could not verify damaged sector count", 2),
                    (re!(r"(?i)(Drift error \(maybe fixed\))( +:) (\d+)"), b"Could not verify drift errors", 1),
                    (re!(r"(?i)(Dropped bytes error \(maybe fixed\))( +:) (\d+)"), b"Could not verify dropped bytes errors", 1),
                    (re!(r"(?i)(Duplicated bytes error \(maybe fixed\))( +:) (\d+)"), b"Could not verify duplicated bytes errors", 1),
                    (re!(r"(?i)(Inconsistency in error sectors)( +:) (\d+)"), b"Could not verify inconsistent error sectors", 1),
                ];
                // 0: any XLD, 1: XLD without Secure Ripper, 2: XLD Secure Ripper only.
                for (re, msg, when) in stats {
                    let (b, n) = rep_cb(re, &body, 0, |m| self.xld_stat(m));
                    body = b;
                    let applies = match when {
                        0 => xld,
                        1 => xld && !self.xld_secure_ripper,
                        _ => xld && self.xld_secure_ripper,
                    };
                    if n == 0 && applies {
                        self.account_track(msg, None);
                    }
                }
                let (b, n) = rep(
                    re!(r"(?i)(List of suspicious positions +)(: *\n?)(( *.* +\d{2}:\d{2}:\d{2} *\n)+)"),
                    &body,
                    r#"<span class="bad">${1}</span><strong>${2}</strong><span class="bad">${3}</span></span>"#,
                    0,
                );
                body = b;
                if n > 0 {
                    self.account_track(b"Suspicious position(s) found", dec(20));
                }
                let (b, n) = rep(
                    re!(r"(?i)Suspicious position( +)([0-9]:[0-9]{2}:[0-9]{2})"),
                    &body,
                    r#"<span class="bad">Suspicious position${1}<span class="log4">${2}</span></span>"#,
                    0,
                );
                body = b;
                if n > 0 {
                    self.account_track(b"Suspicious position(s) found", dec(20));
                }
                let (b, n) = rep(
                    re!(r"(?i)Timing problem( +)([0-9]:[0-9]{2}:[0-9]{2})"),
                    &body,
                    r#"<span class="bad">Timing problem${1}<span class="log4">${2}</span></span>"#,
                    0,
                );
                body = b;
                if n > 0 {
                    self.account_track(b"Timing problem(s) found", dec(20));
                }
                let (b, n) = rep(re!(r"(?i)Missing samples"), &body, r#"<span class="bad">Missing samples</span>"#, 0);
                body = b;
                if n > 0 {
                    self.account_track(b"Missing sample(s) found", dec(20));
                }
                let (b, n) = rep(re!(r"(?i)Copy aborted"), &body, r#"<span class="bad">Copy aborted</span>"#, 0);
                body = b;
                let aborted = n > 0;
                if aborted {
                    self.account_track(b"Copy aborted", dec(100));
                }
                body = r(
                    re!(r"(?i)Pre-gap length( +|\s+:\s+)([0-9]{1,2}:[0-9]{2}:[0-9]{2}.?[0-9]{0,2})"),
                    &body,
                    r#"<span class="log4">Pre-gap length${1}<span class="log3">${2}</span></span>"#,
                );
                body = r(
                    re!(r"(?i)Peak level ([0-9]{1,3}\.[0-9] %)"),
                    &body,
                    r#"<span class="log4">Peak level <span class="log3">${1}</span></span>"#,
                );
                body = r(
                    re!(r"(?i)Extraction speed ([0-9]{1,3}\.[0-9]{1,} X)"),
                    &body,
                    r#"<span class="log4">Extraction speed <span class="log3">${1}</span></span>"#,
                );
                body = r(
                    re!(r"(?i)Track quality ([0-9]{1,3}\.[0-9] %)"),
                    &body,
                    r#"<span class="log4">Track quality <span class="log3">${1}</span></span>"#,
                );
                body = r(
                    re!(r"(?i)Range quality\s+([0-9]{1,3}\.[0-9] %)"),
                    &body,
                    r#"<span class="log4">Range quality <span class="log3">${1}</span></span>"#,
                );
                body = r(
                    re!(r"(?i)CRC32 hash \(skip zero\)(\s*:) ([0-9A-F]{8})"),
                    &body,
                    r#"<span class="log4">CRC32 hash (skip zero)${1}<span class="log3"> ${2}</span></span>"#,
                );
                let (b, eac_tc) = rep_cb(
                    re!(r"(?i)Test CRC ([0-9A-F]{8})\n(\s*)Copy CRC ([0-9A-F]{8})"),
                    &body,
                    0,
                    |m| self.test_copy(m),
                );
                let (b, xld_tc) = rep_cb(
                    re!(r"(?i)CRC32 hash \(test run\)(\s*:) ([0-9A-F]{8})\n(\s*)CRC32 hash(\s+:) ([0-9A-F]{8})"),
                    &b,
                    0,
                    |m| self.test_copy(m),
                );
                body = b;
                if eac_tc == 0 && xld_tc == 0 && !aborted {
                    self.account(b"Test and copy was not used", 10, None, false, false);
                    if !self.secure_mode {
                        let msg: &[u8] = if eac {
                            b"Rip was not done in Secure mode, and T+C was not used - as a result, we cannot verify the authenticity of the rip (-40 points)"
                        } else {
                            b"Rip was not done with Secure Ripper / in CDParanoia mode, and T+C was not used - as a result, we cannot verify the authenticity of the rip (-40 points)"
                        };
                        if !self.seen.contains(msg) {
                            self.score -= 40;
                            self.push_detail(msg.to_vec());
                        }
                    }
                }
                body = r(
                    re!(r"(?i)Copy CRC ([0-9A-F]{8})"),
                    &body,
                    r#"<span class="log4">Copy CRC <span class="log3">${1}</span></span>"#,
                );
                body = r(
                    re!(r"(?i)CRC32 hash(\s*:) ([0-9A-F]{8})"),
                    &body,
                    r#"<span class="log4">CRC32 hash${1}<span class="goodish"> ${2}</span></span>"#,
                );
                body = str_replace(
                    &body,
                    b"Track not present in AccurateRip database",
                    b"<span class=\"badish\">Track not present in AccurateRip database</span>",
                );
                body = r(
                    re!(r"(?i)Accurately ripped( +)\(confidence ([0-9]+)\)( +)(\[[0-9A-F]{8}\])"),
                    &body,
                    r#"<span class="good">Accurately ripped${1}(confidence ${2})${3}${4}</span>"#,
                );
                body = r(re!(r"(?i)Cannot be verified as accurate +\(.*"), &body, r#"<span class="badish">${0}</span>"#);
                // xld ar
                body = rep_cb(
                    re!(r"(?i)AccurateRip signature( +): ([0-9A-F]{8})\n(.*?)(Accurately ripped!?)( +\(A?R?\d?,? ?confidence )([0-9]+\))"),
                    &body,
                    0,
                    ar_xld,
                )
                .0;
                body = r(
                    re!(r"(?i)AccurateRip signature( +): ([0-9A-F]{8})\n(.*?)(Rip may not be accurate\.?)(.*?)"),
                    &body,
                    "<span class=\"log4\">AccurateRip signature${1}: <span class=\"badish\">${2}</span></span>\n${3}<span class=\"badish\">${4}${5}</span>",
                );
                body = r(re!(r"(?i)(Rip may not be accurate\.?)(.*?)"), &body, "<span class=\"badish\">${1}${2}</span>");
                body = r(
                    re!(r"(?i)AccurateRip signature( +): ([0-9A-F]{8})\n(.*?)(Track not present in AccurateRip database\.?)(.*?)"),
                    &body,
                    "<span class=\"log4\">AccurateRip signature${1}: <span class=\"badish\">${2}</span></span>\n${3}<span class=\"badish\">${4}${5}</span>",
                );
                body = r(
                    re!(r"(?i)\(matched[ \w]+;\n *calculated[ \w]+;\n[ \w]+signature[ \w:]+\)"),
                    &body,
                    "<span class=\"goodish\">${0}</span>",
                );
                body = str_replace(&body, b"Copy finished", b"<span class=\"log3\">Copy finished</span>");
                body = r(re!(r"(?i)Copy OK"), &body, r#"<span class="good">Copy OK</span>"#);
                let track = Track { decrease: self.decrease_score_track, bad: std::mem::take(&mut self.bad_track) };
                formatted_track_listing.push(b'\n');
                formatted_track_listing.extend_from_slice(&body);
                upsert(&mut self.tracks[idx], track_number, track);
            }
            log = str_replace(&log, &track_listing, &formatted_track_listing);
            log = str_replace(&log, b"<br>", b"\n");
            // xld all tracks statistics
            log = r1(re!(r"(?i)( +)?(All tracks *)\n"), &log, "${1}<span class=\"log5\">${2}</span>\n");
            log = r1(re!(r"(?i)( +)(Statistics *)\n"), &log, "${1}<span class=\"log5\">${2}</span>\n");
            for re in [
                re!(r"(?i)(Read error)( +:) (\d+)"),
                re!(r"(?i)(Skipped \(treated as error\))( +:) (\d+)"),
                re!(r"(?i)(Jitter error \(maybe fixed\))( +:) (\d+)"),
                re!(r"(?i)(Edge jitter error \(maybe fixed\))( +:) (\d+)"),
                re!(r"(?i)(Atom jitter error \(maybe fixed\))( +:) (\d+)"),
                re!(r"(?i)(Drift error \(maybe fixed\))( +:) (\d+)"),
                re!(r"(?i)(Dropped bytes error \(maybe fixed\))( +:) (\d+)"),
                re!(r"(?i)(Duplicated bytes error \(maybe fixed\))( +:) (\d+)"),
                re!(r"(?i)(Retry sector count)( +:) (\d+)"),
                re!(r"(?i)(Damaged sector count)( +:) (\d+)"),
            ] {
                log = rep_cb(re, &log, 1, xld_all_stat).0;
            }
            self.logs[idx] = log;
            self.check_tracks(idx);

            if let Some(mode) = self.non_secure_mode.clone().filter(|m| truthy(m)) {
                self.account(&cat(&[&mode, b" mode was used"]), 20, None, false, false);
            }
            self.secure_mode = true;
            self.non_secure_mode = None;
        }

        let mut final_tracks: Vec<(Vec<u8>, Track)> = vec![];
        for tracks in std::mem::take(&mut self.tracks) {
            for (number, track) in tracks {
                upsert(&mut final_tracks, number, track);
            }
        }
        for (_, track) in final_tracks {
            self.score -= track.decrease;
            for line in track.bad {
                self.push_detail(line);
            }
        }

        self.log = self.logs.concat();
        if self.log.is_empty() {
            self.score = 0;
            self.account(b"Unrecognized log file! Feel free to report for manual review.", 0, None, false, false);
        }
        if let Some(n) = self.combined {
            self.details.insert(0, format!("Combined Log ({n})").into_bytes());
        }
    }

    fn non_secure(&self) -> bool {
        self.non_secure_mode.as_deref().is_some_and(truthy)
    }

    // Callback functions

    fn drive(&mut self, m: &M) -> Vec<u8> {
        let drive_name = php::trim_bytes(m.g(2));
        if drive_name == b"(null) (null) (revision (null))" {
            self.account(b"Null drive used", 20, None, false, false);
            return cat(&[b"<span class=\"log5\">Used Drive", m.g(1), b"</span>: <span class=\"bad\">", m.g(2), b"</span>"]);
        }
        if FAKE_DRIVES.iter().any(|d| loose_eq(d, drive_name)) {
            self.account(&cat(&[b"Virtual drive used: ", m.g(2)]), 20, None, false, false);
            return cat(&[b"<span class=\"log5\">Used Drive", m.g(1), b"</span>: <span class=\"bad\">", m.g(2), b"</span>"]);
        }
        self.get_drives(drive_name);
        let mut name = m.g(2).to_vec();
        let class: &[u8] = if !self.drives.is_empty() {
            self.drive_found = true;
            b"good"
        } else {
            name.extend_from_slice(b" (not found in database)");
            self.drive_found = false;
            b"badish"
        };
        cat(&[b"<span class=\"log5\">Used Drive", m.g(1), b"</span>: <span class=\"", class, b"\">", &name, b"</span>"])
    }

    pub(crate) fn get_drives(&mut self, drive_name: &[u8]) {
        // Transform what drives report about themselves into AccurateRip DB names.
        let mut d = str_replace(drive_name, b"JLMS", b"Lite-ON");
        d = r(re!(r"TSSTcorp(BD|CD|DVD)"), &d, "TSSTcorp ${1}");
        d = r(re!(r"HL-DT-ST(BD|CD|DVD)"), &d, "HL-DT-ST ${1}");
        d = str_replace(&d, b"HL-DT-ST", b"LG Electronics");
        d = str_replace(&d, b"Matshita", b"Panasonic");
        d = str_replace(&d, b"MATSHITA", b"Panasonic");
        d = r(re!(r"Panasonic(BD|CD|DVD)"), &d, "Panasonic ${1}");
        d = r(re!(r"^[ _-]+"), &d, "");
        d = r(re!(r"\s+-\s"), &d, " ");
        d = r(re!(r"\s+"), &d, " ");
        d = r(re!(r"\(revision [a-zA-Z0-9\.\,\-]*\)"), &d, "");
        // PCRE `$` also matches before a final newline; \s+ above already turned any into a space.
        d = r(re!(r" Adapter.*$"), &d, "");
        let d = php::trim_bytes(&lower(&d)).to_vec();

        // LOGCHECKER_LEVENSTEIN_DISTANCE is 0, so only exact matches count.
        self.drives = vec![];
        self.offsets = vec![];
        for (drive, offset) in ALL_DRIVES.iter() {
            if drive.as_bytes() == d.as_slice() {
                self.drives.push(drive.clone());
                self.offsets.push(offset.clone());
            }
        }
    }

    fn media_type_xld(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if loose_eq(php::trim_bytes(m.g(2)), b"Pressed CD") {
            b"good"
        } else {
            // CD-R etc.; not necessarily "bad" (e.g. commercial CD-R)
            self.account(b"Not a pressed cd", 0, None, true, true);
            b"badish"
        };
        cat(&[b"<span class=\"log5\">Media type", m.g(1), b"</span>: <span class=\"", class, b"\">", m.g(2), b"</span>"])
    }

    fn read_mode(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if loose_eq(m.g(2), b"Secure") {
            b"good"
        } else {
            self.secure_mode = false;
            self.non_secure_mode = Some(m.g(2).to_vec());
            b"bad"
        };
        let mut s = cat(&[b"<span class=\"log5\">Read mode", m.g(1), b"</span>: <span class=\"", class, b"\">", m.g(2), b"</span>"]);
        if truthy(m.g(3)) {
            s.extend(cat(&[b"<span class=\"log4\">", m.g(3), b"</span>"]));
        }
        s
    }

    fn cdparanoia_mode_xld(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if loose_eq(&m.g(2)[..m.g(2).len().min(3)], b"YES") {
            b"good"
        } else {
            self.secure_mode = false;
            b"bad"
        };
        cat(&[b"<span class=\"log5\">Use cdparanoia mode", m.g(1), b"</span>: <span class=\"", class, b"\">", m.g(2), b"</span>"])
    }

    fn ripper_mode_xld(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if loose_eq(&m.g(2)[..m.g(2).len().min(10)], b"CDParanoia") {
            b"good"
        } else if loose_eq(m.g(2), b"XLD Secure Ripper") {
            self.xld_secure_ripper = true;
            b"good"
        } else {
            self.secure_mode = false;
            b"bad"
        };
        cat(&[b"<span class=\"log5\">Ripper mode", m.g(1), b"</span>: <span class=\"", class, b"\">", m.g(2), b"</span>"])
    }

    fn max_retry_count(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if cmp_str_num(m.g(2), Num::Int(10)).is_ge() {
            b"goodish"
        } else {
            self.account(b"Low \"max retry count\" (potentially bad setting)", 0, None, false, false);
            b"badish"
        };
        cat(&[b"<span class=\"log5\">Max retry count", m.g(1), b"</span>: <span class=\"", class, b"\">", m.g(2), b"</span>"])
    }

    fn accurate_stream(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if loose_eq(m.g(2), b"Yes") {
            b"good"
        } else {
            self.account(b"\"Utilize accurate stream\" should be yes", 20, None, false, false);
            b"bad"
        };
        cat(&[b"<span class=\"log5\">Utilize accurate stream", m.g(1), b"</span>: <span class=\"", class, b"\">", m.g(2), b"</span>"])
    }

    fn accurate_stream_eac_pre9(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if !loose_eq(&lower(m.g(1)), b"no ") {
            b"good"
        } else {
            self.account(b"\"accurate stream\" should be yes", 20, None, false, false);
            b"bad"
        };
        cat(&[b", <span class=\"", class, b"\">", m.g(1), b"accurate stream</span>"])
    }

    fn defeat_audio_cache(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if loose_eq(m.g(2), b"Yes") {
            b"good"
        } else {
            self.account(b"\"Defeat audio cache\" should be yes", 10, None, false, false);
            b"bad"
        };
        cat(&[b"<span class=\"log5\">Defeat audio cache", m.g(1), b"</span>: <span class=\"", class, b"\">", m.g(2), b"</span>"])
    }

    fn defeat_audio_cache_eac_pre99(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if !loose_eq(&lower(m.g(1)), b"no ") {
            b"good"
        } else {
            self.account(b"Audio cache not disabled", 10, None, false, false);
            b"bad"
        };
        cat(&[b" <span class=\"", class, b"\">", m.g(1), b"disable cache</span>"])
    }

    fn defeat_audio_cache_xld(&mut self, m: &M) -> Vec<u8> {
        let v = m.g(2);
        let class: &[u8] = if loose_eq(&v[..v.len().min(2)], b"OK") || loose_eq(&v[..v.len().min(3)], b"YES") {
            b"good"
        } else {
            self.account(b"\"Disable audio cache\" should be yes/ok", 10, None, false, false);
            b"bad"
        };
        cat(&[b"<span class=\"log5\">Disable audio cache", m.g(1), b"</span>: <span class=\"", class, b"\">", v, b"</span>"])
    }

    fn c2_pointers(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if loose_eq(&lower(m.g(2)), b"yes") {
            self.account(b"C2 pointers were used", 10, None, false, false);
            b"bad"
        } else {
            b"good"
        };
        cat(&[b"<span class=\"log5\">Make use of C2 pointers", m.g(1), b"</span>: <span class=\"", class, b"\">", m.g(2), b"</span>"])
    }

    fn c2_pointers_eac_pre99(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if loose_eq(&lower(m.g(1)), b"no ") {
            b"good"
        } else {
            self.account(b"C2 pointers were used", 10, None, false, false);
            b"bad"
        };
        cat(&[b"with <span class=\"", class, b"\">", m.g(1), b"C2</span>"])
    }

    fn read_offset(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if self.drive_found {
            if self.offsets.iter().any(|o| loose_eq(m.g(2), o.as_bytes())) {
                b"good"
            } else {
                let msg = format!(
                    "Incorrect read offset for drive. Correct offsets are: {} (Checked against the following drive(s): {})",
                    self.offsets.join(", "),
                    self.drives.join(", ")
                );
                self.account(msg.as_bytes(), 5, None, false, false);
                b"bad"
            }
        } else if cmp_str_num(m.g(2), Num::Int(0)).is_eq() {
            self.account(OFFSET_ZERO_MSG, 5, None, false, false);
            b"bad"
        } else {
            b"badish"
        };
        cat(&[b"<span class=\"log5\">Read offset correction", m.g(1), b"</span>: <span class=\"", class, b"\">", m.g(2), b"</span>"])
    }

    fn fill_offset_samples(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if loose_eq(m.g(2), b"Yes") {
            b"good"
        } else {
            self.account(b"Does not fill up missing offset samples with silence", 5, None, false, false);
            b"bad"
        };
        cat(&[b"<span class=\"log5\">Fill up missing offset samples with silence", m.g(1), b"</span>: <span class=\"", class, b"\">", m.g(2), b"</span>"])
    }

    fn delete_silent_blocks(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if loose_eq(m.g(3), b"Yes") {
            self.account(b"Deletes leading and trailing silent blocks", 5, None, false, false);
            b"bad"
        } else {
            b"good"
        };
        cat(&[b"<span class=\"log5\">Delete leading and trailing silent blocks", m.g(1), m.g(2), b"</span>: <span class=\"", class, b"\">", m.g(3), b"</span>"])
    }

    fn null_samples(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if loose_eq(m.g(2), b"Yes") {
            b"good"
        } else {
            self.account(b"Null samples should be used in CRC calculations", 5, None, false, false);
            b"bad"
        };
        cat(&[b"<span class=\"log5\">Null samples used in CRC calculations", m.g(1), b"</span>: <span class=\"", class, b"\">", m.g(2), b"</span>"])
    }

    fn normalize_eac(&mut self, m: &M) -> Vec<u8> {
        self.account(b"Normalization should be not be active", 100, None, false, false);
        cat(&[b"<span class=\"log5\">Normalize to", m.g(1), b"</span>: <span class=\"bad\">", m.g(2), b"</span>"])
    }

    fn gap_handling(&mut self, m: &M) -> Vec<u8> {
        let v = m.g(2);
        let class: &[u8] = if contains(v, b"Not detected") {
            self.account(b"Gap handling was not detected", 10, None, false, false);
            b"bad"
        } else if contains(v, b"Appended to next track") || contains(v, b"Left out") {
            self.account(b"Gap handling should be appended to previous track", 10, None, false, false);
            b"bad"
        } else if contains(v, b"Appended to previous track") {
            b"good"
        } else {
            b"goodish"
        };
        cat(&[b"<span class=\"log5\">Gap handling", m.g(1), b"</span>: <span class=\"", class, b"\">", v, b"</span>"])
    }

    fn gap_handling_xld(&mut self, m: &M) -> Vec<u8> {
        let v = lower(m.g(2));
        let class: &[u8] = if contains(&v, b"not") {
            self.account(b"Incorrect gap handling", 10, None, false, false);
            b"bad"
        } else if contains(&v, b"analyzed") && contains(&v, b"appended") {
            b"good"
        } else {
            self.account(b"Incomplete gap handling", 10, None, false, false);
            b"badish"
        };
        cat(&[b"<span class=\"log5\">Gap status", m.g(1), b"</span>: <span class=\"", class, b"\">", m.g(2), b"</span>"])
    }

    fn add_id3_tag(&mut self, m: &M) -> Vec<u8> {
        let class: &[u8] = if loose_eq(m.g(2), b"Yes") {
            self.account(
                b"ID3 tags should not be added to FLAC files - they are mainly for MP3 files. FLACs should have vorbis comments for tags instead.",
                1,
                None,
                false,
                false,
            );
            b"badish"
        } else {
            b"good"
        };
        cat(&[b"<span class=\"log5\">Add ID3 tag", m.g(1), b"</span>: <span class=\"", class, b"\">", m.g(2), b"</span>"])
    }

    fn crc_mismatch(&mut self, a: &[u8], b: &[u8], how: &str) -> &'static [u8] {
        if loose_eq(a, b) {
            return b"good";
        }
        self.account_track(&cat(&[b"CRC mismatch: ", a, b" and ", b]), dec(30));
        if !self.secure_mode {
            self.decrease_score_track += 20;
            let combined = match self.combined {
                Some(n) if n > 0 => format!(" ({}) ", self.curr_log),
                _ => String::new(),
            };
            self.bad_track
                .push(format!("Rip {combined}was not done {how}, and experienced CRC mismatches (-20 points)").into_bytes());
            self.secure_mode = true;
        }
        b"bad"
    }

    fn test_copy(&mut self, m: &M) -> Vec<u8> {
        match self.ripper {
            Some(Ripper::Eac) => {
                let class = self.crc_mismatch(m.g(1), m.g(3), "in Secure mode");
                cat(&[b"<span class=\"log4\">Test CRC <span class=\"", class, b"\">", m.g(1), b"</span></span>\n", m.g(2), b"<span class=\"log4\">Copy CRC <span class=\"", class, b"\">", m.g(3), b"</span></span>"])
            }
            Some(Ripper::Xld) => {
                let class = self.crc_mismatch(m.g(2), m.g(5), "with Secure Ripper / in CDParanoia mode");
                cat(&[b"<span class=\"log4\">CRC32 hash (test run)", m.g(1), b" <span class=\"", class, b"\">", m.g(2), b"</span></span>\n", m.g(3), b"<span class=\"log4\">CRC32 hash", m.g(4), b" <span class=\"", class, b"\">", m.g(5), b"</span></span>"])
            }
            _ => vec![],
        }
    }

    fn xld_stat(&mut self, m: &M) -> Vec<u8> {
        let text = cat(&[m.g(1), m.g(2)]);
        let name = lower(m.g(1));
        let n = m.g(3);
        let zero = cmp_str_num(n, Num::Int(0)).is_eq();
        let err = || if cmp_str_num(n, Num::Int(10)).is_gt() { dec(10) } else { Some((n.to_vec(), numeric_i64(n))) };
        let one = cmp_str_num(n, Num::Int(1)).is_eq();
        let class: &[u8] = match name.as_slice() {
            b"read error" | b"skipped (treated as error)" | b"inconsistency in error sectors" | b"damaged sector count" => {
                if zero {
                    b"good"
                } else {
                    let msg = match name.as_slice() {
                        b"read error" => cat(&[b"Read error", if one { b"" } else { b"s" }, b" detected"]),
                        b"skipped (treated as error)" => cat(&[b"Skipped error", if one { b"" } else { b"s" }, b" detected"]),
                        b"inconsistency in error sectors" => {
                            cat(&[b"Inconsistenc", if one { b"y" } else { b"ies" }, b" in error sectors detected"])
                        }
                        _ => cat(&[b"Damaged sector count of ", n]),
                    };
                    self.account_track(&msg, err());
                    b"bad"
                }
            }
            _ if XLD_SOFT_STATS.contains(&name.as_slice()) => {
                if zero {
                    b"goodish"
                } else {
                    b"badish"
                }
            }
            _ => return vec![],
        };
        cat(&[b"<span class=\"log4\">", &text, b"</span> <span class=\"", class, b"\">", n, b"</span>"])
    }

    /// `$this->details[] = $line`.
    fn push_detail(&mut self, line: Vec<u8>) {
        self.seen.insert(line.clone());
        self.details.push(line);
    }

    fn clear_details(&mut self) {
        self.details.clear();
        self.seen.clear();
    }

    fn check_tracks(&mut self, idx: usize) {
        if self.tracks[idx].is_empty() {
            self.clear_details();
            if let Some(n) = self.combined {
                self.push_detail(format!("Combined Log ({n})").into_bytes());
                self.push_detail(format!("Invalid log ({}), no tracks!", self.curr_log).into_bytes());
            } else {
                self.push_detail(b"Invalid log, no tracks!".to_vec());
            }
            self.score = 0;
        }
    }

    /// account($Msg, $Decrease, $Score, $InclCombined, $Notice); decrease 0 = false.
    pub(crate) fn account(&mut self, msg: &[u8], decrease: i64, score: Option<i64>, incl_combined: bool, notice: bool) {
        let append1 = match (incl_combined, self.combined) {
            (true, Some(n)) if n > 0 => format!(" ({})", self.curr_log),
            _ => String::new(),
        };
        let prepend: &[u8] = if notice { b"[Notice] " } else { b"" };
        let (mut decrease_score, mut set_score, mut append2) = (false, false, vec![]);
        let mut decrease = decrease;
        if decrease != 0 {
            decrease_score = true;
            if decrease > 0 {
                append2 = points(decrease.to_string().as_bytes(), decrease == 1);
            }
        } else if let Some(score) = score {
            set_score = true;
            decrease = 100 - score;
            if decrease > 0 {
                append2 = points(decrease.to_string().as_bytes(), decrease == 1);
            }
        }
        let line = cat(&[prepend, msg, append1.as_bytes(), &append2]);
        // Every detail line starts with a letter or '[', so PHP's loose in_array is an exact match.
        if !self.seen.contains(&line) {
            self.push_detail(line);
            if decrease_score {
                self.score -= decrease;
            }
            if set_score {
                self.score = score.unwrap();
            }
        }
    }

    /// accountTrack; the decrease keeps PHP's original spelling (it may be a matched string).
    fn account_track(&mut self, msg: &[u8], decrease: Option<(Vec<u8>, i64)>) {
        let n = intval(&self.track_number);
        let tn = if n < 10 { format!("0{n}").into_bytes() } else { self.track_number.clone() };
        let mut append = vec![];
        if let Some((spelling, value)) = decrease.filter(|(s, _)| truthy(s)) {
            self.decrease_score_track += value;
            append = points(&spelling, loose_eq(&spelling, b"1"));
        }
        let combined = match self.combined {
            Some(n) if n > 0 => format!(" ({})", self.curr_log),
            _ => String::new(),
        };
        self.bad_track.push(cat(&[b"Track ", &tn, combined.as_bytes(), b": ", msg, &append]));
    }
}

pub(crate) const OFFSET_ZERO_MSG: &[u8] = b"The drive was not found in the database, so we cannot determine the correct read offset. However, the read offset in this case was 0, which is almost never correct. As such, we are assuming that the offset is incorrect";

const XLD_SOFT_STATS: [&[u8]; 7] = [
    b"retry sector count",
    b"jitter error (maybe fixed)",
    b"edge jitter error (maybe fixed)",
    b"atom jitter error (maybe fixed)",
    b"drift error (maybe fixed)",
    b"dropped bytes error (maybe fixed)",
    b"duplicated bytes error (maybe fixed)",
];

fn dec(d: i64) -> Option<(Vec<u8>, i64)> {
    Some((d.to_string().into_bytes(), d))
}

/// PHP intval() of a string: leading whitespace, optional sign, digits (saturating).
fn intval(s: &[u8]) -> i64 {
    let s = &s[s.iter().position(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0B' | b'\x0C')).unwrap_or(s.len())..];
    let (neg, digits) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let end = digits.iter().position(|b| !b.is_ascii_digit()).unwrap_or(digits.len());
    let mut v: i64 = 0;
    for &d in &digits[..end] {
        v = v.saturating_mul(10).saturating_add((d - b'0') as i64);
    }
    if neg { -v } else { v }
}

fn numeric_i64(s: &[u8]) -> i64 {
    match php::numeric(s) {
        Some(Num::Int(i)) => i,
        Some(Num::Float(f)) => f as i64,
        None => 0,
    }
}

fn toc(m: &M) -> Vec<u8> {
    cat(&[
        m.g(1), b"<span class=\"log4\">", m.g(2), b"</span>", m.g(3), b"<strong>|</strong>",
        m.g(4), b"<span class=\"log1\">", m.g(5), b"</span>", m.g(7), b"<strong>|</strong>",
        m.g(8), b"<span class=\"log1\">", m.g(9), b"</span>", m.g(11), b"<strong>|</strong>",
        m.g(12), b"<span class=\"log1\">", m.g(13), b"</span>", m.g(14), b"<strong>|</strong>",
        m.g(15), b"<span class=\"log1\">", m.g(16), b"</span>", m.g(17), b"\n",
    ])
}

fn ar_xld(m: &M) -> Vec<u8> {
    // PHP's `strpos(...) != -1` is always true, so the badish branch is unreachable.
    let conf = &m.g(6)[..m.g(6).len().saturating_sub(1)];
    let class: &[u8] = if intval(conf) < 2 { b"goodish" } else { b"good" };
    cat(&[
        b"<span class=\"log4\">AccurateRip signature", m.g(1), b": <span class=\"", class, b"\">", m.g(2), b"</span></span>\n",
        m.g(3), b"<span class=\"", class, b"\">", m.g(4), m.g(5), m.g(6), b"</span>",
    ])
}

fn ar_summary_conf_xld(m: &M) -> Vec<u8> {
    let class: &[u8] = if loose_eq(&lower(php::trim_bytes(m.g(2))), b"ok") {
        if cmp_str_num(m.g(3), Num::Int(2)).is_lt() { b"goodish" } else { b"good" }
    } else {
        b"badish"
    };
    cat(&[m.g(1), b"<span class =\"", class, b"\">", &m.g(0)[m.g(1).len()..], b"</span>"])
}

fn ar_summary_conf(m: &M) -> Vec<u8> {
    let class: &[u8] = if cmp_str_num(m.g(3), Num::Int(2)).is_lt() { b"goodish" } else { b"good" };
    cat(&[b"<span class =\"", class, b"\">", m.g(0), b"</span>"])
}

fn xld_all_stat(m: &M) -> Vec<u8> {
    let text = cat(&[m.g(1), m.g(2)]);
    let name = lower(m.g(1));
    let zero = cmp_str_num(m.g(3), Num::Int(0)).is_eq();
    let class: &[u8] = match name.as_slice() {
        b"read error" | b"skipped (treated as error)" | b"inconsistency in error sectors" | b"damaged sector count" => {
            if zero { b"good" } else { b"bad" }
        }
        _ if XLD_SOFT_STATS.contains(&name.as_slice()) => {
            if zero { b"goodish" } else { b"badish" }
        }
        _ => return vec![],
    };
    cat(&[b"<span class=\"log4\">", &text, b"</span> <span class=\"", class, b"\">", m.g(3), b"</span>"])
}
