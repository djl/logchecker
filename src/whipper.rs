//! Port of Logchecker::whipperParse. Symfony Yaml is replaced by yaml-rust2, with its values
//! mapped onto the PHP types the PHP code sees.

use crate::checksum::{self, CHECKSUM_MISSING, CHECKSUM_OK};
use crate::logchecker::{Logchecker, OFFSET_ZERO_MSG, re, rep_cb};
use crate::php::{self, Num, cmp_str_num, loose_eq, version_compare};
use crate::ripper::Ripper;
use yaml_rust2::parser::Parser;
use yaml_rust2::{Event, Yaml, YamlLoader};

/// A PHP value as Symfony Yaml::parse would produce it.
#[derive(Debug, Clone, PartialEq)]
enum V {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Vec<u8>),
    Map(Vec<(Vec<u8>, V)>),
}

impl V {
    fn from_yaml(y: &Yaml) -> V {
        match y {
            Yaml::Real(s) => s.parse().map_or_else(|_| V::Str(s.clone().into_bytes()), V::Float),
            Yaml::Integer(i) => V::Int(*i),
            Yaml::String(s) => V::Str(s.clone().into_bytes()),
            Yaml::Boolean(b) => V::Bool(*b),
            Yaml::Array(a) => {
                V::Map(a.iter().enumerate().map(|(i, v)| (i.to_string().into_bytes(), V::from_yaml(v))).collect())
            }
            Yaml::Hash(h) => V::Map(h.iter().map(|(k, v)| (V::from_yaml(k).interp(), V::from_yaml(v))).collect()),
            _ => V::Null,
        }
    }

    /// PHP "{$value}" interpolation.
    fn interp(&self) -> Vec<u8> {
        match self {
            V::Null | V::Bool(false) => vec![],
            V::Bool(true) => b"1".to_vec(),
            V::Int(i) => i.to_string().into_bytes(),
            V::Float(f) => php::float_to_string(*f).into_bytes(),
            V::Str(s) => s.clone(),
            V::Map(_) => b"Array".to_vec(),
        }
    }

    fn get(&self, k: &str) -> &V {
        match self {
            V::Map(m) => m.iter().find(|(kk, _)| kk == k.as_bytes()).map_or(&V::Null, |(_, v)| v),
            _ => &V::Null,
        }
    }

    /// `$a[$k] = $v`: overwrite in place or append; a null/scalar becomes an array (PHP autovivification).
    fn set(&mut self, k: &str, v: V) {
        if !matches!(self, V::Map(_)) {
            *self = V::Map(vec![]);
        }
        let V::Map(m) = self else { unreachable!() };
        match m.iter_mut().find(|(kk, _)| kk == k.as_bytes()) {
            Some(slot) => slot.1 = v,
            None => m.push((k.as_bytes().to_vec(), v)),
        }
    }

    /// `&mut $a[$k]`, creating the key (and the array) as PHP does on write.
    fn get_mut(&mut self, k: &str) -> &mut V {
        if !matches!(self, V::Map(_)) {
            *self = V::Map(vec![]);
        }
        let V::Map(m) = self else { unreachable!() };
        let i = match m.iter().position(|(kk, _)| kk == k.as_bytes()) {
            Some(i) => i,
            None => {
                m.push((k.as_bytes().to_vec(), V::Null));
                m.len() - 1
            }
        };
        &mut m[i].1
    }

    fn isset(&self, k: &str) -> bool {
        !matches!(self.get(k), V::Null)
    }

    /// PHP empty().
    fn empty(&self) -> bool {
        match self {
            V::Null | V::Bool(false) | V::Int(0) => true,
            V::Float(f) => *f == 0.0,
            V::Str(s) => s.is_empty() || s == b"0",
            V::Map(m) => m.is_empty(),
            _ => false,
        }
    }

    fn entries(&self) -> Vec<(Vec<u8>, V)> {
        match self {
            V::Map(m) => m.clone(),
            _ => vec![],
        }
    }

    fn is_str(&self, s: &str) -> bool {
        matches!(self, V::Str(v) if v == s.as_bytes())
    }
}

fn span(class: &str, v: &[u8]) -> V {
    V::Str([format!("<span class='{class}'>").as_bytes(), v, b"</span>"].concat())
}

/// YAML double-quoted scalar that parses back to exactly `s`. Stands in for Symfony's
/// Yaml::dump, whose output Yaml::parse reads back as the same string.
fn yaml_quote(s: &[u8]) -> Vec<u8> {
    let mut out = vec![b'"'];
    for &b in s {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0..=0x1F | 0x7F => out.extend_from_slice(format!("\\x{b:02X}").as_bytes()),
            _ => out.push(b),
        }
    }
    out.push(b'"');
    out
}

/// Seconds since the epoch for a YAML timestamp (what Symfony returns for unquoted dates).
fn timestamp(s: &str) -> Option<i64> {
    let re = re!(r"^(\d{4})-(\d{1,2})-(\d{1,2})(?:(?:[Tt]|[ \t]+)(\d{1,2}):(\d{2}):(\d{2})(?:\.\d*)?[ \t]*(Z|[-+]\d{1,2}(?::?\d{2})?)?)?$");
    let c = re.captures(s.as_bytes())?;
    let n = |i: usize| c.get(i).map_or(0, |m| std::str::from_utf8(m.as_bytes()).unwrap().parse::<i64>().unwrap());
    let (y, mo, d) = (n(1), n(2), n(3));
    // Days from civil (Howard Hinnant).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * ((mo + 9) % 12) + 2) / 5 + d - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    let mut t = days * 86400 + n(4) * 3600 + n(5) * 60 + n(6);
    if let Some(tz) = c.get(7).map(|m| m.as_bytes()).filter(|z| *z != b"Z") {
        let sign = if tz[0] == b'-' { -1 } else { 1 };
        let digits: Vec<u8> = tz[1..].iter().filter(|b| b.is_ascii_digit()).copied().collect();
        let (h, m) = if digits.len() <= 2 { (&digits[..], &b""[..]) } else { digits.split_at(digits.len() - 2) };
        let p = |x: &[u8]| std::str::from_utf8(x).unwrap().parse::<i64>().unwrap_or(0);
        t -= sign * (p(h) * 3600 + p(m) * 60);
    }
    Some(t)
}

/// gmdate("Y-m-d\TH:i:s\Z", $t)
fn gmdate(t: i64) -> String {
    let (days, secs) = (t.div_euclid(86400), t.rem_euclid(86400));
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

pub(crate) fn parse(lc: &mut Logchecker) {
    let raw = lc.raw_log().to_vec();
    if let Some(c) = re!(r"whipper ([0-9]+\.[0-9]+\.[0-9])").captures(&raw)
        && version_compare("0.7.3", &String::from_utf8_lossy(&c[1])) == 1 {
            lc.account(b"Logs must be produced by whipper 0.7.3+.", 100, None, false, false);
            return;
        }
    // Whipper 0.7.x can write invalid YAML (unescaped values), so quote these.
    let (log, _) = rep_cb(re!(r"  (Release|Album): (.+)"), &raw, 0, |m| {
        [b"  ", m.g(1), b": ", &yaml_quote(m.g(2))].concat()
    });
    // Symfony would parse CRCs that start with 0 as octals.
    let (log, _) = rep_cb(re!(r"CRC: ([A-Z0-9]+)"), &log, 0, |m| [b"CRC: \"", m.g(1), b"\""].concat());

    let parsed = std::str::from_utf8(&log).ok().filter(|s| !has_alias(s)).and_then(|s| YamlLoader::load_from_str(s).ok());
    let mut y = match parsed.as_deref() {
        Some([doc, ..]) if matches!(doc, Yaml::Hash(_)) => V::from_yaml(doc),
        _ => {
            lc.account(b"Could not parse whipper log.", 100, None, false, false);
            return;
        }
    };

    let created_by = y.get("Log created by").interp();
    let version = created_by.split(|&b| b == b' ').nth(1).map(<[u8]>::to_vec);
    lc.set_ripper_version(version.clone());
    // Releases before 0.7.3 used octal track numbers, which merge tracks 08 and 09.
    let version = version.unwrap_or_default();
    if V::Str(version.clone()).empty() || version_compare("0.7.3", &String::from_utf8_lossy(&version)) == 1 {
        lc.account(b"Logs must be produced by whipper 0.7.3+", 100, None, false, false);
        return;
    }

    if let V::Str(s) = y.get("Log created by") {
        let s = re!(r"^(whipper) ([^\s]+)")
            .replace(s, &b"<span class='good'>${1}</span> <span class='log1'>${2}</span>"[..])
            .into_owned();
        y.set("Log created by", V::Str(s));
    }

    if y.get("SHA-256 hash").empty() {
        lc.set_checksum_state(CHECKSUM_MISSING);
    } else {
        let state = checksum::validate(lc.file(), Ripper::Whipper).unwrap_or(CHECKSUM_MISSING);
        lc.set_checksum_state(state);
        let class = if state == CHECKSUM_OK { "good" } else { "bad" };
        let v = span(class, &y.get("SHA-256 hash").interp());
        y.set("SHA-256 hash", v);
    }

    let key = "Ripping phase information";
    let drive = y.get(key).get("Drive").clone();
    let offset = y.get(key).get("Read offset correction").clone();
    let drive_s = drive.interp();
    if crate::logchecker::FAKE_DRIVES.iter().any(|d| loose_eq(d, php::trim_bytes(&drive_s))) {
        lc.account(&[b"Virtual drive used: ", &drive_s[..]].concat(), 20, None, false, false);
        y.get_mut(key).set("Drive", span("bad", &drive_s));
    } else {
        lc.get_drives(&drive_s);
        let mut drive_s = drive_s;
        let (drive_class, offset_class);
        let offset_s = offset.interp();
        if !lc.drives().is_empty() {
            drive_class = "good";
            if lc.offsets().iter().any(|o| loose_eq(&offset_s, o.as_bytes())) {
                offset_class = "good";
            } else {
                offset_class = "bad";
                let msg = format!(
                    "Incorrect read offset for drive. Correct offsets are: {} (Checked against the following drive(s): {})",
                    lc.offsets().join(", "),
                    lc.drives().join(", ")
                );
                lc.account(msg.as_bytes(), 5, None, false, false);
            }
        } else {
            drive_class = "badish";
            drive_s.extend_from_slice(b" (not found in database)");
            if offset.is_str("0") {
                offset_class = "bad";
                lc.account(OFFSET_ZERO_MSG, 5, None, false, false);
            } else {
                offset_class = "badish";
            }
        }
        y.get_mut(key).set("Drive", span(drive_class, &drive_s));
        let positive = match &offset {
            V::Int(i) => *i > 0,
            V::Float(f) => *f > 0.0,
            V::Bool(b) => *b,
            V::Str(s) => cmp_str_num(s, Num::Int(0)).is_gt(),
            _ => false,
        };
        let offset_s = if positive { [b"+", &offset_s[..]].concat() } else { offset_s };
        y.get_mut(key).set("Read offset correction", span(offset_class, &offset_s));
    }

    let defeat = y.get(key).get("Defeat audio cache").clone();
    let (value, class) = match &defeat {
        V::Str(s) if s.eq_ignore_ascii_case(b"yes") => ("Yes", "good"),
        V::Str(_) => ("No", "bad"),
        V::Bool(true) => ("true", "good"),
        _ => ("false", "bad"),
    };
    if class == "bad" {
        lc.account(b"\"Defeat audio cache\" should be Yes/true", 10, None, false, false);
    }
    y.get_mut(key).set("Defeat audio cache", span(class, value.as_bytes()));
    let overread = match y.get(key).get("Overread into lead-out") {
        V::Bool(b) => V::Str(if *b { b"true".to_vec() } else { b"false".to_vec() }),
        v => v.clone(),
    };
    y.get_mut(key).set("Overread into lead-out", span("log4", &overread.interp()));

    // CD Metadata
    let key = "CD metadata";
    let release_key = if y.get(key).isset("Release") { "Release" } else { "Album" };
    if let V::Str(s) = y.get(key).get(release_key).clone() {
        y.get_mut(key).set(release_key, span("log4", &s));
    } else {
        for k in ["Artist", "Title"] {
            let v = span("log4", &y.get(key).get(release_key).get(k).interp());
            y.get_mut(key).get_mut(release_key).set(k, v);
        }
    }

    // TOC
    // Walk the maps in place: looking each entry up by key is quadratic in the track count.
    if let V::Map(toc) = y.get_mut("TOC") {
        for (_, t) in toc {
            for f in ["Start", "Length", "Start sector", "End sector"] {
                let v = span("log1", &t.get(f).interp());
                t.set(f, v);
            }
        }
    }

    // Tracks
    let tracks = match y.get_mut("Tracks") {
        V::Map(m) => &mut m[..],
        _ => &mut [],
    };
    for (_, t) in tracks {
        let peak = match t.get("Peak level") {
            V::Int(i) => *i as f64,
            V::Float(f) => *f,
            V::Bool(b) => f64::from(u8::from(*b)),
            V::Str(s) => match php::numeric(s) {
                Some(Num::Int(i)) => i as f64,
                Some(Num::Float(f)) => f,
                None => 0.0,
            },
            _ => 0.0,
        };
        t.set("Peak level", V::Str(format!("{peak:.6}").into_bytes()));
        let (test, copy) = (t.get("Test CRC").clone(), t.get("Copy CRC").clone());
        let class = if test != copy {
            lc.account(&[b"CRC mismatch: ", &test.interp()[..], b" and ", &copy.interp()].concat(), 30, None, false, false);
            "bad"
        } else {
            "good"
        };
        t.set("Test CRC", span(class, &test.interp()));
        t.set("Copy CRC", span(class, &copy.interp()));
        let class = if t.get("Status").is_str("Copy OK") { "good" } else { "bad" };
        let v = span(class, &t.get("Status").interp());
        t.set("Status", v);
        for f in ["Filename", "Pre-gap length", "Peak level", "Extraction speed", "Extraction quality"] {
            if t.isset(f) {
                let v = span("log3", &t.get(f).interp());
                t.set(f, v);
            }
        }
        for ar in ["AccurateRip v1", "AccurateRip v2"] {
            if !t.isset(ar) {
                continue;
            }
            let a = t.get_mut(ar);
            let class = if a.get("Result").is_str("Found, exact match") { "good" } else { "badish" };
            let v = span(class, &a.get("Result").interp());
            a.set("Result", v);
            if a.isset("Local CRC") && a.isset("Remote CRC") {
                let class = if a.get("Local CRC") == a.get("Remote CRC") { "goodish" } else { "badish" };
                let (l, r) = (span(class, &a.get("Local CRC").interp()), span(class, &a.get("Remote CRC").interp()));
                a.set("Local CRC", l);
                a.set("Remote CRC", r);
            }
        }
    }

    // Conclusive status report
    let key = "Conclusive status report";
    let s = y.get_mut(key);
    let class = if s.get("AccurateRip summary").is_str("All tracks accurately ripped") { "good" } else { "badish" };
    let v = span(class, &s.get("AccurateRip summary").interp());
    s.set("AccurateRip summary", v);
    let health = if s.isset("Health Status") { "Health Status" } else { "Health status" };
    let class = if s.get(health).is_str("No errors occurred") { "good" } else { "bad" };
    let v = span(class, &s.get(health).interp());
    s.set(health, v);

    let created = match y.get("Log creation date") {
        V::Int(i) => *i,
        V::Str(s) => timestamp(&String::from_utf8_lossy(s)).unwrap_or(0),
        _ => 0,
    };

    let mut out = Vec::new();
    let w = |out: &mut Vec<u8>, parts: &[&[u8]]| parts.iter().for_each(|p| out.extend_from_slice(p));
    let tf = |v: &V, yes: &str, no: &str| match v {
        V::Bool(b) => (if *b { yes } else { no }).as_bytes().to_vec(),
        v => v.interp(),
    };
    w(&mut out, &[b"Log created by: ", &y.get("Log created by").interp(), b"\nLog creation date: ", gmdate(created).as_bytes(), b"\n\n"]);
    out.extend_from_slice(b"Ripping phase information:\n");
    for (k, v) in y.get("Ripping phase information").entries() {
        w(&mut out, &[b"  ", &k, b": ", &tf(&v, "true", "false"), b"\n"]);
    }
    out.extend_from_slice(b"\nCD metadata:\n");
    for (k, v) in y.get("CD metadata").entries() {
        if let V::Map(m) = &v {
            w(&mut out, &[b"  ", &k, b":\n"]);
            for (kk, vv) in m {
                w(&mut out, &[b"    ", kk, b": ", &vv.interp(), b"\n"]);
            }
        } else {
            w(&mut out, &[b"  ", &k, b": ", &tf(&v, "true", "false"), b"\n"]);
        }
    }
    out.extend_from_slice(b"\nTOC:\n");
    for (k, t) in y.get("TOC").entries() {
        w(&mut out, &[b"  ", &k, b":\n"]);
        for (kk, v) in t.entries() {
            w(&mut out, &[b"    ", &kk, b": ", &v.interp(), b"\n"]);
        }
        out.push(b'\n');
    }
    out.extend_from_slice(b"Tracks:\n");
    for (k, t) in y.get("Tracks").entries() {
        w(&mut out, &[b"  ", &k, b":\n"]);
        for (kk, v) in t.entries() {
            if let V::Map(m) = &v {
                w(&mut out, &[b"    ", &kk, b":\n"]);
                for (kkk, vv) in m {
                    w(&mut out, &[b"      ", kkk, b": ", &vv.interp(), b"\n"]);
                }
            } else {
                w(&mut out, &[b"    ", &kk, b": ", &tf(&v, "Yes", "No"), b"\n"]);
            }
        }
        out.push(b'\n');
    }
    out.extend_from_slice(b"Conclusive status report:\n");
    for (k, v) in y.get("Conclusive status report").entries() {
        w(&mut out, &[b"  ", &k, b": ", &v.interp(), b"\n"]);
    }
    out.push(b'\n');
    if y.isset("SHA-256 hash") {
        w(&mut out, &[b"SHA-256 hash: ", &y.get("SHA-256 hash").interp(), b"\n"]);
    }
    lc.set_log(out);
}

/// Whipper never writes YAML aliases, and the loader copies each one, so nested aliases
/// (a "billion laughs" log) would use unbounded memory.
fn has_alias(s: &str) -> bool {
    let mut parser = Parser::new_from_str(s);
    loop {
        match parser.next_token() {
            Ok((Event::Alias(_), _)) => return true,
            Ok((Event::StreamEnd, _)) | Err(_) => return false,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip() {
        let t = timestamp("2018-11-23T15:19:21Z").unwrap();
        assert_eq!(t, 1542986361);
        assert_eq!(gmdate(t), "2018-11-23T15:19:21Z");
        assert_eq!(gmdate(timestamp("2018-11-23T17:19:21+02:00").unwrap()), "2018-11-23T15:19:21Z");
    }

    #[test]
    fn quoted_yaml_reads_back() {
        let s = br#"a: "b" \ # c: d"#;
        let doc = format!("k: {}", String::from_utf8(yaml_quote(s)).unwrap());
        let y = &YamlLoader::load_from_str(&doc).unwrap()[0];
        assert_eq!(y["k"].as_str().unwrap().as_bytes(), s);
    }
}
