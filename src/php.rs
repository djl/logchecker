//! The few PHP built-ins whose exact behaviour the output depends on.

const TRIM: [char; 6] = [' ', '\t', '\n', '\r', '\0', '\x0B'];

/// PHP `trim()` with its default character set.
pub fn trim(s: &str) -> &str {
    s.trim_matches(TRIM)
}

pub fn trim_bytes(s: &[u8]) -> &[u8] {
    let keep = |b: &u8| !TRIM.contains(&(*b as char));
    let start = s.iter().position(keep).unwrap_or(s.len());
    let end = s.iter().rposition(keep).map_or(start, |p| p + 1);
    &s[start..end]
}

/// PHP `json_encode($v, JSON_PRETTY_PRINT)`: 4-space indent, `\/`, `\uXXXX` for non-ASCII.
pub fn json_encode_pretty(v: &serde_json::Value) -> String {
    let mut out = String::new();
    write_json(v, 0, &mut out);
    out
}

fn write_json(v: &serde_json::Value, depth: usize, out: &mut String) {
    use serde_json::Value;
    let pad = |d: usize| "    ".repeat(d);
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_json_string(s, out),
        Value::Array(a) if a.is_empty() => out.push_str("[]"),
        Value::Object(o) if o.is_empty() => out.push_str("{}"),
        Value::Array(a) => {
            out.push_str("[\n");
            for (i, item) in a.iter().enumerate() {
                out.push_str(&pad(depth + 1));
                write_json(item, depth + 1, out);
                out.push_str(if i + 1 < a.len() { ",\n" } else { "\n" });
            }
            out.push_str(&pad(depth));
            out.push(']');
        }
        Value::Object(o) => {
            out.push_str("{\n");
            for (i, (k, item)) in o.iter().enumerate() {
                out.push_str(&pad(depth + 1));
                write_json_string(k, out);
                out.push_str(": ");
                write_json(item, depth + 1, out);
                out.push_str(if i + 1 < o.len() { ",\n" } else { "\n" });
            }
            out.push_str(&pad(depth));
            out.push('}');
        }
    }
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' => out.push_str("\\/"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || !c.is_ascii() => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A PHP scalar as far as the loose comparisons in Logchecker need.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Num {
    Int(i64),
    Float(f64),
}

impl Num {
    fn f(self) -> f64 {
        match self {
            Num::Int(i) => i as f64,
            Num::Float(f) => f,
        }
    }
}

/// PHP 8 numeric string (is_numeric): optional surrounding whitespace, sign, digits, '.', exponent.
pub fn numeric(s: &[u8]) -> Option<Num> {
    let ws = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0B' | b'\x0C');
    let start = s.iter().position(|b| !ws(b))?;
    let end = s.iter().rposition(|b| !ws(b)).unwrap() + 1;
    let t = std::str::from_utf8(&s[start..end]).ok()?;
    let b = t.as_bytes();
    let mut i = usize::from(matches!(b.first(), Some(b'+' | b'-')));
    let int_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    let mut digits = i - int_start;
    let mut is_int = true;
    if i < b.len() && b[i] == b'.' {
        is_int = false;
        i += 1;
        let frac = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        digits += i - frac;
    }
    if digits == 0 {
        return None;
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        let mut j = i + 1;
        if matches!(b.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        let exp = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == exp {
            return None;
        }
        is_int = false;
        i = j;
    }
    if i != b.len() {
        return None;
    }
    if is_int
        && let Ok(v) = t.parse::<i64>() {
            return Some(Num::Int(v));
        }
    t.parse::<f64>().ok().map(Num::Float)
}

fn cmp_num(a: Num, b: Num) -> std::cmp::Ordering {
    match (a, b) {
        (Num::Int(x), Num::Int(y)) => x.cmp(&y),
        _ => a.f().partial_cmp(&b.f()).unwrap_or(std::cmp::Ordering::Less),
    }
}

/// PHP 8 `$string <=> $number`.
pub fn cmp_str_num(s: &[u8], n: Num) -> std::cmp::Ordering {
    match numeric(s) {
        Some(v) => cmp_num(v, n),
        None => {
            let ns = match n {
                Num::Int(i) => i.to_string(),
                Num::Float(f) => float_to_string(f),
            };
            s.cmp(ns.as_bytes())
        }
    }
}

/// PHP 8 `$a == $b` for two strings: numerically if both are numeric.
pub fn loose_eq(a: &[u8], b: &[u8]) -> bool {
    match (numeric(a), numeric(b)) {
        (Some(x), Some(y)) => cmp_num(x, y).is_eq(),
        _ => a == b,
    }
}

/// PHP's float to string conversion (precision = -1, i.e. shortest round-trip).
pub fn float_to_string(f: f64) -> String {
    if f.is_nan() {
        return "NAN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "INF".into() } else { "-INF".into() };
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0".into() } else { "0".into() };
    }
    // Like printf %.17G with shortest digits: scientific when exponent < -4 or >= 15.
    let sci = format!("{f:e}");
    let (mantissa, exp) = sci.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    if !(-4..15).contains(&exp) {
        let mantissa = if mantissa.contains('.') { mantissa.to_string() } else { format!("{mantissa}.0") };
        format!("{mantissa}E{}{}", if exp < 0 { "-" } else { "+" }, exp.abs())
    } else {
        format!("{f}")
    }
}

/// PHP `version_compare($a, $b)`: -1, 0 or 1.
pub fn version_compare(a: &str, b: &str) -> i32 {
    if a.is_empty() || b.is_empty() {
        return match (a.is_empty(), b.is_empty()) {
            (true, true) => 0,
            (false, _) => 1,
            _ => -1,
        };
    }
    let (ca, cb) = (canonicalize(a), canonicalize(b));
    let mut ta = ca.split('.').filter(|t| !t.is_empty()).peekable();
    let mut tb = cb.split('.').filter(|t| !t.is_empty()).peekable();
    let digit = |t: &str| t.as_bytes()[0].is_ascii_digit();
    let mut compare = 0;
    while let (Some(&p1), Some(&p2)) = (ta.peek(), tb.peek()) {
        compare = match (digit(p1), digit(p2)) {
            (true, true) => {
                let (l1, l2) = (strtol(p1), strtol(p2));
                (l1 > l2) as i32 - (l1 < l2) as i32
            }
            (false, false) => special_form(p1, p2),
            (true, false) => special_form("#N#", p2),
            (false, true) => special_form(p1, "#N#"),
        };
        ta.next();
        tb.next();
        if compare != 0 {
            return compare;
        }
    }
    // One side has tokens left: PHP recurses on the rest of that string.
    let rest = |it: &mut dyn Iterator<Item = &str>| it.collect::<Vec<_>>().join(".");
    if let Some(&p1) = ta.peek() {
        compare = if digit(p1) { 1 } else { version_compare(&rest(&mut ta), "#N#") };
    } else if let Some(&p2) = tb.peek() {
        compare = if digit(p2) { -1 } else { version_compare("#N#", &rest(&mut tb)) };
    }
    compare
}

fn strtol(t: &str) -> i64 {
    let end = t.bytes().position(|b| !b.is_ascii_digit()).unwrap_or(t.len());
    t[..end].parse().unwrap_or(i64::MAX)
}

fn canonicalize(v: &str) -> String {
    let b = v.as_bytes();
    let mut q = vec![b[0]];
    let isdig = |x: u8| x.is_ascii_digit();
    let isndig = |x: u8| !x.is_ascii_digit() && x != b'.';
    let mut lp = b[0];
    for &c in &b[1..] {
        let last = *q.last().unwrap();
        if matches!(c, b'-' | b'_' | b'+') {
            if last != b'.' {
                q.push(b'.');
            }
        } else if (isndig(lp) && isdig(c)) || (isdig(lp) && isndig(c)) {
            if last != b'.' {
                q.push(b'.');
            }
            q.push(c);
        } else if !c.is_ascii_alphanumeric() {
            if last != b'.' {
                q.push(b'.');
            }
        } else {
            q.push(c);
        }
        lp = c;
    }
    String::from_utf8_lossy(&q).into_owned()
}

fn special_form(a: &str, b: &str) -> i32 {
    const FORMS: [(&str, i32); 10] =
        [("dev", 0), ("alpha", 1), ("a", 1), ("beta", 2), ("b", 2), ("RC", 3), ("rc", 3), ("#", 4), ("pl", 5), ("p", 5)];
    let order = |f: &str| FORMS.iter().find(|(name, _)| f.starts_with(name)).map_or(-1, |&(_, o)| o);
    (order(a) - order(b)).signum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_matches_php() {
        let v = serde_json::json!({"a": [1, "é/😀"], "b": [], "c": {}});
        assert_eq!(
            json_encode_pretty(&v),
            "{\n    \"a\": [\n        1,\n        \"\\u00e9\\/\\ud83d\\ude00\"\n    ],\n    \"b\": [],\n    \"c\": {}\n}"
        );
    }

    #[test]
    fn trims_like_php() {
        assert_eq!(trim("\x0B\0 a \u{3000}\n"), "a \u{3000}");
        assert_eq!(trim_bytes(b" \t\n"), b"");
        assert_eq!(trim_bytes(b" x y\r"), b"x y");
    }

    #[test]
    fn version_compare_like_php() {
        assert_eq!(version_compare("0.99", "1.0"), -1);
        assert_eq!(version_compare("1.0", "1.0"), 0);
        assert_eq!(version_compare("1.3", "1.0"), 1);
        assert_eq!(version_compare("0.7.3", "0.7.2"), 1);
        assert_eq!(version_compare("0.7.3", "0.9.0"), -1);
        assert_eq!(version_compare("1.0b3", "1.0"), -1);
        assert_eq!(version_compare("1.0", "1.0.1"), -1);
        assert_eq!(version_compare("1.0pl1", "1.0"), 1);
        assert_eq!(version_compare("20121222", "20121027"), 1);
    }

    #[test]
    fn loose_comparisons_like_php() {
        assert!(loose_eq(b"+6", b"6"));
        assert!(loose_eq(b"1E5", b"100000"));
        assert!(!loose_eq(b"abc", b"ABC"));
        assert!(cmp_str_num(b"0.95", Num::Float(0.95)).is_le());
        assert!(cmp_str_num(b"0.95 prebeta 11", Num::Float(0.95)).is_gt());
        assert!(cmp_str_num(b"3", Num::Int(10)).is_lt());
        assert_eq!(numeric(b" 12 "), Some(Num::Int(12)));
        assert_eq!(numeric(b"12abc"), None);
        assert_eq!(numeric(b"."), None);
        assert_eq!(float_to_string(0.873), "0.873");
        assert_eq!(float_to_string(1.0), "1");
        assert_eq!(float_to_string(1e20), "1.0E+20");
    }
}
