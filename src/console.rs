//! Symfony Console's OutputFormatter, as far as the PHP commands use it: `<fg=..;options=..>`
//! style tags become ANSI codes when decorated and vanish when not; unknown tags stay literal.

use regex::bytes::Regex;
use std::sync::LazyLock;

#[derive(Clone, PartialEq, Default)]
struct Style {
    set: Vec<u8>,
    unset: Vec<u8>,
}

impl Style {
    fn apply(&self, text: &[u8]) -> Vec<u8> {
        if self.set.is_empty() {
            return text.to_vec();
        }
        [b"\x1b[", &self.set[..], b"m", text, b"\x1b[", &self.unset, b"m"].concat()
    }
}

fn color(name: &str, bg: bool) -> Option<(String, String)> {
    let base = if bg { 40 } else { 30 };
    let n = match name {
        "black" => 0,
        "red" => 1,
        "green" => 2,
        "yellow" => 3,
        "blue" => 4,
        "magenta" => 5,
        "cyan" => 6,
        "white" => 7,
        "default" => 9,
        "gray" => return Some(((if bg { 100 } else { 90 }).to_string(), (base + 9).to_string())),
        _ => {
            let bright = name.strip_prefix("bright-")?;
            let (set, _) = color(bright, bg)?;
            let n: u32 = set.parse().ok()?;
            return Some(((n + 60).to_string(), (base + 9).to_string()));
        }
    };
    Some(((base + n).to_string(), (base + 9).to_string()))
}

/// createStyleFromString; None means the tag is printed literally.
fn style_from_string(tag: &str) -> Option<Style> {
    let named = match tag {
        "error" => Some("fg=white;bg=red"),
        "info" => Some("fg=green"),
        "comment" => Some("fg=yellow"),
        "question" => Some("fg=black;bg=cyan"),
        _ => None,
    };
    let tag = named.unwrap_or(tag);
    static PAIR: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"([^=]+)=([^;]+)(;|$)").unwrap());
    let (mut fg, mut bg, mut opts) = (None, None, Vec::new());
    let mut any = false;
    for c in PAIR.captures_iter(tag) {
        any = true;
        let key = c[1].to_lowercase();
        let val = c[2].to_lowercase();
        match key.as_str() {
            "fg" => fg = Some(color(&val, false)?),
            "bg" => bg = Some(color(&val, true)?),
            "href" => {}
            "options" => {
                for o in val.split([',', ';']).filter(|o| !o.is_empty()) {
                    let codes = match o {
                        "bold" => ("1", "22"),
                        "underscore" => ("4", "24"),
                        "blink" => ("5", "25"),
                        "reverse" => ("7", "27"),
                        "conceal" => ("8", "28"),
                        _ => return None,
                    };
                    if !opts.contains(&codes) {
                        opts.push(codes);
                    }
                }
            }
            _ => return None,
        }
    }
    if !any {
        return None;
    }
    let mut set = vec![];
    let mut unset = vec![];
    for (s, u) in fg.iter().chain(bg.iter()) {
        set.push(s.clone());
        unset.push(u.clone());
    }
    for (s, u) in opts {
        set.push(s.to_string());
        unset.push(u.to_string());
    }
    Some(Style { set: set.join(";").into_bytes(), unset: unset.join(";").into_bytes() })
}

/// OutputFormatter::format.
pub fn format(message: &[u8], decorated: bool) -> Vec<u8> {
    static TAG: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i-u)<(([a-z](?:[^\\<>]+|\\.)*)|/([a-z][^<>]*)?)>").unwrap()
    });
    let mut stack: Vec<Style> = vec![];
    let mut out = Vec::new();
    let mut offset = 0;
    let apply = |stack: &[Style], text: &[u8]| -> Vec<u8> {
        match (decorated, stack.last()) {
            (true, Some(s)) => s.apply(text),
            _ => text.to_vec(),
        }
    };
    for c in TAG.captures_iter(message) {
        let m = c.get(0).unwrap();
        if m.start() != 0 && message[m.start() - 1] == b'\\' {
            continue;
        }
        out.extend(apply(&stack, &message[offset..m.start()]));
        offset = m.end();
        let open = m.as_bytes()[1] != b'/';
        let tag = if open { c.get(2) } else { c.get(3) }.map_or(&b""[..], |g| g.as_bytes());
        if !open && tag.is_empty() {
            stack.pop();
            continue;
        }
        match style_from_string(&String::from_utf8_lossy(tag)) {
            None => out.extend(apply(&stack, m.as_bytes())),
            Some(style) if open => stack.push(style),
            Some(style) => {
                // Pop back to the matching style; Symfony throws on a mismatch, we just pop.
                if let Some(i) = stack.iter().rposition(|s| *s == style) {
                    stack.truncate(i);
                }
            }
        }
    }
    out.extend(apply(&stack, &message[offset..]));
    // strtr($output, ["\0" => '\\', '\\<' => '<', '\\>' => '>']), a single pass.
    let mut result = Vec::with_capacity(out.len());
    let mut i = 0;
    while i < out.len() {
        match (out[i], out.get(i + 1)) {
            (0, _) => result.push(b'\\'),
            (b'\\', Some(&c @ (b'<' | b'>'))) => {
                result.push(c);
                i += 1;
            }
            (b, _) => result.push(b),
        }
        i += 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_known_tags_keeps_unknown() {
        let s = b"<fg=green;options=bold>ok</> <span class =\"good\">x</span> a\\<b";
        assert_eq!(format(s, false), b"ok <span class =\"good\">x</span> a<b".to_vec());
        assert_eq!(format(b"<fg=red>x</>", true), b"\x1b[31mx\x1b[39m".to_vec());
    }
}
