//! Port of Util::decodeEncoding and Chardet.php. PHP shells out to `cchardetect`; we use a
//! pure-Rust port of uchardet (from cchardet 2.2.0a2) and tables generated from glibc iconv.

/// What `cchardetect FILE` reports, as Chardet::analyze parses it: lower-cased charset
/// (`none` when undetected, with confidence 0).
pub fn analyze(data: &[u8]) -> (String, f64) {
    let mut ud = crate::uchardet::UniversalDetector::new();
    // cchardetect feeds the file in 256 KiB chunks.
    for chunk in data.chunks(256 * 1024) {
        ud.handle_data(chunk);
    }
    let (charset, confidence) = ud.data_end();
    if charset.is_empty() { ("none".into(), 0.0) } else { (charset.to_ascii_lowercase(), confidence as f64) }
}

/// Util::decodeEncoding. Err is PHP's RuntimeException ("could not detect log encoding").
pub fn decode_encoding(log: &[u8]) -> Result<Vec<u8>, ()> {
    // Whipper uses UTF-8, and chardet may misdetect it.
    if crate::logchecker::contains(log, b"Log created by: whipper") {
        return Ok(log.to_vec());
    }
    let at = |i: usize| log.get(i).copied().unwrap_or(0);
    if (at(0), at(1)) == (0xFF, 0xFE) {
        return Ok(utf16_lossy(&log[2..], u16::from_le_bytes));
    }
    if (at(0), at(1)) == (0xFE, 0xFF) {
        return Ok(utf16_lossy(&log[2..], u16::from_be_bytes));
    }
    if (at(0), at(1), at(2)) == (0xEF, 0xBB, 0xBF) {
        return Ok(log[3..].to_vec());
    }
    let (charset, confidence) = analyze(log);
    if charset == "utf-8" {
        return Ok(log.to_vec());
    }
    if confidence > 0.6 {
        let charset = match charset.as_str() {
            "macroman" => "macintosh",
            "maccentraleurope" => "mac-centraleurope",
            "maccyrillic" => "mac-cyrillic",
            "macis" => "mac-is",
            "macsami" => "mac-sami",
            "macuk" => "mac-uk",
            c => c,
        };
        iconv(charset, log).ok_or(())
    } else if confidence > 0.3 {
        // Poor confidence: PHP falls back to ISO-8859-1.
        Ok(iconv("iso-8859-1", log).unwrap())
    } else {
        Ok(log.to_vec())
    }
}

/// mb_convert_encoding from UTF-16: malformed units become '?'.
fn utf16_lossy(data: &[u8], unit: fn([u8; 2]) -> u16) -> Vec<u8> {
    let units = data.chunks(2).map(|c| if c.len() == 2 { Some(unit([c[0], c[1]])) } else { None });
    let mut out = String::new();
    let mut iter = units.peekable();
    while let Some(u) = iter.next() {
        let Some(u) = u else {
            out.push('?');
            continue;
        };
        match u {
            0xD800..=0xDBFF => match iter.peek() {
                Some(Some(lo @ 0xDC00..=0xDFFF)) => {
                    let c = 0x10000 + ((u as u32 - 0xD800) << 10) + (*lo as u32 - 0xDC00);
                    out.push(char::from_u32(c).unwrap());
                    iter.next();
                }
                _ => out.push('?'),
            },
            0xDC00..=0xDFFF => out.push('?'),
            u => out.push(char::from_u32(u as u32).unwrap()),
        }
    }
    out.into_bytes()
}

/// Strict `iconv($charset, 'UTF-8', $data)`: None where PHP returns false.
fn iconv(charset: &str, data: &[u8]) -> Option<Vec<u8>> {
    if charset == "ascii" {
        return data.is_ascii().then(|| data.to_vec());
    }
    if let Some(table) = crate::codepages::table(charset) {
        let mut out = String::with_capacity(data.len());
        for &b in data {
            match table[b as usize] {
                0 if b != 0 => return None,
                cp => out.push(char::from_u32(cp)?),
            }
        }
        return Some(out.into_bytes());
    }
    // glibc's UTF-16/32 without a BOM default to big-endian.
    let enc = match charset {
        "utf-16" => encoding_rs::UTF_16BE,
        "utf-32" => return utf32be(data),
        // shortcut: encoding_rs differs from glibc on a few unassigned code points in these
        // multibyte sets and lacks euc-tw, hz-gb-2312, iso-2022-cn/kr (PHP converts them; we fail).
        // Upgrade with tables generated from glibc if such logs show up.
        "big5" => encoding_rs::BIG5,
        "euc-jp" => encoding_rs::EUC_JP,
        "euc-kr" | "cp949" | "uhc" => encoding_rs::EUC_KR,
        "gb18030" => encoding_rs::GB18030,
        "gb2312" => encoding_rs::GBK,
        "shift_jis" | "sjis" => encoding_rs::SHIFT_JIS,
        "iso-2022-jp" => encoding_rs::ISO_2022_JP,
        _ => return None,
    };
    enc.decode_without_bom_handling_and_without_replacement(data).map(|s| s.into_owned().into_bytes())
}

fn utf32be(data: &[u8]) -> Option<Vec<u8>> {
    if !data.len().is_multiple_of(4) {
        return None;
    }
    data.as_chunks::<4>().0.iter()
        .map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])))
        .collect::<Option<String>>()
        .map(String::into_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_bad_units_become_question_marks() {
        assert_eq!(utf16_lossy(&[0x41, 0, 0x00, 0xD8, 0x42, 0, 7], u16::from_le_bytes), b"A?B?");
    }

    #[test]
    fn iconv_strict() {
        assert_eq!(iconv("windows-1251", b"\xCF\xF0"), Some("Пр".as_bytes().to_vec()));
        assert_eq!(iconv("windows-1252", b"\x81"), None);
        assert_eq!(iconv("ascii", b"\x80"), None);
    }

    #[test]
    fn analyze_charsets() {
        assert_eq!(analyze(b""), ("none".into(), 0.0));
        assert_eq!(analyze(b"hello"), ("ascii".into(), 1.0));
        assert_eq!(analyze(b"hello\xA0world"), ("iso-8859-1".into(), 1.0));
        assert_eq!(analyze(b"\xEF\xBB\xBFhello"), ("utf-8-sig".into(), 0.99_f32 as f64));
        assert_eq!(analyze(b"\xFE\xFFa"), ("utf-16".into(), 0.99_f32 as f64));
        assert_eq!(analyze(b"\xFF\xFE\x00\x00"), ("utf-32".into(), 0.99_f32 as f64));
        assert_eq!(analyze(b"hello ~{<:Ky2;S{#,~} world"), ("hz-gb-2312".into(), 0.99_f32 as f64));
        assert_eq!(analyze(b"hello \x1b$B$\"$$$&$($*\x1b(B world"), ("iso-2022-jp".into(), 0.99_f32 as f64));
        let heb_l = b" \xF9\xEC\xE5\xED \xE7\xE1\xF8\xE9\xED \xEE\xE4 \xF0\xF9\xEE\xF2 \xE4\xE9\xE5\xED ".repeat(40);
        let heb_v = b" \xED\xE5\xEC\xF9 \xED\xE9\xF8\xE1\xE7 \xE4\xEE \xF2\xEE\xF9\xF0 \xED\xE5\xE9\xE4 ".repeat(40);
        assert_eq!(analyze(&heb_l).0, "windows-1255");
        assert_eq!(analyze(&heb_v).0, "iso-8859-8");
    }

    /// (charset, confidence bits) for every bundled translation in every encoding we decode,
    /// checked against the C++ uchardet the port replaced. Regenerate with UPDATE_GOLDEN=1.
    #[test]
    fn detection_matches_golden() {
        let got: String = golden_corpus()
            .iter()
            .map(|(name, data)| {
                let (cs, conf) = analyze(data);
                format!("{name}\t{cs}\t{:016x}\n", conf.to_bits())
            })
            .collect();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/charset_golden.tsv");
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::write(path, &got).unwrap();
        }
        let want = std::fs::read_to_string(path).unwrap();
        for (g, w) in got.lines().zip(want.lines()) {
            assert_eq!(g, w);
        }
        assert_eq!(got.lines().count(), want.lines().count());
    }

    fn golden_corpus() -> Vec<(String, Vec<u8>)> {
        const SINGLE_BYTE: [&str; 30] = [
            "iso-8859-1", "iso-8859-2", "iso-8859-3", "iso-8859-4", "iso-8859-5", "iso-8859-6", "iso-8859-7",
            "iso-8859-8", "iso-8859-9", "iso-8859-10", "iso-8859-11", "iso-8859-13", "iso-8859-15", "iso-8859-16",
            "windows-1250", "windows-1251", "windows-1252", "windows-1253", "windows-1255", "windows-1256",
            "windows-1257", "windows-1258", "ibm852", "ibm855", "ibm866", "koi8-r", "tis-620", "viscii",
            "mac-centraleurope", "mac-cyrillic",
        ];
        use encoding_rs::{BIG5, EUC_JP, EUC_KR, GB18030, GBK, ISO_2022_JP, SHIFT_JIS};
        const MULTI_BYTE: [&encoding_rs::Encoding; 7] = [SHIFT_JIS, EUC_JP, ISO_2022_JP, GBK, GB18030, BIG5, EUC_KR];
        // Also put these languages' text across the 256 KiB chunk edge.
        const EDGE_LANGS: [&str; 5] = ["cs", "de", "jp", "ru", "zh"];

        fn strings(v: &serde_json::Value, out: &mut String) {
            match v {
                serde_json::Value::String(s) => {
                    out.push_str(s);
                    out.push('\n');
                }
                serde_json::Value::Array(a) => a.iter().for_each(|v| strings(v, out)),
                serde_json::Value::Object(o) => o.values().for_each(|v| strings(v, out)),
                _ => {}
            }
        }

        let mut files: Vec<_> = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/resources/languages"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        files.sort();
        let mut out = vec![];
        let mut seen = std::collections::HashSet::new();
        // Pure-ASCII and repeated inputs add nothing over `analyze_charsets`.
        let mut add = |name: String, data: Vec<u8>| {
            if !data.is_ascii() && seen.insert(data.clone()) {
                out.push((name, data));
            }
        };
        for f in files {
            let lang = f.file_stem().unwrap().to_str().unwrap().to_string();
            let mut text = String::new();
            strings(&serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap(), &mut text);
            let mut encoded = vec![
                ("utf-8".to_string(), text.clone().into_bytes()),
                ("utf-16le".to_string(), text.encode_utf16().flat_map(u16::to_le_bytes).collect()),
                ("utf-16be".to_string(), text.encode_utf16().flat_map(u16::to_be_bytes).collect()),
            ];
            // Characters a charset can't encode are dropped.
            for cs in SINGLE_BYTE {
                let table = crate::codepages::table(cs).unwrap();
                let bytes = text.chars().filter_map(|c| table.iter().position(|&cp| cp == c as u32).map(|b| b as u8));
                encoded.push((cs.to_string(), bytes.collect()));
            }
            for enc in MULTI_BYTE {
                let kept: String = text.chars().filter(|c| !enc.encode(c.encode_utf8(&mut [0; 4])).2).collect();
                encoded.push((enc.name().to_ascii_lowercase(), enc.encode(&kept).0.into_owned()));
            }
            for (cs, bytes) in encoded {
                for len in [60, 400, bytes.len()] {
                    add(format!("{lang}\t{cs}\t{len}"), bytes[..len.min(bytes.len())].to_vec());
                }
                if EDGE_LANGS.contains(&lang.as_str()) {
                    for pad in [1, 2] {
                        let data = [&b"A".repeat(256 * 1024 - pad)[..], &bytes[..bytes.len().min(5000)]].concat();
                        add(format!("{lang}\t{cs}\tedge-{pad}"), data);
                    }
                }
            }
        }
        out
    }
}
