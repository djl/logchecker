//! The upstream test suites (Logchecker phpunit, eac_logchecker.py, xld_logchecker.py) ported as-is.

use logchecker::checksum::{self, CHECKSUM_INVALID as INVALID, CHECKSUM_MISSING as MISSING, CHECKSUM_OK as OK, eac, xld};
use logchecker::ripper::Ripper;

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fix(p: &str) -> String {
    format!("{FIX}/{p}")
}

// tests/Check/Checksum/EACTest.php
#[test]
fn php_eac_checksum() {
    let expected = [
        OK, OK, MISSING, MISSING, OK, MISSING, MISSING, INVALID, MISSING, MISSING, MISSING, OK, OK, MISSING,
        INVALID, INVALID, MISSING, OK, MISSING, MISSING, MISSING, MISSING, MISSING, MISSING, MISSING, INVALID, INVALID,
    ];
    for (i, want) in expected.iter().enumerate() {
        let path = fix(&format!("logchecker/eac/checksum/{:02}.log", i + 1));
        assert_eq!(eac::validate(&std::fs::read(&path).unwrap()), *want, "{path}");
    }
}

// tests/Check/Checksum/XLDTest.php
#[test]
fn php_xld_checksum() {
    let expected = [OK, OK, INVALID, MISSING, OK, OK, MISSING, OK];
    for (i, want) in expected.iter().enumerate() {
        let path = fix(&format!("logchecker/xld/checksum/{:02}.log", i + 1));
        assert_eq!(xld::validate(&std::fs::read(&path).unwrap()), *want, "{path}");
    }
}

// tests/Check/ChecksumTest.php
#[test]
fn php_checksum_dispatch() {
    // Upstream's "Log file does not exist" case is gone: validate takes bytes, not a path.
    let data = std::fs::read(fix("xld/01.log")).unwrap();
    assert_eq!(checksum::validate(&data, Ripper::Unknown).unwrap_err(), "Unknown ripper: unknown");
}

// eac_logchecker.py: test_eac_logchecker.py
#[test]
fn py_eac() {
    use eac::Status::{Bad as B, No as N, Ok as G};
    let expected: [&[eac::Status]; 27] = [
        &[G, G], &[G], &[N], &[G, N], &[G, G], &[N], &[N], &[B], &[N], &[N], &[N], &[G], &[G], &[N], &[B],
        &[B], &[N], &[G], &[N], &[N], &[N], &[N], &[N], &[N], &[G, N], &[B], &[G, B, B, B],
    ];
    for (i, want) in expected.iter().enumerate() {
        let path = fix(&format!("eac/{:02}.log", i + 1));
        assert_eq!(eac::entry_statuses(&std::fs::read(&path).unwrap()), *want, "{path}");
    }
}

// xld_logchecker.py: test.py (not_real.log is the CLI's missing-file case, covered in tests/cli.rs)
#[test]
fn py_xld() {
    use xld::Outcome::*;
    let expected = [Ok, Ok, Malformed, NotALogfile, Ok, Ok, NotALogfile, Ok];
    for (i, want) in expected.iter().enumerate() {
        let path = fix(&format!("xld/{:02}.log", i + 1));
        assert_eq!(xld::check(&std::fs::read(&path).unwrap()), *want, "{path}");
    }
}

// tests/UtilTest.php::testDecodeLog
#[test]
fn php_decode_log() {
    let mut cases = Vec::new();
    for entry in std::fs::read_dir(fix("logchecker/eac/originals")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        let mut parts = name.split('_');
        let (lang, log) = (parts.next().unwrap(), parts.next().unwrap_or(""));
        cases.push((path.clone(), fix(&format!("logchecker/eac/utf8/{lang}/{log}"))));
    }
    for entry in std::fs::read_dir(fix("logchecker/xld/originals")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        cases.push((path, fix(&format!("logchecker/xld/utf8/{name}"))));
    }
    let mut checked = 0;
    for (log, expected) in cases {
        let Ok(expected) = std::fs::read(&expected) else { continue };
        let got = logchecker::charset::decode_encoding(&std::fs::read(&log).unwrap()).unwrap();
        assert!(got == expected, "{}", log.display());
        checked += 1;
    }
    assert_eq!(checked, 4, "decode fixtures: cs_1, jp_2, pl_1, xld macroman");
}

// tests/Parser/EAC/TranslatorTest.php
#[test]
fn php_translator() {
    use logchecker::translator::{get_language, translate};
    let mut checked = 0;
    for dir in std::fs::read_dir(fix("logchecker/eac/utf8")).unwrap() {
        let dir = dir.unwrap().path();
        let lang = dir.file_name().unwrap().to_str().unwrap().to_string();
        for f in std::fs::read_dir(&dir).unwrap() {
            let path = f.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap();
            if name.contains("_en") {
                continue;
            }
            let log = std::fs::read_to_string(&path).unwrap();
            assert_eq!(get_language(&log).unwrap().code, lang, "{name}");
            let want = std::fs::read_to_string(path.to_str().unwrap().replace(".log", "_en.log")).unwrap();
            assert!(translate(&log, &lang).unwrap() == want, "{}", path.display());
            checked += 1;
        }
    }
    assert_eq!(checked, 7);
    let xld = std::fs::read_to_string(fix("logchecker/xld/originals/xld_perfect.log")).unwrap();
    assert!(get_language(&xld).is_none());
    for f in std::fs::read_dir(fix("logchecker/eac/originals")).unwrap() {
        let path = f.unwrap().path();
        if path.file_name().unwrap().to_str().unwrap().starts_with("en") {
            let log = logchecker::charset::decode_encoding(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(get_language(&String::from_utf8(log).unwrap()).unwrap().code, "en", "{}", path.display());
        }
    }
}

// tests/LogcheckerTest.php::testLogchecker
#[test]
fn php_logchecker() {
    let mut failures = vec![];
    let mut count = 0;
    for ripper in ["eac", "xld", "whipper"] {
        let base = fix(&format!("logchecker/{ripper}"));
        let mut entries: Vec<_> = std::fs::read_dir(format!("{base}/originals")).unwrap().map(|e| e.unwrap().path()).collect();
        entries.sort();
        for path in entries {
            let name = path.file_name().unwrap().to_str().unwrap().to_string();
            let details: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(format!("{base}/details/{}", name.replace(".log", ".json"))).unwrap())
                    .unwrap();
            let html = std::fs::read(format!("{base}/html/{name}")).unwrap();
            let mut lc = logchecker::logchecker::Logchecker::new();
            lc.new_file(path.to_str().unwrap()).unwrap();
            lc.parse();
            count += 1;
            let actual = lc.details_json().unwrap();
            if actual != details {
                failures.push(format!("{ripper}/{name}: details\n  want {details}\n  got  {actual}"));
            }
            if lc.get_log() != html.as_slice() {
                failures.push(format!("{ripper}/{name}: html differs"));
            }
        }
    }
    assert_eq!(count, 44);
    assert!(failures.is_empty(), "{} failures:\n{}", failures.len(), failures.join("\n"));
}

// tests/LogcheckerTest.php::testCheckUnknownLog
#[test]
fn php_unknown_log() {
    let mut lc = logchecker::logchecker::Logchecker::new();
    lc.new_file(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/upstream.rs")).unwrap();
    lc.parse();
    assert_eq!(lc.get_ripper(), Some(Ripper::Unknown));
    assert_eq!(lc.get_ripper_version(), None);
    assert_eq!(lc.get_score(), 0);
    assert_eq!(lc.get_language(), "en");
    assert_eq!(lc.get_details(), [b"Unknown log file, could not determine ripper.".to_vec()]);
}
