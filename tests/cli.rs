//! CLI behaviour that the library tests can't see.

use std::process::Command;

fn run(args: &[&str]) -> (String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_logchecker")).args(args).env_remove("NO_COLOR").output().unwrap();
    (String::from_utf8_lossy(&out.stdout).into_owned(), out.status.code().unwrap())
}

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

#[test]
fn analyze_plain_output_strips_styles() {
    let (out, code) = run(&["analyze", &format!("{FIX}/logchecker/eac/originals/en_1.log")]);
    assert_eq!(code, 0);
    assert!(out.starts_with("Ripper  : EAC\nVersion : "), "{out}");
    assert!(out.contains("\nLog Text:\n\n"));
    assert!(!out.contains("<fg=") && !out.contains("\x1b["));
    assert_eq!(run(&["analyze", "missing.log"]), ("Invalid file\n".into(), 1));
    assert_eq!(run(&["--version"]).0, "logchecker 0.1.0 (upstream ca56547)\n");
}

#[test]
fn analyze_json() {
    let (out, code) = run(&["analyze", "--json", &format!("{FIX}/logchecker/eac/originals/en_1.log")]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["ripper"], "EAC");
    assert!(v["score"].is_i64() && v["details"].is_array());
}

fn write_tmp(name: &str, data: &str) -> String {
    let path = format!("{}/{name}", env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(&path, data).unwrap();
    path
}

// Nested YAML aliases expand to ~10^9 nodes if the loader resolves them.
#[test]
fn whipper_alias_bomb_is_rejected() {
    let mut log = String::from("Log created by: whipper 0.9.0\na0: &a0 [x,x,x,x,x,x,x,x,x,x]\n");
    for i in 1..9 {
        log += &format!("a{i}: &a{i} [{}]\n", vec![format!("*a{}", i - 1); 10].join(","));
    }
    let (out, code) = run(&["analyze", "--json", &write_tmp("alias_bomb.log", &log)]);
    assert_eq!(code, 0);
    assert!(out.contains("Could not parse whipper log."), "{out}");
}

// Splitting into parts used to be quadratic: 80k parts took ~4s in release.
#[test]
fn many_parts_split_quickly() {
    let log = format!("Exact Audio Copy V1.0 from 1. January 2020\n{}", "x\nEnd of status report\n".repeat(100_000));
    let path = write_tmp("many_parts.log", &log);
    let start = std::time::Instant::now();
    assert_eq!(run(&["analyze", "--no_text", &path]).1, 0);
    assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
}

// Whipper details and track lookups used to be quadratic: 90k tracks took ~60s in release.
#[test]
fn many_whipper_tracks_score_quickly() {
    let log = std::fs::read_to_string(format!("{FIX}/logchecker/whipper/originals/whipper_0_9_0.log")).unwrap();
    let (head, rest) = log.split_once("Tracks:\n").unwrap();
    let tail = &rest[rest.find("Conclusive status report:").unwrap()..];
    let tracks: String = (1..=30_000)
        .map(|i| format!("  {i}:\n    Filename: ./a/{i}.flac\n    Test CRC: {i:08X}\n    Copy CRC: {:08X}\n    Status: Copy OK\n\n", i + 1))
        .collect();
    let path = write_tmp("many_whipper_tracks.log", &format!("{head}Tracks:\n{tracks}{tail}"));
    let start = std::time::Instant::now();
    let (out, code) = run(&["analyze", "--json", &path]);
    assert_eq!(code, 0);
    assert!(out.contains("CRC mismatch: 00007530 and 00007531"), "{}", &out[..out.len().min(500)]);
    assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
}

// The checksum used to re-read the path, which a pipe can't do: valid logs came out invalid.
#[test]
fn analyze_from_stdin_keeps_checksum() {
    use std::io::Write;
    use std::process::Stdio;
    let log = std::fs::read(format!("{FIX}/xld/01.log")).unwrap();
    // A real pipe: a file on stdin could be reopened through /dev/stdin.
    let mut child = Command::new(env!("CARGO_BIN_EXE_logchecker"))
        .args(["analyze", "--no_text", "/dev/stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&log).unwrap();
    let out = child.wait_with_output().unwrap();
    let out = String::from_utf8_lossy(&out.stdout);
    assert!(out.contains("Checksum: checksum_ok"), "{out}");
}

// Printing into a closed pipe (`| head`) used to panic with exit code 101.
#[test]
fn closed_stdout_is_not_a_crash() {
    use std::process::Stdio;
    let mut child = Command::new(env!("CARGO_BIN_EXE_logchecker"))
        .args(["analyze", "--json"])
        .arg(format!("{FIX}/logchecker/eac/originals/en_1.log"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert_ne!(out.status.code(), Some(101), "{}", String::from_utf8_lossy(&out.stderr));
}
