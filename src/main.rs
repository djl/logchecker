//! CLI. `analyze`, `decode` and `translate` print what OPSnet/Logchecker's Symfony commands
//! print.

use logchecker::logchecker::{Logchecker, VERSION, str_replace};
use logchecker::{charset, console, php, translator};
use std::io::{IsTerminal, Write};
use std::process::ExitCode;

const USAGE: &str = "Usage:
  logchecker analyze [--html] [--no_text] [--json] <file> [<out_file> [<details>]]
  logchecker decode <file> [<out_file>]
  logchecker translate [-l|--language <code>] <file> [<out_file>]

Global options: --ansi, --no-ansi, -V/--version, -h/--help";

/// println! that ignores write errors, so a closed pipe (`| head`) doesn't panic.
macro_rules! say {
    ($($t:tt)*) => {{ let _ = writeln!(std::io::stdout(), $($t)*); }};
}

struct Out {
    decorated: bool,
    quiet: bool,
}

impl Out {
    fn write(&self, msg: &[u8]) {
        if !self.quiet {
            let _ = std::io::stdout().write_all(&console::format(msg, self.decorated));
        }
    }
    fn writeln(&self, msg: &[u8]) {
        self.write(&[msg, b"\n"].concat());
    }
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut decorated = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    args.retain(|a| match a.as_str() {
        "--ansi" => {
            decorated = true;
            false
        }
        "--no-ansi" => {
            decorated = false;
            false
        }
        _ => true,
    });
    let mut out = Out { decorated, quiet: false };
    if args.iter().any(|a| a == "-V" || a == "--version") {
        out.writeln(format!("logchecker <info>{VERSION}</info>").as_bytes());
        return ExitCode::SUCCESS;
    }
    let Some(cmd) = args.first().cloned() else {
        say!("logchecker {VERSION}\n\n{USAGE}");
        return ExitCode::SUCCESS;
    };
    let rest = &args[1..];
    if rest.iter().any(|a| a == "-h" || a == "--help") || cmd == "-h" || cmd == "--help" || cmd == "help" {
        say!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let result = match cmd.as_str() {
        "analyze" | "analyse" => analyze(&mut out, rest),
        "decode" => decode(&mut out, rest),
        "translate" => translate(&mut out, rest),
        _ => Err(format!("Command \"{cmd}\" is not defined.")),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("{e}\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

/// Split options (with their names) from positional arguments; `valued` options take a value.
fn parse<'a>(args: &'a [String], flags: &[&str], valued: &[&str]) -> Result<(Vec<(String, Option<&'a str>)>, Vec<&'a str>), String> {
    let (mut opts, mut pos) = (vec![], vec![]);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--" {
            pos.extend(it.by_ref().map(String::as_str));
            break;
        }
        if a.starts_with('-') && a.len() > 1 {
            let (name, inline) = match a.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (a.as_str(), None),
            };
            if flags.contains(&name) && inline.is_none() {
                opts.push((name.to_string(), None));
            } else if valued.contains(&name) {
                let v = match inline {
                    Some(v) => v,
                    None => it.next().ok_or(format!("The \"{name}\" option requires a value."))?,
                };
                opts.push((name.to_string(), Some(v)));
            } else {
                return Err(format!("The \"{name}\" option does not exist."));
            }
        } else {
            pos.push(a.as_str());
        }
    }
    Ok((opts, pos))
}

fn positional<'a>(pos: &[&'a str], max: usize) -> Result<&'a str, String> {
    match pos.len() {
        0 => Err("Not enough arguments (missing: \"file\").".into()),
        n if n > max => Err("Too many arguments.".into()),
        _ => Ok(pos[0]),
    }
}

fn write_file(path: &str, data: &[u8]) -> Result<(), String> {
    std::fs::write(path, data).map_err(|e| format!("{path}: {e}"))
}

fn analyze(out: &mut Out, args: &[String]) -> Result<u8, String> {
    let (opts, pos) = parse(args, &["--html", "--no_text", "--json"], &[])?;
    let file = positional(&pos, 3)?;
    let has = |n: &str| opts.iter().any(|(o, _)| o == n);
    if !std::path::Path::new(file).exists() {
        out.writeln(b"Invalid file");
        return Ok(1);
    }
    let mut lc = Logchecker::new();
    lc.new_file(file).map_err(|e| format!("{file}: {e}"))?;
    lc.parse();

    if let Some(details) = pos.get(2) {
        // json_encode fails (false, written as "") on invalid UTF-8.
        let json = lc.details_json().map(|v| php::json_encode_pretty(&v)).unwrap_or_default();
        write_file(details, json.as_bytes())?;
    }
    if let Some(out_file) = pos.get(1) {
        write_file(out_file, lc.get_log())?;
        if !has("--json") {
            return Ok(0);
        }
    }
    if has("--json") {
        let json = lc.details_json().ok_or("Log details are not valid UTF-8")?;
        say!("{}", php::json_encode_pretty(&json));
        return Ok(0);
    }

    let field = |label: &str, v: &[u8]| [label.as_bytes(), v].concat();
    out.writeln(&field("Ripper  : ", lc.get_ripper().map_or("", |r| r.as_str()).as_bytes()));
    out.writeln(&field("Version : ", lc.get_ripper_version().unwrap_or(b"")));
    out.writeln(&field("Language: ", lc.get_language().as_bytes()));
    out.writeln(&field("Score   : ", lc.get_score().to_string().as_bytes()));
    out.writeln(&field("Checksum: ", lc.get_checksum_state().as_bytes()));
    if !lc.get_details().is_empty() {
        out.writeln(b"Details :");
        for d in lc.get_details() {
            out.writeln(&[b"    ", &d[..]].concat());
        }
    }
    if has("--no_text") {
        return Ok(0);
    }
    out.writeln(b"");
    out.writeln(b"Log Text:");
    out.writeln(b"");

    static DOUBLE_QUOTED: std::sync::LazyLock<regex::bytes::Regex> =
        std::sync::LazyLock::new(|| regex::bytes::Regex::new(r#"(?-u)<span class="([a-zA-Z0-9 ]+)">"#).unwrap());
    let mut log = DOUBLE_QUOTED.replace_all(lc.get_log(), &b"<span class='${1}'>"[..]).into_owned();
    if has("--html") {
        if !out.quiet {
            let _ = std::io::stdout().write_all(&[&log[..], b"\n"].concat());
        }
        return Ok(0);
    }
    // PHP str_replace with arrays: each pair applied in turn over the whole string.
    const REPLACES: [(&[u8], &[u8]); 15] = [
        (b"</span>", b"</>"),
        (b"</strong>", b"</>"),
        (b"<span class='good'>", b"<fg=green;options=bold>"),
        (b"<span class='bad'>", b"<fg=red;options=bold>"),
        (b"<span class='goodish'>", b"<fg=cyan;options=bold>"),
        (b"<span class='badish'>", b"<fg=yellow;options=bold>"),
        (b"<span class='log1'>", b"<options=underscore>"),
        (b"<span class='log2'>", b"<fg=yellow>"),
        (b"<span class='log3'>", b"<fg=blue>"),
        (b"<span class='log4'>", b"<options=bold>"),
        (b"<span class='log5'>", b"<options=underscore>"),
        (b"<span class='log4 log1'>", b"<options=bold>"),
        (b"<span class='log4 log3'>", b"<fg=blue;options=bold>"),
        (b"<span class='log4 log5'>", b"<options=bold,underscore>"),
        (b"<strong>", b"<options=bold>"),
    ];
    for (from, to) in REPLACES {
        log = str_replace(&log, from, to);
    }
    out.writeln(&log);
    Ok(0)
}

fn decode(out: &mut Out, args: &[String]) -> Result<u8, String> {
    let (_, pos) = parse(args, &[], &[])?;
    let file = positional(&pos, 2)?;
    if !std::path::Path::new(file).exists() {
        out.writeln(b"Invalid file");
        return Ok(1);
    }
    let raw = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
    let log = charset::decode_encoding(&raw).map_err(|()| "Could not properly decode log encoding".to_string())?;
    match pos.get(1) {
        Some(out_file) => write_file(out_file, &log)?,
        None => out.write(&log),
    }
    Ok(0)
}

fn translate(out: &mut Out, args: &[String]) -> Result<u8, String> {
    let (opts, pos) = parse(args, &[], &["-l", "--language"])?;
    let file = positional(&pos, 2)?;
    if !std::path::Path::new(file).exists() {
        out.writeln(b"Invalid file");
        return Ok(1);
    }
    let raw = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
    let out_file = pos.get(1);
    if out_file.is_some() {
        out.quiet = true;
    }
    let text = std::str::from_utf8(&raw).ok();
    let code = match opts.last().and_then(|(_, v)| *v).filter(|v| !v.is_empty() && *v != "0") {
        Some(code) => {
            out.writeln(format!("Translating from {code} to English").as_bytes());
            code.to_string()
        }
        None => {
            let lang = text.and_then(translator::get_language).ok_or("Could not determine language of EAC log")?;
            out.writeln(format!("Translating from {} ({}) to English", lang.name, lang.name_english).as_bytes());
            lang.code
        }
    };
    // PHP's /u replacements leave invalid UTF-8 untouched.
    let log = match text {
        Some(t) => translator::translate(t, &code)?.into_bytes(),
        None if code == "en" => raw.clone(),
        None => {
            translator::translate("", &code)?;
            raw.clone()
        }
    };
    match out_file {
        Some(f) => write_file(f, &log)?,
        None => out.write(&log),
    }
    Ok(0)
}
