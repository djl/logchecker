//! CLI. `analyze` prints the details as JSON; `decode` and `translate` print the converted log.

use logchecker::logchecker::{Logchecker, VERSION};
use logchecker::{charset, php, translator};
use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "Usage:
  logchecker analyze [-o <out_file>] <file>
  logchecker decode [-o <out_file>] <file>
  logchecker translate [-l|--language <code>] [-o <out_file>] <file>

Global options: -V/--version, -h/--help";

/// println! that ignores write errors, so a closed pipe (`| head`) doesn't panic.
macro_rules! say {
    ($($t:tt)*) => {{ let _ = writeln!(std::io::stdout(), $($t)*); }};
}

struct Out {
    quiet: bool,
}

impl Out {
    fn write(&self, msg: &[u8]) {
        if !self.quiet {
            let _ = std::io::stdout().write_all(msg);
        }
    }
    fn writeln(&self, msg: &[u8]) {
        self.write(&[msg, b"\n"].concat());
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out = Out { quiet: false };
    if args.iter().any(|a| a == "-V" || a == "--version") {
        say!("logchecker {VERSION}");
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
    let (opts, pos) = parse(args, &[], &["-o"])?;
    let file = positional(&pos, 1)?;
    if !std::path::Path::new(file).exists() {
        out.writeln(b"Invalid file");
        return Ok(1);
    }
    let mut lc = Logchecker::new();
    lc.new_file(file).map_err(|e| format!("{file}: {e}"))?;
    lc.parse();

    let json = lc.details_json().ok_or("Log details are not valid UTF-8")?;
    let json = php::json_encode_pretty(&json);
    match opts.last().and_then(|(_, v)| *v) {
        Some(f) => write_file(f, json.as_bytes())?,
        None => say!("{json}"),
    }
    Ok(0)
}

fn decode(out: &mut Out, args: &[String]) -> Result<u8, String> {
    let (opts, pos) = parse(args, &[], &["-o"])?;
    let file = positional(&pos, 1)?;
    if !std::path::Path::new(file).exists() {
        out.writeln(b"Invalid file");
        return Ok(1);
    }
    let raw = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
    let log = charset::decode_encoding(&raw).map_err(|()| "Could not properly decode log encoding".to_string())?;
    match opts.last().and_then(|(_, v)| *v) {
        Some(f) => write_file(f, &log)?,
        None => out.write(&log),
    }
    Ok(0)
}

fn translate(out: &mut Out, args: &[String]) -> Result<u8, String> {
    let (opts, pos) = parse(args, &[], &["-l", "--language", "-o"])?;
    let file = positional(&pos, 1)?;
    if !std::path::Path::new(file).exists() {
        out.writeln(b"Invalid file");
        return Ok(1);
    }
    let raw = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
    let out_file = opts.iter().rfind(|(n, _)| n == "-o").and_then(|(_, v)| *v);
    if out_file.is_some() {
        out.quiet = true;
    }
    let text = std::str::from_utf8(&raw).ok();
    let code = match opts.iter().rfind(|(n, _)| n != "-o").and_then(|(_, v)| *v).filter(|v| !v.is_empty() && *v != "0") {
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
