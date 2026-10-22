//! Port of Parser/EAC/Translator.php.

use regex::{NoExpand, Regex, RegexBuilder};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use serde_json::{Map, Value};

macro_rules! languages {
    ($($code:literal),*) => {
        fn language_file(code: &str) -> Option<&'static str> {
            match code {
                $($code => Some(include_str!(concat!("../resources/languages/", $code, ".json"))),)*
                _ => None,
            }
        }
    };
}
languages!("bg", "cs", "de", "en", "es", "fr", "it", "jp", "ko", "nl", "pl", "ru", "se", "sk", "sr", "zh", "master");

fn load(code: &str) -> Option<Map<String, Value>> {
    serde_json::from_str(language_file(code)?).ok()
}

pub struct Language {
    pub code: String,
    pub name: String,
    pub name_english: String,
}

/// Translator::translate. Err is InvalidFileException's message.
pub fn translate(log: &str, code: &str) -> Result<String, String> {
    if code == "en" {
        return Ok(log.to_string());
    }
    let mut log = log.to_string();
    for (re, en) in rules(code)? {
        log = re.replace_all(&log, NoExpand(en)).into_owned();
    }
    Ok(log)
}

/// A language's (pattern, English) replacements in file order, compiled once per process.
fn rules(code: &str) -> Result<&'static [(Regex, String)], String> {
    static CACHE: LazyLock<Mutex<HashMap<String, &'static [(Regex, String)]>>> = LazyLock::new(Default::default);
    if let Some(r) = CACHE.lock().unwrap().get(code) {
        return Ok(r);
    }
    let english = load("en").unwrap();
    let Some(translation) = load(code) else {
        return Err(format!("Could not find translation file for {code}."));
    };
    let mut rules = vec![];
    for (key, value) in &translation {
        // PHP empty(): missing, "" or "0".
        let Some(Value::String(en)) = english.get(key) else { continue };
        if en.is_empty() || en == "0" {
            continue;
        }
        let values = match value {
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
            Value::String(s) => vec![s.as_str()],
            _ => vec![],
        };
        // Case-insensitive for most things, but not "No", "Yes", etc. (keys up to 16).
        let insensitive = key.parse::<i64>().map_or(true, |k| k > 16);
        for v in values {
            let re = RegexBuilder::new(&regex::escape(v)).case_insensitive(insensitive).build().unwrap();
            rules.push((re, en.clone()));
        }
    }
    // Leaked on purpose: at most one entry per bundled language.
    let rules: &'static [(Regex, String)] = Vec::leak(rules);
    CACHE.lock().unwrap().insert(code.to_string(), rules);
    Ok(rules)
}

/// Translator::getLanguage. None is UnknownLanguageException.
pub fn get_language(log: &str) -> Option<Language> {
    let master = load("master").unwrap();
    for (code, lang) in &master {
        for s in lang["eac_strings"].as_array().unwrap() {
            let re = RegexBuilder::new(&regex::escape(s.as_str().unwrap())).case_insensitive(true).build().unwrap();
            if re.is_match(log) {
                return Some(Language {
                    code: code.clone(),
                    name: lang["name"].as_str().unwrap().into(),
                    name_english: lang["name_english"].as_str().unwrap().into(),
                });
            }
        }
    }
    None
}
