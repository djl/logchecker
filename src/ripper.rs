//! Port of Check/Ripper.php.

use crate::logchecker::contains;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ripper {
    Unknown,
    Whipper,
    Xld,
    Eac,
}

impl Ripper {
    pub fn as_str(self) -> &'static str {
        match self {
            Ripper::Unknown => "unknown",
            Ripper::Whipper => "whipper",
            Ripper::Xld => "XLD",
            Ripper::Eac => "EAC",
        }
    }
}

/// None means "Could not determine ripper".
pub fn get_ripper(log: &[u8]) -> Option<Ripper> {
    if contains(log, b"Log created by: whipper") {
        Some(Ripper::Whipper)
    } else if contains(log, b"X Lossless Decoder version") {
        Some(Ripper::Xld)
    } else if contains(log, b"Exact Audio Copy") {
        Some(Ripper::Eac)
    } else {
        // Only a first line that is terminated counts (PHP strstr returns false otherwise).
        let pos = log.iter().position(|&b| b == b'\n')?;
        contains(&log[..pos], b"EAC").then_some(Ripper::Eac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ripper_test_php() {
        let cases: [(&str, Ripper); 5] = [
            ("Exact Audio Copy V1.3 from 2. September 2016\n\nEAC extraction logfile from 11. December 2016, 0:14", Ripper::Eac),
            ("EAC 展開 ログファイル 日付： 24. 12月 2005, 18:37 for CD\nTest", Ripper::Eac),
            ("Отчёт EAC об извлечении, выполненном 15. января 2010, 16:06 для диска:\nGirls Against Boys / Cruise Yourself", Ripper::Eac),
            ("Log created by: whipper 0.7.0 (internal logger)\nLog creation date: 2018-11-23T15:19:21Z", Ripper::Whipper),
            ("X Lossless Decoder version 20161007 (149.3)\n\nXLD extraction logfile from 2017-01-04 18:59:53 -0500", Ripper::Xld),
        ];
        for (log, ripper) in cases {
            assert_eq!(get_ripper(log.as_bytes()), Some(ripper));
        }
        assert_eq!(get_ripper(b"invalid invalid invalid"), None);
    }
}
