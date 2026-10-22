//! Port of Check/Checksum.php.

pub mod eac;
mod rijndael;
pub mod whipper;
pub mod xld;

use crate::ripper::Ripper;

pub const CHECKSUM_OK: &str = "checksum_ok";
pub const CHECKSUM_INVALID: &str = "checksum_invalid";
pub const CHECKSUM_MISSING: &str = "checksum_missing";

/// Validates a log file's raw bytes, returning one of the CHECKSUM_* states.
pub fn validate(data: &[u8], ripper: Ripper) -> Result<&'static str, String> {
    match ripper {
        Ripper::Whipper => Ok(whipper::validate(data)),
        Ripper::Eac => Ok(eac::validate(data)),
        Ripper::Xld => Ok(xld::validate(data)),
        Ripper::Unknown => Err("Unknown ripper: unknown".into()),
    }
}
