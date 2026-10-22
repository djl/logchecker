//! Port of Check/Checksum/XLD.php (itself a port of xld_logchecker.py).
//! The signature is SHA-256 with a non-standard initial state, a bespoke scramble step,
//! and base64 with a non-standard alphabet.

use super::{CHECKSUM_INVALID, CHECKSUM_MISSING, CHECKSUM_OK};

const LOGCHECKER_MIN_VERSION: &str = "20121027";
const BEGIN_SIGNATURE: &str = "\n-----BEGIN XLD SIGNATURE-----\n";
const END_SIGNATURE: &str = "\n-----END XLD SIGNATURE-----\n";

const INITIAL_STATE: [u32; 8] =
    [0x1D95E3A4, 0x06520EF5, 0x3A9CFB75, 0x6104BCAE, 0x09CEDA82, 0xBA55E60B, 0xEAEC16C6, 0xEB19AF15];

pub const SHA256_STANDARD_STATE: [u32; 8] =
    [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];

const ROUND_CONSTANTS: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
];

const MAGIC_CONSTANTS: [u32; 8] =
    [0x99036946, 0xE99DB8E7, 0xE3AE2FA7, 0x0A339740, 0xF06EB6A9, 0x92FF9B65, 0x028F7873, 0x9070E316];

const XLD_ALPHABET: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";

/// xld_logchecker.py's verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    NotALogfile,
    Malformed,
    Forged,
    Ok,
}

pub fn validate(data: &[u8]) -> &'static str {
    match check(data) {
        Outcome::Ok => CHECKSUM_OK,
        Outcome::Malformed | Outcome::Forged => CHECKSUM_INVALID,
        Outcome::NotALogfile => CHECKSUM_MISSING,
    }
}

pub fn check(data: &[u8]) -> Outcome {
    // XLD logs are UTF-8; anything else is not a valid logfile.
    let Ok(data) = std::str::from_utf8(data) else {
        return Outcome::NotALogfile;
    };
    let first_line = data.split('\n').next().unwrap_or("");
    let version = first_line
        .starts_with("X Lossless Decoder version")
        .then(|| first_line.split_ascii_whitespace().nth(4))
        .flatten();
    let Some((text, rest)) = data.split_once(BEGIN_SIGNATURE) else {
        return Outcome::NotALogfile;
    };
    let old_signature = crate::php::trim(rest.split(END_SIGNATURE).next().unwrap());
    if old_signature != signature(text.as_bytes()) {
        return Outcome::Malformed;
    }
    // A signature produced by a pre-20121027 XLD is considered forged.
    match version {
        Some(v) if v > LOGCHECKER_MIN_VERSION => Outcome::Ok,
        _ => Outcome::Forged,
    }
}

fn signature(text: &[u8]) -> String {
    let mut input = hex(&sha256_with_state(text, INITIAL_STATE)).into_bytes();
    input.extend_from_slice(b"\nVersion=0001");
    let scrambled = scramble(&input);
    base64_xld(&scrambled)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 compression with a caller-supplied initial state.
pub fn sha256_with_state(data: &[u8], mut state: [u32; 8]) -> [u8; 32] {
    let mut msg = data.to_vec();
    let bit_len = 8 * data.len() as u64;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[4 * i..4 * i + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for i in 0..64 {
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(ROUND_CONSTANTS[i]).wrapping_add(w[i]);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
    let mut out = [0u8; 32];
    for (i, s) in state.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&s.to_be_bytes());
    }
    out
}

fn scramble(data: &[u8]) -> Vec<u8> {
    let stop = 8 * (data.len() / 8);
    let unaligned = &data[stop..];
    let mut data = data[..stop].to_vec();
    if !unaligned.is_empty() {
        data.extend_from_slice(&[0; 8]);
    }

    let (mut x, mut y) = (0x6479B873u32, 0x48853AFCu32);
    let mut output = Vec::new();
    for block in data.as_chunks::<8>().0 {
        x ^= u32::from_be_bytes(block[0..4].try_into().unwrap());
        y ^= u32::from_be_bytes(block[4..8].try_into().unwrap());
        for _ in 0..4 {
            for i in 0..2 {
                y ^= x;
                let a = MAGIC_CONSTANTS[4 * i].wrapping_add(y);
                let b = a.wrapping_sub(1).wrapping_add(a.rotate_left(1));
                x ^= b ^ b.rotate_left(4);
                let c = MAGIC_CONSTANTS[4 * i + 1].wrapping_add(x);
                let d = c.wrapping_add(1).wrapping_add(c.rotate_left(2));
                let e = MAGIC_CONSTANTS[4 * i + 2].wrapping_add(d ^ d.rotate_left(8));
                let f = e.rotate_left(1).wrapping_sub(e);
                y ^= (x | f) ^ f.rotate_left(16);
                let g = MAGIC_CONSTANTS[4 * i + 3].wrapping_add(y);
                x ^= g.wrapping_add(1).wrapping_add(g.rotate_left(2));
            }
        }
        output.extend_from_slice(&x.to_be_bytes());
        output.extend_from_slice(&y.to_be_bytes());
    }
    // The unaligned tail is XORed with the last scrambled block, truncated to its length.
    if !unaligned.is_empty() {
        let last = output.split_off(output.len() - 8);
        output.extend(unaligned.iter().zip(last).map(|(u, l)| u ^ l));
    }
    output
}

/// Base64 with XLD's alphabet and no padding.
fn base64_xld(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, &b)| n | (b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(XLD_ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_sha256() {
        assert_eq!(
            hex(&sha256_with_state(b"abc", SHA256_STANDARD_STATE)),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
