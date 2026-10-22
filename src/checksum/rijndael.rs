//! Rijndael encryption with a 256-bit block and 256-bit key (Nb = Nk = 8, 14 rounds).
//! Not AES: AES fixes the block at 128 bits. Used only by the EAC checksum.

const NB: usize = 8;
const NK: usize = 8;
const NR: usize = 14;
// Row shift offsets for Nb = 8.
const SHIFTS: [usize; 4] = [0, 1, 3, 4];

const fn sbox() -> [u8; 256] {
    let mut s = [0u8; 256];
    let (mut p, mut q) = (1u8, 1u8);
    loop {
        // p *= 3 in GF(2^8)
        p = p ^ (p << 1) ^ if p & 0x80 != 0 { 0x1B } else { 0 };
        // q /= 3
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        if q & 0x80 != 0 {
            q ^= 0x09;
        }
        let x = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
        s[p as usize] = x ^ 0x63;
        if p == 1 {
            break;
        }
    }
    s[0] = 0x63;
    s
}

static SBOX: [u8; 256] = sbox();

fn xtime(b: u8) -> u8 {
    (b << 1) ^ if b & 0x80 != 0 { 0x1B } else { 0 }
}

pub struct Rijndael256 {
    round_keys: [[u8; 4 * NB]; NR + 1],
}

impl Rijndael256 {
    pub fn new(key: &[u8; 4 * NK]) -> Self {
        let total = NB * (NR + 1);
        let mut w = vec![[0u8; 4]; total];
        for i in 0..NK {
            w[i].copy_from_slice(&key[4 * i..4 * i + 4]);
        }
        let mut rcon = 1u8;
        for i in NK..total {
            let mut t = w[i - 1];
            if i % NK == 0 {
                t.rotate_left(1);
                t = t.map(|b| SBOX[b as usize]);
                t[0] ^= rcon;
                rcon = xtime(rcon);
            } else if i % NK == 4 {
                t = t.map(|b| SBOX[b as usize]);
            }
            for j in 0..4 {
                w[i][j] = w[i - NK][j] ^ t[j];
            }
        }
        let mut round_keys = [[0u8; 4 * NB]; NR + 1];
        for (r, rk) in round_keys.iter_mut().enumerate() {
            for c in 0..NB {
                rk[4 * c..4 * c + 4].copy_from_slice(&w[r * NB + c]);
            }
        }
        Self { round_keys }
    }

    /// Encrypt one 32-byte block. State byte (row r, column c) lives at index 4c + r.
    pub fn encrypt_block(&self, block: &mut [u8; 4 * NB]) {
        let add = |s: &mut [u8; 32], k: &[u8; 32]| s.iter_mut().zip(k).for_each(|(a, b)| *a ^= b);
        add(block, &self.round_keys[0]);
        for round in 1..=NR {
            for b in block.iter_mut() {
                *b = SBOX[*b as usize];
            }
            let old = *block;
            for r in 1..4 {
                for c in 0..NB {
                    block[4 * c + r] = old[4 * ((c + SHIFTS[r]) % NB) + r];
                }
            }
            if round != NR {
                for c in 0..NB {
                    let col = [block[4 * c], block[4 * c + 1], block[4 * c + 2], block[4 * c + 3]];
                    let all = col[0] ^ col[1] ^ col[2] ^ col[3];
                    for r in 0..4 {
                        block[4 * c + r] = col[r] ^ all ^ xtime(col[r] ^ col[(r + 1) % 4]);
                    }
                }
            }
            add(block, &self.round_keys[round]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbox_spot_values() {
        assert_eq!((SBOX[0x00], SBOX[0x01], SBOX[0x53], SBOX[0xFF]), (0x63, 0x7C, 0xED, 0x16));
    }

}
