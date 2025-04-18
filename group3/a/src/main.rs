// src/main.rs
// Pure-Rust XChaCha20-Poly1305 File Encryption CLI (no external crates)
// Rust 2021 edition

use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};

// magic header
const MAGIC: [u8; 4] = *b"XCP1";

// --- Zeroize Module ---
mod zeroize {
    pub fn zeroize(buf: &mut [u8]) {
        use std::ptr;
        for b in buf {
            unsafe { ptr::write_volatile(b, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

// constant-time equality
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

mod rng {
    use std::io;

    #[cfg(unix)]
    pub fn fill_random(buf: &mut [u8]) -> io::Result<()> {
        let mut f = std::fs::File::open("/dev/urandom")?;
        f.read_exact(buf)?;
        Ok(())
    }

    #[cfg(windows)]
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            hAlg: *mut std::ffi::c_void,
            pbBuffer: *mut u8,
            cbBuffer: u32,
            dwFlags: u32,
        ) -> i32;
    }

    #[cfg(windows)]
    pub fn fill_random(buf: &mut [u8]) -> io::Result<()> {
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                0x00000002,
            )
        };
        if status == 0 { Ok(()) }
        else { Err(io::Error::new(io::ErrorKind::Other, format!("BCryptGenRandom failed: 0x{:X}", status))) }
    }
}

mod chacha20 {
    use std::convert::TryInto;

    #[inline]
    fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
    }

    pub fn chacha20_block(key: &[u8; 32], ctr: u32, nonce: &[u8; 12]) -> [u8; 64] {
        let constants = *b"expand 32-byte k";
        let mut state = [0u32; 16];
        for i in 0..4 { state[i] = u32::from_le_bytes(constants[4*i..4*i+4].try_into().unwrap()); }
        for i in 0..8 { state[4+i] = u32::from_le_bytes(key[4*i..4*i+4].try_into().unwrap()); }
        state[12] = ctr;
        for i in 0..3 { state[13+i] = u32::from_le_bytes(nonce[4*i..4*i+4].try_into().unwrap()); }

        let mut working = state;
        for _ in 0..10 {
            quarter_round(&mut working, 0, 4, 8, 12);
            quarter_round(&mut working, 1, 5, 9, 13);
            quarter_round(&mut working, 2, 6, 10, 14);
            quarter_round(&mut working, 3, 7, 11, 15);
            quarter_round(&mut working, 0, 5, 10, 15);
            quarter_round(&mut working, 1, 6, 11, 12);
            quarter_round(&mut working, 2, 7, 8, 13);
            quarter_round(&mut working, 3, 4, 9, 14);
        }

        let mut out = [0u8; 64];
        for i in 0..16 {
            let res = working[i].wrapping_add(state[i]).to_le_bytes();
            out[4*i..4*i+4].copy_from_slice(&res);
        }
        out
    }

    pub fn chacha20_encrypt(key: &[u8; 32], nonce: &[u8; 12], ctr: u32, plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plaintext.len());
        let mut counter = ctr;
        for chunk in plaintext.chunks(64) {
            let ks = chacha20_block(key, counter, nonce);
            counter = counter.wrapping_add(1);
            for (i, &b) in chunk.iter().enumerate() {
                out.push(b ^ ks[i]);
            }
        }
        out
    }

    pub fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
        use std::convert::TryInto;
        let constants = *b"expand 32-byte k";
        let mut state = [0u32; 16];
        for i in 0..4 { state[i] = u32::from_le_bytes(constants[4*i..4*i+4].try_into().unwrap()); }
        for i in 0..8 { state[4+i] = u32::from_le_bytes(key[4*i..4*i+4].try_into().unwrap()); }
        for i in 0..4 { state[12+i] = u32::from_le_bytes(nonce[4*i..4*i+4].try_into().unwrap()); }

        let mut working = state;
        for _ in 0..10 {
            quarter_round(&mut working, 0, 4, 8, 12);
            quarter_round(&mut working, 1, 5, 9, 13);
            quarter_round(&mut working, 2, 6, 10, 14);
            quarter_round(&mut working, 3, 7, 11, 15);
            quarter_round(&mut working, 0, 5, 10, 15);
            quarter_round(&mut working, 1, 6, 11, 12);
            quarter_round(&mut working, 2, 7, 8, 13);
            quarter_round(&mut working, 3, 4, 9, 14);
        }

        let mut subkey = [0u8; 32];
        for i in 0..4 { subkey[4*i..4*i+4].copy_from_slice(&working[i].to_le_bytes()); }
        for i in 0..4 { subkey[16+4*i..16+4*i+4].copy_from_slice(&working[12+i].to_le_bytes()); }
        subkey
    }
}

mod poly1305 {
    use std::convert::TryInto;
    const P: u128 = u128::MAX - 4; // 2^128 - 5

    pub fn poly1305_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
        let r = clamp(&key[..16]);
        let s = u128::from_le_bytes(key[16..32].try_into().unwrap());
        let mut acc: u128 = 0;

        for chunk in msg.chunks(16) {
            let mut n: u128 = 0;
            for (i, &b) in chunk.iter().enumerate() {
                n |= (b as u128) << (8 * i);
            }
            if chunk.len() < 16 {
                n |= 1u128 << (8 * chunk.len());
            }
            acc = acc.wrapping_add(n) % P;
            acc = acc.wrapping_mul(r) % P;
        }

        acc = acc.wrapping_add(s);
        acc.to_le_bytes()
    }

    fn clamp(r: &[u8]) -> u128 {
        let mut t = [0u8; 16];
        t.copy_from_slice(&r[..16]);
        t[3]  &= 15;  t[7]  &= 15;  t[11] &= 15;  t[15] &= 15;
        t[4]  &= 252; t[8]  &= 252; t[12] &= 252;
        u128::from_le_bytes(t)
    }
}

mod aead {
    use crate::constant_time_eq;
    use crate::chacha20::{hchacha20, chacha20_block, chacha20_encrypt};
    use crate::poly1305::poly1305_mac;

    pub struct XChaCha20Poly1305 { key: [u8; 32] }

    impl XChaCha20Poly1305 {
        pub fn new(key: [u8; 32]) -> Self { Self { key } }

        pub fn encrypt_chunk(&self, nonce: &[u8; 24], pt: &[u8], aad: &[u8])
            -> (Vec<u8>, [u8; 16])
        {
            let mut hn = [0u8; 16]; hn.copy_from_slice(&nonce[..16]);
            let subkey = hchacha20(&self.key, &hn);

            let mut n12 = [0u8; 12]; n12[4..12].copy_from_slice(&nonce[16..24]);
            let block0 = chacha20_block(&subkey, 0, &n12);
            let ct     = chacha20_encrypt(&subkey, &n12, 1, pt);

            let mut mac_data = Vec::new();
            mac_data.extend_from_slice(aad);
            if aad.len() % 16 != 0 {
                mac_data.extend(vec![0u8; 16 - (aad.len() % 16)]);
            }
            mac_data.extend_from_slice(&ct);
            if ct.len() % 16 != 0 {
                mac_data.extend(vec![0u8; 16 - (ct.len() % 16)]);
            }
            mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
            mac_data.extend_from_slice(&(ct.len()  as u64).to_le_bytes());

            let mut full_key = [0u8; 32];
            full_key[..16].copy_from_slice(&block0[..16]);
            full_key[16..].copy_from_slice(&block0[16..32]);
            let tag = poly1305_mac(&full_key, &mac_data);

            (ct, tag)
        }

        pub fn decrypt_chunk(
            &self,
            nonce: &[u8; 24],
            ct: &[u8],
            aad: &[u8],
            tag: &[u8; 16]
        ) -> Result<Vec<u8>, ()>
        {
            let mut hn = [0u8; 16]; hn.copy_from_slice(&nonce[..16]);
            let subkey = hchacha20(&self.key, &hn);

            let mut n12 = [0u8; 12]; n12[4..12].copy_from_slice(&nonce[16..24]);
            let block0 = chacha20_block(&subkey, 0, &n12);

            let mut mac_data = Vec::new();
            mac_data.extend_from_slice(aad);
            if aad.len() % 16 != 0 {
                mac_data.extend(vec![0u8; 16 - (aad.len() % 16)]);
            }
            mac_data.extend_from_slice(ct);
            if ct.len() % 16 != 0 {
                mac_data.extend(vec![0u8; 16 - (ct.len() % 16)]);
            }
            mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
            mac_data.extend_from_slice(&(ct.len() as u64).to_le_bytes());

            let mut full_key = [0u8; 32];
            full_key[..16].copy_from_slice(&block0[..16]);
            full_key[16..].copy_from_slice(&block0[16..32]);
            let expected = poly1305_mac(&full_key, &mac_data);
            if !constant_time_eq(&expected, tag) {
                return Err(());
            }

            Ok(chacha20_encrypt(&subkey, &n12, 1, ct))
        }
    }
}

mod file_format {
    use std::io::{self, Read, Write};

    pub const CHUNK_SIZE: usize = 64 * 1024;
    pub const VERSION: u8 = 1;
    pub const MAGIC: [u8; 4] = *b"XCP1";

    pub struct Header { pub nonce: [u8; 24] }

    impl Header {
        pub fn new(nonce: [u8; 24]) -> Self { Self { nonce } }
        pub fn write(&self, w: &mut impl Write) -> io::Result<()> {
            w.write_all(&MAGIC)?;
            w.write_all(&[VERSION])?;
            w.write_all(&self.nonce)?;
            Ok(())
        }
        pub fn read(r: &mut impl Read) -> io::Result<Self> {
            let mut m = [0u8; 4]; r.read_exact(&mut m)?;
            if m != MAGIC {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Bad magic"));
            }
            let mut v = [0u8]; r.read_exact(&mut v)?;
            if v[0] != VERSION {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Bad ver"));
            }
            let mut n = [0u8; 24]; r.read_exact(&mut n)?;
            Ok(Header { nonce: n })
        }
    }

    pub fn increment_nonce(n: &mut [u8; 24]) {
        for i in (0..24).rev() {
            n[i] = n[i].wrapping_add(1);
            if n[i] != 0 { break; }
        }
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <keyfile> <file>", args[0]);
        std::process::exit(1);
    }
    let mut key = load_key(&args[1])?;
    let path = &args[2];

    let mut f = File::open(path)?;
    let mut buf = [0u8; 4];
    f.read_exact(&mut buf)?;

    let tmp = format!("{}.tmp", path);
    if buf == MAGIC {
        decrypt_file(&key, path, &tmp)?;
    } else {
        encrypt_file(&key, path, &tmp)?;
    }

    if fs::rename(&tmp, path).is_err() {
        fs::remove_file(path)?;
        fs::rename(&tmp, path)?;
    }

    // zeroize key
    zeroize::zeroize(&mut key);
    Ok(())
}

fn load_key(p: &str) -> io::Result<[u8; 32]> {
    let mut f = File::open(p)?;
    let mut b = [0u8; 32];
    f.read_exact(&mut b)?;
    Ok(b)
}

fn encrypt_file(key: &[u8; 32], in_path: &str, out_path: &str) -> io::Result<()> {
    let mut infile = File::open(in_path)?;
    let mut outfile = File::create(out_path)?;
    let cipher = aead::XChaCha20Poly1305::new(*key);

    let mut nonce = [0u8; 24];
    rng::fill_random(&mut nonce)?;
    file_format::Header::new(nonce).write(&mut outfile)?;

    let mut buf = vec![0u8; file_format::CHUNK_SIZE];
    loop {
        let n = infile.read(&mut buf)?;
        if n == 0 { break; }
        let (ct, tag) = cipher.encrypt_chunk(&nonce, &buf[..n], &[]);
        outfile.write_all(&ct)?;
        outfile.write_all(&tag)?;
        file_format::increment_nonce(&mut nonce);
    }
    Ok(())
}

fn decrypt_file(key: &[u8; 32], in_path: &str, out_path: &str) -> io::Result<()> {
    let mut infile = File::open(in_path)?;
    let mut outfile = File::create(out_path)?;
    let cipher = aead::XChaCha20Poly1305::new(*key);

    let header = file_format::Header::read(&mut infile)?;
    let mut nonce = header.nonce;
    let mut buf = vec![0u8; file_format::CHUNK_SIZE + 16];

    loop {
        let n = infile.read(&mut buf)?;
        if n == 0 { break; }
        if n < 16 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Missing tag"));
        }
        let bytes = &buf[..n];
        let (ct, tag) = bytes.split_at(n - 16);
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);
        let pt = cipher.decrypt_chunk(&nonce, ct, &[], &tag_arr)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Auth failure"))?;
        outfile.write_all(&pt)?;
        file_format::increment_nonce(&mut nonce);
    }
    Ok(())
}

