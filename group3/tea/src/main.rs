use std::env;
use std::fs;
use std::num::ParseIntError;
use std::process;

const DELTA: u32 = 0x9E3779B9;
const ROUNDS: usize = 32;

fn tea_encrypt(v: &mut [u32; 2], k: &[u32; 4]) {
    let mut v0 = v[0];
    let mut v1 = v[1];
    let mut sum: u32 = 0;
    for _ in 0..ROUNDS {
        sum = sum.wrapping_add(DELTA);
        v0 = v0.wrapping_add(
            ((v1 << 4).wrapping_add(k[0]))
            ^ (v1.wrapping_add(sum))
            ^ ((v1 >> 5).wrapping_add(k[1]))
        );
        v1 = v1.wrapping_add(
            ((v0 << 4).wrapping_add(k[2]))
            ^ (v0.wrapping_add(sum))
            ^ ((v0 >> 5).wrapping_add(k[3]))
        );
    }
    v[0] = v0;
    v[1] = v1;
}

fn tea_decrypt(v: &mut [u32; 2], k: &[u32; 4]) {
    let mut v0 = v[0];
    let mut v1 = v[1];
    let mut sum = DELTA.wrapping_mul(ROUNDS as u32);
    for _ in 0..ROUNDS {
        v1 = v1.wrapping_sub(
            ((v0 << 4).wrapping_add(k[2]))
            ^ (v0.wrapping_add(sum))
            ^ ((v0 >> 5).wrapping_add(k[3]))
        );
        v0 = v0.wrapping_sub(
            ((v1 << 4).wrapping_add(k[0]))
            ^ (v1.wrapping_add(sum))
            ^ ((v1 >> 5).wrapping_add(k[1]))
        );
        sum = sum.wrapping_sub(DELTA);
    }
    v[0] = v0;
    v[1] = v1;
}

fn parse_u32_hex(s: &str) -> Result<u32, ParseIntError> {
    u32::from_str_radix(s.trim_start_matches("0x"), 16)
}

fn process_buffer(buf: &mut [u8], k: &[u32; 4], encrypt: bool) {
    for chunk in buf.chunks_mut(8) {
        let mut v = [0u32; 2];
        for i in 0..2 {
            let offset = i * 4;
            v[i] = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        if encrypt {
            tea_encrypt(&mut v, k);
        } else {
            tea_decrypt(&mut v, k);
        }
        for i in 0..2 {
            let bytes = v[i].to_be_bytes();
            let offset = i * 4;
            chunk[offset..offset + 4].copy_from_slice(&bytes);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 7 {
        eprintln!(
            "Usage: {} <encrypt|decrypt> k0 k1 k2 k3 <filepath>",
            args[0]
        );
        process::exit(1);
    }
    let mode = &args[1];
    let key_vec: Vec<u32> = args[2..6]
        .iter()
        .map(|s| parse_u32_hex(s).expect("Invalid key hex"))
        .collect();
    let key_arr = [key_vec[0], key_vec[1], key_vec[2], key_vec[3]];
    let filepath = &args[6];

    let mut buf = fs::read(filepath).unwrap_or_else(|e| {
        eprintln!("Failed to read file: {}", e);
        process::exit(1);
    });
    let pad_len = (8 - (buf.len() % 8)) % 8;
    buf.extend(vec![0u8; pad_len]);

    let encrypting = match mode.as_str() {
        "encrypt" => true,
        "decrypt" => false,
        _ => {
            eprintln!("Mode must be 'encrypt' or 'decrypt'");
            process::exit(1);
        }
    };

    process_buffer(&mut buf, &key_arr, encrypting);

    fs::write(filepath, &buf).unwrap_or_else(|e| {
        eprintln!("Failed to write file: {}", e);
        process::exit(1);
    });

    println!("{} complete: {}", mode, filepath);
}
