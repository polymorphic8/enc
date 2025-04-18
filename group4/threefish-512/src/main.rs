//[package]
//name = "threefish_cli"
//version = "0.1.0"
//edition = "2021"
//
//[dependencies]
//clap = { version = "4.2", features = ["derive"] }
//threefish = "0.5.2"
//rand = "0.8"
//zeroize = "1.5"
//anyhow = "1.0"
//log = "0.4"
//env_logger = "0.10"
//indicatif = "0.17"

use std::{
    fs::{File, OpenOptions, remove_file, rename},
    io::{Read, Write},
    path::Path,
};
use clap::{Parser, Subcommand};
use rand::{RngCore, rngs::OsRng};
use threefish::Threefish512;
use zeroize::Zeroize;
use anyhow::{anyhow, Result};

const MAGIC: &[u8;4] = b"T5FS";
const VERSION: u8 = 1;
// 512-bit (64-byte) key
const DEFAULT_KEY: [u8;64] = [0x42; 64];

#[derive(Parser)]
#[command(author, version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate default key.key
    Keygen,
    /// Encrypt file in-place
    Encrypt { path: String },
    /// Decrypt file in-place
    Decrypt { path: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen    => keygen(),
        Commands::Encrypt { path } => process(&path, true),
        Commands::Decrypt { path } => process(&path, false),
    }
}

fn load_key() -> Result<[u8;64]> {
    let path = Path::new("key.key");
    if !path.exists() {
        return Err(anyhow!("No key.key found. Run `threefish_cli keygen` first."));
    }
    let mut file = File::open(path)?;
    let mut key = [0u8;64];
    file.read_exact(&mut key)?;
    Ok(key)
}

fn keygen() -> Result<()> {
    let path = Path::new("key.key");
    if path.exists() {
        return Err(anyhow!("key.key already exists"));
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&DEFAULT_KEY)?;
    Ok(())
}

fn process(path_str: &str, encrypt: bool) -> Result<()> {
    let in_path  = Path::new(path_str);
    let tmp_path = in_path.with_extension("tmp");
    let mut infile  = File::open(in_path)?;
    let mut outfile = File::create(&tmp_path)?;
    let mut key = load_key()?;

    // Header handling
    let nonce = if encrypt {
        outfile.write_all(MAGIC)?;
        outfile.write_all(&[VERSION])?;
        let n = OsRng.next_u64();
        outfile.write_all(&n.to_le_bytes())?;
        n
    } else {
        let mut hdr = [0u8; 4 + 1 + 8];
        infile.read_exact(&mut hdr)?;
        if &hdr[0..4] != MAGIC { return Err(anyhow!("Invalid format")); }
        if hdr[4] != VERSION { return Err(anyhow!("Unsupported version")); }
        let mut nb = [0u8;8];
        nb.copy_from_slice(&hdr[5..13]);
        u64::from_le_bytes(nb)
    };

    // Stream process in 64-byte blocks
    let mut buffer = [0u8;64];
    let mut block_index = 0u64;
    loop {
        let n = infile.read(&mut buffer)?;
        if n == 0 { break; }
        let keystream = generate_keystream_block(&key, nonce, block_index);
        for i in 0..n {
            buffer[i] ^= keystream[i];
        }
        outfile.write_all(&buffer[..n])?;
        block_index += 1;
    }
    key.zeroize();

    // Atomic replace
    remove_file(in_path)?;
    rename(tmp_path, in_path)?;
    Ok(())
}

fn generate_keystream_block(key: &[u8;64], nonce: u64, block_index: u64) -> [u8;64] {
    // Interpret key as 8×u64
    let key_u64: &[u64;8] = unsafe { &*(key.as_ptr() as *const [u64;8]) };
    let tweak = [nonce, block_index];
    let mut block = [0u64;8];
    block[0] = block_index;
    let cipher = Threefish512::new_with_tweak_u64(key_u64, &tweak);
    cipher.encrypt_block_u64(&mut block);
    unsafe { std::mem::transmute(block) }
}
