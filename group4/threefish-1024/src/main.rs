use std::{fs::{File, remove_file, rename}, io::{Read, Write}, path::Path};
use clap::{Parser, Subcommand};
use rand::random;
use threefish::Threefish1024;
use zeroize::Zeroize;
use anyhow::{anyhow, Result};

const MAGIC: &[u8; 4] = b"T1FS";
const VERSION: u8 = 1;

#[derive(Parser)]
#[command(author, version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt file in-place
    Encrypt { path: String },
    /// Decrypt file in-place
    Decrypt { path: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encrypt { path } => process(&path, true),
        Commands::Decrypt { path } => process(&path, false),
    }
}

fn load_key() -> Result<[u8; 128]> {
    let path = Path::new("key.key");
    if !path.exists() {
        return Err(anyhow!("No key.key found. Generate a key externally and place it in key.key"));
    }
    let meta = path.metadata()?;
    if meta.len() != 128 {
        return Err(anyhow!(
            "Invalid key length: expected 128 bytes, got {} bytes",
            meta.len()
        ));
    }
    let mut file = File::open(path)?;
    let mut key = [0u8; 128];
    file.read_exact(&mut key)?;
    Ok(key)
}

fn process(path_str: &str, encrypt: bool) -> Result<()> {
    // load key first
    let mut key = load_key()?;

    let in_path = Path::new(path_str);
    let tmp_path = in_path.with_extension("tmp");
    let mut infile = File::open(in_path)?;
    let mut outfile = File::create(&tmp_path)?;

    // Header handling
    let nonce = if encrypt {
        outfile.write_all(MAGIC)?;
        outfile.write_all(&[VERSION])?;
        let n: u64 = random();
        outfile.write_all(&n.to_le_bytes())?;
        n
    } else {
        let mut hdr = [0u8; 4 + 1 + 8];
        infile.read_exact(&mut hdr)?;
        if &hdr[0..4] != MAGIC { return Err(anyhow!("Invalid format")); }
        if hdr[4] != VERSION { return Err(anyhow!("Unsupported version")); }
        let mut nb = [0u8; 8];
        nb.copy_from_slice(&hdr[5..]);
        u64::from_le_bytes(nb)
    };

    // Stream process in 128-byte blocks
    let mut buffer = [0u8; 128];
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

fn generate_keystream_block(key: &[u8; 128], nonce: u64, block_index: u64) -> [u8; 128] {
    let key_u64: &[u64; 16] = unsafe { &*(key.as_ptr() as *const [u64; 16]) };
    let tweak = [nonce, block_index];
    let mut block = [0u64; 16];
    block[0] = block_index;
    let cipher = Threefish1024::new_with_tweak_u64(key_u64, &tweak);
    cipher.encrypt_block_u64(&mut block);
    unsafe { std::mem::transmute(block) }
}
