use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;

use chacha20poly1305::{
    XChaCha20Poly1305,  // AEAD cipher
    XNonce,             // 24-byte nonce for XChaCha20
    aead::{AeadCore, KeyInit, AeadInPlace},
};
use argon2::{Argon2, Algorithm, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword::read_password;
use zeroize::Zeroize;

/// Magic header to identify encrypted files (8 bytes)
const MAGIC: &[u8; 8] = b"XCH20ENC";

/// Maximum file size supported (5 GiB)
const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024 * 1024;

fn main() -> std::io::Result<()> {
    // Parse command-line arguments (expect exactly one filename)
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <FILE>", args.get(0).map(|s| s.as_str()).unwrap_or("xcrypt"));
        std::process::exit(1);
    }
    let filename = &args[1];

    // Restrict operation to files in the same directory as the executable
    let exe_dir = env::current_exe().ok()
        .and_then(|p| p.parent().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    let input_path = fs::canonicalize(PathBuf::from(filename))?;
    if !input_path.starts_with(&exe_dir) {
        eprintln!("Error: File path is not allowed (must be in program directory)");
        std::process::exit(1);
    }

    // Open and read the entire input file into memory
    let metadata = fs::metadata(&input_path)?;
    let file_size = metadata.len();
    if file_size > MAX_FILE_SIZE {
        eprintln!("Error: File too large (exceeds 5GB limit)");
        std::process::exit(1);
    }
    let mut file = File::open(&input_path)?;
    let mut buffer = Vec::with_capacity(file_size as usize + 16);
    file.read_to_end(&mut buffer)?;

    // Determine mode by checking magic header
    let is_encrypted = buffer.len() >= MAGIC.len() && &buffer[..MAGIC.len()] == MAGIC;

    // Prompt for password (hidden input).
    if is_encrypted {
        print!("Enter password to decrypt: ");
    } else {
        print!("Enter password to encrypt: ");
    }
    io::stdout().flush()?;

    let password = match read_password() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Error: Failed to read password");
            std::process::exit(1);
        }
    };

    // For encryption, confirm password
    let mut password2 = String::new();
    if !is_encrypted {
        print!("Confirm password: ");
        io::stdout().flush()?;
        password2 = match read_password() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Error: Failed to read password");
                std::process::exit(1);
            }
        };
        if password != password2 {
            eprintln!("Error: Passwords do not match");
            std::process::exit(1);
        }
    }

    // Convert password to byte vector and clear the original strings
    let mut password_bytes = password.into_bytes();
    password2.zeroize(); // Securely erase the second password
    // Remove trailing whitespace/newline
    while password_bytes.last().map_or(false, |b| b.is_ascii_whitespace()) {
        password_bytes.pop();
    }

    // Set up Argon2id with strong parameters (64 MiB memory, 3 iterations, single-thread)
    let params = Params::new(
        64 * 1024, // 64 MiB memory cost
        3,         // iterations
        1,         // parallelism (single-thread)
        None
    ).expect("Invalid Argon2 parameters");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    if !is_encrypted {
        // Encryption mode

        // Generate random salt (16 bytes)
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        // Derive encryption key
        let mut key = [0u8; 32];
        if let Err(e) = argon2.hash_password_into(&password_bytes, &salt, &mut key) {
            password_bytes.zeroize();
            eprintln!("Error: Key derivation failed: {}", e);
            std::process::exit(1);
        }

        let cipher = XChaCha20Poly1305::new((&key).into());
        // Generate a random 24-byte nonce
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Encrypt in-place
        buffer.reserve(16); // space for Poly1305 tag
        if let Err(_) = cipher.encrypt_in_place(&nonce, b"", &mut buffer) {
            key.zeroize();
            password_bytes.zeroize();
            eprintln!("Error: Encryption failed");
            std::process::exit(1);
        }

        // Write Magic + salt + nonce + ciphertext to a new temp file
        let mut out_path = input_path.clone();
        out_path.set_file_name(format!(
            "{}.tmp",
            input_path.file_name().unwrap().to_string_lossy()
        ));
        let mut tmp_file = match OpenOptions::new().write(true).create_new(true).open(&out_path) {
            Ok(f) => f,
            Err(e) => {
                key.zeroize();
                password_bytes.zeroize();
                eprintln!("Error: Cannot create temporary file: {}", e);
                std::process::exit(1);
            }
        };
        if let Err(e) = tmp_file
            .write_all(MAGIC)
            .and_then(|()| tmp_file.write_all(&salt))
            .and_then(|()| tmp_file.write_all(nonce.as_slice()))
            .and_then(|()| tmp_file.write_all(&buffer))
        {
            let _ = fs::remove_file(&out_path);
            key.zeroize();
            password_bytes.zeroize();
            eprintln!("Error: Failed to write output file: {}", e);
            std::process::exit(1);
        }
        tmp_file.flush()?;
        tmp_file.sync_all()?;

        // Atomically rename temp file over the original file
        if let Err(e) = fs::rename(&out_path, &input_path) {
            let _ = fs::remove_file(&out_path);
            key.zeroize();
            password_bytes.zeroize();
            eprintln!("Error: Failed to finalize write: {}", e);
            std::process::exit(1);
        }
        // Sync directory
        if let Some(dir) = input_path.parent() {
            if let Ok(dir_fd) = File::open(dir) {
                let _ = dir_fd.sync_all();
            }
        }

        // Zero sensitive data
        key.zeroize();
        password_bytes.zeroize();
        buffer.zeroize();

        // Exit quietly
        Ok(())

    } else {
        // Decryption mode
        if buffer.len() < MAGIC.len() + 16 + 24 + 16 {
            // Header (8) + salt (16) + nonce (24) + tag (16) => 64 bytes min
            password_bytes.zeroize();
            eprintln!("Error: File is too short or corrupted");
            std::process::exit(1);
        }

        // Copy salt into a local array to avoid borrow checker issues
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&buffer[MAGIC.len()..MAGIC.len()+16]);

        // Copy nonce into a local array
        let mut nonce_bytes = [0u8; 24];
        nonce_bytes.copy_from_slice(&buffer[MAGIC.len()+16..MAGIC.len()+16+24]);

        let nonce = XNonce::from_slice(&nonce_bytes);

        // Derive key
        let mut key = [0u8; 32];
        if let Err(_) = argon2.hash_password_into(&password_bytes, &salt, &mut key) {
            password_bytes.zeroize();
            eprintln!("Error: Key derivation failed (out of memory?)");
            std::process::exit(1);
        }
        let cipher = XChaCha20Poly1305::new((&key).into());

        // Remove header from the buffer
        buffer.drain(0..MAGIC.len()+16+24);

        // Decrypt in-place
        if cipher.decrypt_in_place(nonce, b"", &mut buffer).is_err() {
            key.zeroize();
            password_bytes.zeroize();
            buffer.zeroize();
            eprintln!("Error: Decryption failed (wrong password or corrupt file)");
            std::process::exit(1);
        }

        // buffer now holds the plaintext
        // Write it out atomically
        let mut out_path = input_path.clone();
        out_path.set_file_name(format!(
            "{}.tmp",
            input_path.file_name().unwrap().to_string_lossy()
        ));
        let mut tmp_file = match OpenOptions::new().write(true).create_new(true).open(&out_path) {
            Ok(f) => f,
            Err(e) => {
                key.zeroize();
                password_bytes.zeroize();
                buffer.zeroize();
                eprintln!("Error: Cannot create temporary file: {}", e);
                std::process::exit(1);
            }
        };
        if let Err(e) = tmp_file.write_all(&buffer) {
            let _ = fs::remove_file(&out_path);
            key.zeroize();
            password_bytes.zeroize();
            buffer.zeroize();
            eprintln!("Error: Failed to write output file: {}", e);
            std::process::exit(1);
        }
        tmp_file.flush()?;
        tmp_file.sync_all()?;

        if let Err(e) = fs::rename(&out_path, &input_path) {
            let _ = fs::remove_file(&out_path);
            key.zeroize();
            password_bytes.zeroize();
            buffer.zeroize();
            eprintln!("Error: Failed to finalize write: {}", e);
            std::process::exit(1);
        }
        if let Some(dir) = input_path.parent() {
            if let Ok(dir_fd) = File::open(dir) {
                let _ = dir_fd.sync_all();
            }
        }

        // Zero sensitive data
        key.zeroize();
        password_bytes.zeroize();
        buffer.zeroize();

        Ok(())
    }
}



