use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;

use aes_gcm_siv::{
    aead::{Aead, NewAead, generic_array::GenericArray},
    Aes256GcmSiv,  // AES-256 in GCM-SIV mode
};
use argon2::{Argon2, Algorithm, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword::read_password;
use zeroize::Zeroize;

/// Magic header to identify AES-256-GCM-SIV encrypted files (8 bytes).
/// Adjust if you want a different marker, or preserve old magic if you wish.
const MAGIC: &[u8; 8] = b"AES256SV";

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
    let mut buffer = Vec::with_capacity(file_size as usize);
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

    // Remove trailing whitespace/newline from password
    while password_bytes.last().map_or(false, |b| b.is_ascii_whitespace()) {
        password_bytes.pop();
    }

    // Argon2id with strong parameters (64 MiB memory, 3 iterations, single-thread)
    let params = Params::new(
        64 * 1024, // 64 MiB in KiB
        3,
        1,
        None
    ).expect("Invalid Argon2 parameters");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    if !is_encrypted {
        // --------------------
        // ENCRYPTION MODE
        // --------------------

        // Generate random salt (16 bytes)
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        // Derive a 32-byte (256-bit) key from the password
        let mut key_bytes = [0u8; 32];
        if let Err(e) = argon2.hash_password_into(&password_bytes, &salt, &mut key_bytes) {
            password_bytes.zeroize();
            eprintln!("Error: Key derivation failed: {}", e);
            std::process::exit(1);
        }

        // Create AES-256-GCM-SIV cipher instance
        // 1) Build the cipher with the derived key
        let cipher = Aes256GcmSiv::new_from_slice(&key_bytes)
            .expect("Error: invalid key length for AES-256-GCM-SIV");

        // Generate a random 12-byte nonce for AES-GCM-SIV
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        // Encrypt: returns Vec<u8> containing ciphertext + 16-byte auth tag appended
        let ciphertext = match cipher.encrypt(nonce, buffer.as_slice()) {
            Ok(ct) => ct,
            Err(_) => {
                key_bytes.zeroize();
                password_bytes.zeroize();
                eprintln!("Error: Encryption failed");
                std::process::exit(1);
            }
        };

        // Write Magic + salt + nonce + ciphertext to a new temp file
        let mut out_path = input_path.clone();
        out_path.set_file_name(format!(
            "{}.tmp",
            input_path.file_name().unwrap().to_string_lossy()
        ));
        let mut tmp_file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&out_path)
        {
            Ok(f) => f,
            Err(e) => {
                key_bytes.zeroize();
                password_bytes.zeroize();
                eprintln!("Error: Cannot create temporary file: {}", e);
                std::process::exit(1);
            }
        };

        if let Err(e) = tmp_file
            .write_all(MAGIC)
            .and_then(|()| tmp_file.write_all(&salt))
            .and_then(|()| tmp_file.write_all(&nonce_bytes))
            .and_then(|()| tmp_file.write_all(&ciphertext))
        {
            let _ = fs::remove_file(&out_path);
            key_bytes.zeroize();
            password_bytes.zeroize();
            eprintln!("Error: Failed to write output file: {}", e);
            std::process::exit(1);
        }
        tmp_file.flush()?;
        tmp_file.sync_all()?;

        // Atomically rename temp file over the original file
        if let Err(e) = fs::rename(&out_path, &input_path) {
            let _ = fs::remove_file(&out_path);
            key_bytes.zeroize();
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
        key_bytes.zeroize();
        password_bytes.zeroize();
        buffer.zeroize();

        Ok(())
    } else {
        // --------------------
        // DECRYPTION MODE
        // --------------------

        // Minimal length check: 8 (MAGIC) + 16 (SALT) + 12 (NONCE) + 16 (TAG) => 52 bytes
        if buffer.len() < MAGIC.len() + 16 + 12 + 16 {
            password_bytes.zeroize();
            eprintln!("Error: File is too short or corrupted");
            std::process::exit(1);
        }

        // Copy salt
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&buffer[MAGIC.len()..MAGIC.len() + 16]);

        // Copy nonce
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&buffer[MAGIC.len() + 16..MAGIC.len() + 16 + 12]);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        // Derive key
        let mut key_bytes = [0u8; 32];
        if let Err(_) = argon2.hash_password_into(&password_bytes, &salt, &mut key_bytes) {
            password_bytes.zeroize();
            eprintln!("Error: Key derivation failed (out of memory?)");
            std::process::exit(1);
        }

        let cipher = Aes256GcmSiv::new_from_slice(&key_bytes)
            .expect("Error: invalid key length for AES-256-GCM-SIV");

        // Extract ciphertext portion
        let ciphertext = &buffer[MAGIC.len() + 16 + 12..];

        // Decrypt
        let plaintext = match cipher.decrypt(nonce, ciphertext) {
            Ok(pt) => pt,
            Err(_) => {
                key_bytes.zeroize();
                password_bytes.zeroize();
                buffer.zeroize();
                eprintln!("Error: Decryption failed (wrong password or corrupt file)");
                std::process::exit(1);
            }
        };

        // Write plaintext to a temp file
        let mut out_path = input_path.clone();
        out_path.set_file_name(format!(
            "{}.tmp",
            input_path.file_name().unwrap().to_string_lossy()
        ));
        let mut tmp_file = match OpenOptions::new().write(true).create_new(true).open(&out_path) {
            Ok(f) => f,
            Err(e) => {
                key_bytes.zeroize();
                password_bytes.zeroize();
                buffer.zeroize();
                eprintln!("Error: Cannot create temporary file: {}", e);
                std::process::exit(1);
            }
        };

        if let Err(e) = tmp_file.write_all(&plaintext) {
            let _ = fs::remove_file(&out_path);
            key_bytes.zeroize();
            password_bytes.zeroize();
            buffer.zeroize();
            eprintln!("Error: Failed to write output file: {}", e);
            std::process::exit(1);
        }
        tmp_file.flush()?;
        tmp_file.sync_all()?;

        // Atomically rename
        if let Err(e) = fs::rename(&out_path, &input_path) {
            let _ = fs::remove_file(&out_path);
            key_bytes.zeroize();
            password_bytes.zeroize();
            buffer.zeroize();
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
        key_bytes.zeroize();
        password_bytes.zeroize();
        buffer.zeroize();

        Ok(())
    }
}


