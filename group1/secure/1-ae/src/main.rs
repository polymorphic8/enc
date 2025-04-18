

// [package]
// name = "xae"
// version = "1.0.0"
// edition = "2021"


// [dependencies]
// aes-gcm-siv = "0.10"
// rand = "0.8"
// tempfile = "3.6"
// anyhow = "1"


use anyhow::{anyhow, Result};
use aes_gcm_siv::aead::{Aead, NewAead};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;

const MAGIC_HEADER: &[u8] = b"MYAESGCM";
const NONCE_SIZE: usize = 12;

fn main() -> Result<()> {
    // Get the file path from the command line
    let file_path = match env::args().nth(1) {
        Some(path) => PathBuf::from(path),
        None => {
            eprintln!("Usage: ae <file_path>");
            std::process::exit(1);
        }
    };

    // Load the 32-byte key from "1.key" in the same directory as the executable.
    let exe_dir = env::current_exe()?.parent().unwrap().to_path_buf();
    let key_path = exe_dir.join("1.key");
    let key_bytes = fs::read(&key_path)?;
    if key_bytes.len() != 32 {
        return Err(anyhow!("Key file must be exactly 32 bytes."));
    }

    // Build the cipher
    let cipher = Aes256GcmSiv::new_from_slice(&key_bytes)
        .map_err(|_| anyhow!("Invalid key length for AES-256-GCM-SIV"))?;

    // Read the entire file
    let mut file_data = fs::read(&file_path)?;

    // Check if the file is encrypted
    let is_encrypted = file_data.starts_with(MAGIC_HEADER);

    if is_encrypted {
        // DECRYPT

        // Remove magic header
        file_data.drain(0..MAGIC_HEADER.len());
        if file_data.len() < NONCE_SIZE {
            return Err(anyhow!("File is missing the nonce or is corrupted."));
        }

        // Extract nonce & ciphertext
        let nonce_bytes = file_data.drain(0..NONCE_SIZE).collect::<Vec<u8>>();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = file_data;

        // Decrypt (map aes_gcm_siv error to anyhow)
        let decrypted = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| anyhow!("Decryption failed: {:?}", e))?;

        // Overwrite the original file contents atomically
        let mut temp_file = NamedTempFile::new_in(file_path.parent().unwrap())?;
        temp_file.write_all(&decrypted)?;
        temp_file.flush()?;
        fs::rename(temp_file.path(), &file_path)?;
    } else {
        // ENCRYPT

        // Generate a random 12-byte nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt (map aes_gcm_siv error to anyhow)
        let ciphertext = cipher
            .encrypt(nonce, file_data.as_ref())
            .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

        // Write [ MAGIC_HEADER | NONCE | CIPHERTEXT ] atomically
        let mut temp_file = NamedTempFile::new_in(file_path.parent().unwrap())?;
        temp_file.write_all(MAGIC_HEADER)?;
        temp_file.write_all(&nonce_bytes)?;
        temp_file.write_all(&ciphertext)?;
        temp_file.flush()?;
        fs::rename(temp_file.path(), &file_path)?;
    }

    Ok(())
}

