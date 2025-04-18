// src/main.rs
use aes_gcm_siv::aead::{Aead, KeyInit, generic_array::GenericArray};
use aes_gcm_siv::Aes256GcmSiv;
use rand::RngCore;
use std::{env, fs, process, path::PathBuf};

/// Unique prefix to mark files as encrypted with AES-256-GCM-SIV
const MAGIC: &[u8] = b"AES256-GCM-SIV";

/// Build a `.tmp` sibling next to the given filename
fn build_temp_filename(original: &str) -> PathBuf {
    let mut path = PathBuf::from(original);
    path.set_extension("tmp");
    path
}

fn main() {
    let key_bytes: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03,  // example; replace with your own key!
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F,
    ];
    let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key_bytes));

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <filename>", args[0]);
        process::exit(1);
    }
    let filename = &args[1];
    let file_content = fs::read(filename).unwrap_or_else(|_| {
        eprintln!("Failed to read file: {}", filename);
        process::exit(1);
    });

    if file_content.starts_with(MAGIC) {
        // Decrypt path
        let data = &file_content[MAGIC.len()..];
        if data.len() < 12 + 16 {
            eprintln!("File too short to be valid AES‑GCM‑SIV data");
            process::exit(1);
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let plaintext = cipher
            .decrypt(
                GenericArray::from_slice(nonce_bytes),
                ciphertext.as_ref(),
            )
            .expect("Decryption failed; wrong key or corrupted file");

        let tmp = build_temp_filename(filename);
        fs::write(&tmp, &plaintext).unwrap_or_else(|_| {
            eprintln!("Failed to write temporary file: {:?}", tmp);
            process::exit(1);
        });
        fs::remove_file(filename).ok();
        fs::rename(&tmp, filename).unwrap_or_else(|_| {
            eprintln!("Failed to overwrite original with decrypted data");
            process::exit(1);
        });
        println!("File decrypted successfully: {}", filename);
    } else {
        // Encrypt path
        let mut rng = rand::rng();
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);

        let ciphertext = cipher
            .encrypt(
                GenericArray::from_slice(&nonce),
                file_content.as_ref(),
            )
            .expect("Encryption failure!");

        let mut output = Vec::with_capacity(MAGIC.len() + 12 + ciphertext.len());
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        let tmp = build_temp_filename(filename);
        fs::write(&tmp, &output).unwrap_or_else(|_| {
            eprintln!("Failed to write temporary file: {:?}", tmp);
            process::exit(1);
        });
        fs::remove_file(filename).ok();
        fs::rename(&tmp, filename).unwrap_or_else(|_| {
            eprintln!("Failed to overwrite original with encrypted data");
            process::exit(1);
        });
        println!("File encrypted successfully: {}", filename);
    }
}
