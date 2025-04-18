use aes_gcm::aead::{Aead, KeyInit, generic_array::GenericArray};
use aes_gcm::Aes256Gcm;
use rand::RngCore;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

/// Helper to build a temporary filename next to the original file.
/// Example: if `original` is "data.bin", we might create "data.bin.tmp".
fn build_temp_filename(original: &str) -> PathBuf {
    let mut path = PathBuf::from(original);
    // Append an extension or suffix for the tmp file
    path.set_extension("tmp");
    path
}

fn main() {
    // =============================
    // Hard-coded 32-byte AES key
    // Replace with your own key!
    // =============================
    let key_bytes: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03,  // <-- example
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F
    ];

    // Initialize cipher
    let key = GenericArray::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} --E|--D <filename>", args[0]);
        process::exit(1);
    }

    let mode = &args[1];
    let filename = &args[2];

    // Read the file contents fully
    let file_content = fs::read(filename).unwrap_or_else(|_| {
        eprintln!("Failed to read file: {}", filename);
        process::exit(1);
    });

    if mode == "--E" {
        // ENCRYPT
        let mut rng = rand::thread_rng();
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, file_content.as_ref())
            .expect("Encryption failure!");

        // We'll store the nonce (12 bytes) + ciphertext in the output file.
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        // Write to a .tmp file in the same directory
        let temp_path = build_temp_filename(filename);
        fs::write(&temp_path, &output).unwrap_or_else(|_| {
            eprintln!("Failed to write temporary file: {:?}", temp_path);
            process::exit(1);
        });

        // Delete the original file (to avoid rename errors on Windows),
        // then rename/move the .tmp to the original filename.
        fs::remove_file(filename).ok(); // Ignore errors if file doesn't exist
        fs::rename(&temp_path, filename).unwrap_or_else(|_| {
            eprintln!("Failed to rename temp file to {:?}", filename);
            process::exit(1);
        });

        println!("File encrypted successfully, overwriting: {}", filename);
    } else if mode == "--D" {
        // DECRYPT
        if file_content.len() < 12 + 16 {
            eprintln!("File too short to be valid AES-GCM data");
            process::exit(1);
        }

        // First 12 bytes are the nonce
        let nonce_bytes = &file_content[..12];
        // The remainder is the ciphertext (including the 16-byte auth tag)
        let ciphertext = &file_content[12..];

        let nonce = GenericArray::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .expect("Decryption failure! Possibly wrong key or corrupted data.");

        // Write to a .tmp file
        let temp_path = build_temp_filename(filename);
        fs::write(&temp_path, &plaintext).unwrap_or_else(|_| {
            eprintln!("Failed to write temporary file: {:?}", temp_path);
            process::exit(1);
        });

        // Delete original, then rename .tmp to final
        fs::remove_file(filename).ok();
        fs::rename(&temp_path, filename).unwrap_or_else(|_| {
            eprintln!("Failed to rename temp file to {:?}", filename);
            process::exit(1);
        });

        println!("File decrypted successfully, overwriting: {}", filename);
    } else {
        eprintln!("Unknown mode: '{}'. Use --E or --D.", mode);
        process::exit(1);
    }
}

