use anyhow::{anyhow, Result};
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use clap::{Arg, ArgAction, Command};
use rand::RngCore;
use std::fs;
use std::io::Write;
use std::path::Path;

const SALT: &[u8] = b"CHANGE_ME_BEFORE_PRODUCTION";
const KEY_FILE_NAME: &str = "p.bin";

fn main() -> Result<()> {
    let matches = Command::new("chacha20_cli")
        .version("0.1.0")
        .about("Simple XChaCha20-Poly1305 encryption CLI.")
        .author("Your Name <you@example.com>")
        .arg(
            Arg::new("encrypt")
                .long("E")
                .help("Encrypt a file")
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("decrypt")
                .long("D")
                .help("Decrypt a file")
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("overwrite")
                .long("over")
                .help("Encrypt or decrypt in-place with an atomic overwrite")
                .required(false)
                .num_args(1)
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("keygen")
                .long("keygen")
                .help("Generate a key file deterministically from a password")
                .required(false)
                .num_args(1)
                .action(ArgAction::Set),
        )
        .arg(Arg::new("input").help("Input file").required(false).index(1))
        .arg(Arg::new("output").help("Output file").required(false).index(2))
        .get_matches();

    let is_encrypt = matches.get_flag("encrypt");
    let is_decrypt = matches.get_flag("decrypt");
    let overwrite_file = matches.get_one::<String>("overwrite");
    let keygen_password = matches.get_one::<String>("keygen");
    let input = matches.get_one::<String>("input");
    let output = matches.get_one::<String>("output");

    if let Some(password) = keygen_password {
        deterministic_keygen(password)?;
        println!("Key file '{}' generated from the given password.", KEY_FILE_NAME);
        return Ok(());
    }

    if !(is_encrypt || is_decrypt || overwrite_file.is_some()) {
        return Err(anyhow!(
            "No valid operation specified. Use --E, --D, or --over. See --help for usage."
        ));
    }

    if let Some(file_to_overwrite) = overwrite_file {
        if is_encrypt && is_decrypt {
            return Err(anyhow!("Cannot specify both --E and --D in overwrite mode."));
        }
        let encrypt_mode = if is_encrypt {
            true
        } else if is_decrypt {
            false
        } else {
            true
        };

        atomic_overwrite(file_to_overwrite, encrypt_mode)?;
        println!(
            "{} in-place completed for '{}'.",
            if encrypt_mode { "Encryption" } else { "Decryption" },
            file_to_overwrite
        );
        return Ok(());
    }

    let input = input.ok_or_else(|| anyhow!("No input file provided."))?;
    let output = output.ok_or_else(|| anyhow!("No output file provided."))?;

    if is_encrypt && is_decrypt {
        return Err(anyhow!(
            "Cannot specify both --E and --D simultaneously. Use only one."
        ));
    }

    if is_encrypt {
        encrypt_file(input, output)?;
        println!("Encrypted '{}' to '{}'.", input, output);
    } else if is_decrypt {
        decrypt_file(input, output)?;
        println!("Decrypted '{}' to '{}'.", input, output);
    } else {
        return Err(anyhow!("No operation specified. Use --E, --D, or --over."));
    }

    Ok(())
}

/// Load the key from p.bin. Returns an error if the file is missing or invalid.
fn load_key() -> Result<Key> {
    let key_data = fs::read(KEY_FILE_NAME)
        .map_err(|_| anyhow!("Could not read key file '{}'", KEY_FILE_NAME))?;

    if key_data.len() != 32 {
        return Err(anyhow!(
            "Key file '{}' is invalid. Expected 32 bytes.",
            KEY_FILE_NAME
        ));
    }

    let key_array = Key::clone_from_slice(&key_data);
    Ok(key_array)
}

/// Encrypt an entire file (in memory) with XChaCha20-Poly1305.
fn encrypt_file(input_file: &str, output_file: &str) -> Result<()> {
    let key = load_key()?;
    let plaintext = fs::read(input_file)
        .map_err(|_| anyhow!("Could not read input file '{}'", input_file))?;

    // Random 24-byte nonce
    let mut nonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cipher = XChaCha20Poly1305::new(&key);
    // IMPORTANT: use `plaintext.as_slice()`
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), plaintext.as_slice())
        .map_err(|_| anyhow!("Encryption failed."))?;

    // Output: [24 bytes of nonce] + [ciphertext]
    let mut combined = Vec::with_capacity(24 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    let mut out_file = fs::File::create(output_file)
        .map_err(|_| anyhow!("Could not create output file '{}'", output_file))?;
    out_file.write_all(&combined)?;
    out_file.sync_all()?;

    Ok(())
}

/// Decrypt an entire file (in memory) with XChaCha20-Poly1305.
fn decrypt_file(input_file: &str, output_file: &str) -> Result<()> {
    let key = load_key()?;
    let data = fs::read(input_file)
        .map_err(|_| anyhow!("Could not read input file '{}'", input_file))?;

    if data.len() < 25 {
        return Err(anyhow!(
            "Invalid ciphertext in '{}': too short for nonce + data.",
            input_file
        ));
    }

    let nonce_bytes = &data[..24];
    let ciphertext = &data[24..];

    let cipher = XChaCha20Poly1305::new(&key);
    // Here ciphertext is already &[u8], so it's fine.
    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| anyhow!("Decryption failed. Wrong key or corrupted data."))?;

    let mut out_file = fs::File::create(output_file)
        .map_err(|_| anyhow!("Could not create output file '{}'", output_file))?;
    out_file.write_all(&plaintext)?;
    out_file.sync_all()?;

    Ok(())
}

/// Atomic in-place encrypt or decrypt a file.
fn atomic_overwrite(file_to_overwrite: &str, encrypt: bool) -> Result<()> {
    let original_path = Path::new(file_to_overwrite);
    let parent_dir = original_path.parent().unwrap_or_else(|| Path::new("."));

    let temp_file_path = parent_dir.join(format!(
        ".{}.tmp",
        original_path.file_name().unwrap().to_string_lossy()
    ));

    if temp_file_path.exists() {
        return Err(anyhow!(
            "Temp file '{}' already exists. Cannot overwrite safely.",
            temp_file_path.display()
        ));
    }

    let key = load_key()?;
    let original_data = fs::read(&original_path)
        .map_err(|_| anyhow!("Could not read file '{}'", file_to_overwrite))?;

    let result_data = if encrypt {
        let mut nonce_bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let cipher = XChaCha20Poly1305::new(&key);
        // Use `as_slice()` again
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce_bytes), original_data.as_slice())
            .map_err(|_| anyhow!("Encryption failed."))?;

        let mut combined = Vec::with_capacity(24 + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        combined
    } else {
        if original_data.len() < 25 {
            return Err(anyhow!("Invalid ciphertext: too short for nonce + data."));
        }
        let nonce_bytes = &original_data[..24];
        let ciphertext = &original_data[24..];

        let cipher = XChaCha20Poly1305::new(&key);
        cipher
            .decrypt(XNonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|_| anyhow!("Decryption failed. Wrong key or corrupted data."))?
    };

    // Write the processed data to the temp file
    {
        let mut tmp_file = fs::File::create(&temp_file_path)
            .map_err(|_| anyhow!("Could not create temp file '{}'", temp_file_path.display()))?;
        tmp_file.write_all(&result_data)?;
        tmp_file.sync_all()?;
    }

    // Rename the temp file over the original (atomic on most platforms)
    fs::rename(&temp_file_path, &original_path).map_err(|e| {
        anyhow!(
            "Could not atomically rename '{}' to '{}': {}",
            temp_file_path.display(),
            original_path.display(),
            e
        )
    })?;

    Ok(())
}

/// Deterministic key generation using Argon2. Writes a 32-byte key to p.bin.
fn deterministic_keygen(password: &str) -> Result<()> {
    let argon = Argon2::default();
    let mut derived_key = [0u8; 32];

    argon
        .hash_password_into(password.as_bytes(), SALT, &mut derived_key)
        .map_err(|e| anyhow!("Argon2 hashing failed: {}", e))?;

    let mut file = fs::File::create(KEY_FILE_NAME)
        .map_err(|_| anyhow!("Could not create key file '{}'", KEY_FILE_NAME))?;
    file.write_all(&derived_key)?;
    file.sync_all()?;

    Ok(())
}



