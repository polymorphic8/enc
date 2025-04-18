#![forbid(unsafe_code)]

use argon2::{Argon2, Algorithm, Params, Version};
use rpassword::read_password;
use std::fs::File;
use std::io::{self, Write};
use zeroize::Zeroizing;

fn main() -> io::Result<()> {
    // 1) Prompt for the password (first time)
    print!("Enter password: ");
    io::stdout().flush()?;
    let p1 = Zeroizing::new(
        read_password().expect("Failed to read first password")
    );

    // 2) Prompt for the password (second time)
    print!("Enter password again: ");
    io::stdout().flush()?;
    let p2 = Zeroizing::new(
        read_password().expect("Failed to read second password")
    );

    // 3) Check if the two passwords match
    if p1 != p2 {
        eprintln!("Error: Passwords did not match. Exiting.");
        std::process::exit(1);
    }
    // From here on, you can use either `p1` or `p2`—they have the same contents.
    let password = p1;

    // ------------------------------
    // Argon2 Configuration Settings
    // ------------------------------
    // For best security, customize these or generate truly random salts.
    const SALT1: &[u8] = b"FixedSaltForKey01";
    const SALT2: &[u8] = b"FixedSaltForKey02";

    // Tweak these based on system capabilities
    const MEMORY_SIZE_KIB: u32 = 1024 * 256; // 256 MB
    const TIME_COST: u32 = 4;
    const PARALLELISM: u32 = 8;
    const OUTPUT_KEY_LEN: usize = 32;

    // Set up Argon2 with chosen parameters
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(MEMORY_SIZE_KIB, TIME_COST, PARALLELISM, Some(OUTPUT_KEY_LEN))
            .expect("Failed to create Argon2 params"),
    );

    // Derive key #1
    let mut key1 = Zeroizing::new(vec![0u8; OUTPUT_KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), SALT1, &mut key1)
        .expect("Error deriving key 1");

    // Derive key #2
    let mut key2 = Zeroizing::new(vec![0u8; OUTPUT_KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), SALT2, &mut key2)
        .expect("Error deriving key 2");

    // Write out the keys as 1.key, 2.key
    write_key_to_file("1.key", &key1)?;
    write_key_to_file("2.key", &key2)?;

    println!("Keys successfully derived and saved as '1.key' and '2.key' in current directory.");

    // key1, key2, and password will be zeroized on drop
    Ok(())
}

fn write_key_to_file(filename: &str, key: &[u8]) -> io::Result<()> {
    let mut file = File::create(filename)?;
    file.write_all(key)?;
    file.sync_all()?;
    Ok(())
}

