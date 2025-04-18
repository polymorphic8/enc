use std::env;
use std::fs::File;
use std::io::Write;

use argon2::{
    Argon2,
    Algorithm,
    Params,
    Version,
};

/// The name of the key file to be created.
/// Change this before compile time if you want a different filename.
const KEY_FILE_NAME: &str = "mykey.bin";

/// A salt or "seed" that you can change before compile time 
/// to produce a different key for the same password.
const SALT_SEED: &str = "my_secret_salt_1";

/// Another "seed"/pepper that you can change. Combining multiple 
/// seeds lets you more easily differentiate builds.
const SECRET_PEPPER: &str = "my_secret_pepper_2";

fn main() {
    // Collect command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <PASSWORD>", args[0]);
        std::process::exit(1);
    }

    let password = &args[1];

    // Combine the seeds to form a salt:
    let combined_salt = format!("{}{}", SALT_SEED, SECRET_PEPPER);

    // Configure Argon2 parameters (this is an example; adjust as needed)
    let params = Params::default(); 
    // or, for example: let params = Params::new(65536, 3, 1, None).unwrap();

    // Create an Argon2 instance (Argon2id is recommended)
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Prepare a 32-byte buffer to hold the derived key
    let mut key_32 = [0u8; 32];

    // Derive the key (raw bytes) from the password and salt
    argon2
        .hash_password_into(password.as_bytes(), combined_salt.as_bytes(), &mut key_32)
        .expect("Error hashing password with Argon2");

    // Write the key to the configured file
    let mut file = File::create(KEY_FILE_NAME)
        .expect("Unable to create key file");

    file.write_all(&key_32)
        .expect("Unable to write key data to file");

    println!("32-byte key has been written to {}", KEY_FILE_NAME);
}


