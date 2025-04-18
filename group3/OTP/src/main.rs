use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

fn main() -> io::Result<()> {
    // This is the simplest approach: just define your key file name here.
    let key_file_name = "key.key";

    // 1. Parse Command-Line Arguments
    let args: Vec<String> = env::args().collect();
    let (input_path, output_path, atomic_overwrite) = match args.len() {
        // e.g. ./xor_app -over my_file
        3 if args[1] == "-over" => (args[2].clone(), args[2].clone(), true),
        // e.g. ./xor_app input_file output_file
        3 => (args[1].clone(), args[2].clone(), false),
        _ => {
            eprintln!("Usage:");
            eprintln!("  {} <input_file> <output_file>", args[0]);
            eprintln!("  {} -over <input_file>", args[0]);
            std::process::exit(1);
        }
    };

    // 2. Read Input File
    let input_data = fs::read(&input_path).map_err(|e| {
        eprintln!("Error reading input file '{}': {}", input_path, e);
        e
    })?;

    // 3. Read Key from key_file_name
    let key_data = fs::read(key_file_name).map_err(|e| {
        eprintln!("Error reading key file '{}': {}", key_file_name, e);
        e
    })?;

    // 4. Validate Key Size
    if key_data.len() < input_data.len() {
        eprintln!(
            "Key file '{}' is too small: {} bytes < input file {} bytes.",
            key_file_name,
            key_data.len(),
            input_data.len()
        );
        std::process::exit(1);
    }

    // 5. XOR in Memory
    let xor_data: Vec<u8> = input_data
        .iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key_data[i])
        .collect();

    // 6. Write Result
    if atomic_overwrite {
        // Overwrite mode: write to a temp file and rename
        let input_file_path = Path::new(&input_path);
        let tmp_path = input_file_path
            .with_file_name(format!(
                "{}.tmp",
                input_file_path.file_name().unwrap().to_string_lossy()
            ));
        
        {
            let mut tmp_file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)?;
            tmp_file.write_all(&xor_data)?;
            tmp_file.flush()?;
            tmp_file.sync_all()?;
        }

        fs::rename(&tmp_path, &input_path)?;
    } else {
        // Normal mode: write XORed data to output_path
        fs::write(&output_path, &xor_data)?;
    }

    println!("Operation successful.");
    Ok(())
}



