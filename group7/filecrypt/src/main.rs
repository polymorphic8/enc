use clap::{Parser, Subcommand};
use sodiumoxide::crypto::secretstream::{self, Header, Stream, Tag};
use std::{fs, io::{self, Read, Write}, path::Path, process};

const MAGIC: &[u8; 5] = b"MYENC";
const VERSION: u8 = 1;
const CHUNK_SIZE: usize = 64 * 1024;

#[derive(Parser)]
#[clap(author, version, about)]
struct Cli {
    #[clap(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt file in-place
    #[clap(name = "E")]
    E { file: String },
    /// Decrypt file in-place
    #[clap(name = "D")]
    D { file: String },
}

fn load_key() -> secretstream::Key {
    let key_bytes = match fs::read("key.key") {
        Ok(b) => b,
        Err(_) => {
            eprintln!(
                "Error: key.key not found. Please create a {}-byte key file named key.key.",
                secretstream::KEYBYTES
            );
            process::exit(1);
        }
    };
    if key_bytes.len() != secretstream::KEYBYTES {
        eprintln!(
            "Error: key.key has invalid length ({} bytes). Key must be {} bytes long.",
            key_bytes.len(),
            secretstream::KEYBYTES
        );
        process::exit(1);
    }
    secretstream::Key::from_slice(&key_bytes).unwrap()
}

fn main() -> io::Result<()> {
    sodiumoxide::init().expect("failed to init sodiumoxide");
    let key = load_key();
    let cli = Cli::parse();
    match cli.cmd {
        Commands::E { file } => encrypt_in_place(&file, &key),
        Commands::D { file } => decrypt_in_place(&file, &key),
    }
}

fn encrypt_in_place(path: &str, key: &secretstream::Key) -> io::Result<()> {
    let src = Path::new(path);
    let tmp = src.with_file_name(format!("{}.tmp", src.file_name().unwrap().to_string_lossy()));

    let mut reader = fs::File::open(src)?;
    let (mut push_stream, header) = Stream::init_push(key).unwrap();

    {
        let mut out = fs::File::create(&tmp)?;
        out.write_all(MAGIC)?;
        out.write_all(&[VERSION])?;
        out.write_all(header.as_ref())?;
        out.sync_all()?;

        let mut buf = [0u8; CHUNK_SIZE];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 { break; }
            let tag = if n < buf.len() { Tag::Final } else { Tag::Message };
            let encrypted = push_stream.push(&buf[..n], None, tag).unwrap();
            out.write_all(&encrypted)?;
            if tag == Tag::Final { break; }
        }
        out.sync_all()?;
    }

    fs::rename(tmp, src)?;
    Ok(())
}

fn decrypt_in_place(path: &str, key: &secretstream::Key) -> io::Result<()> {
    let src = Path::new(path);
    let tmp = src.with_file_name(format!("{}.tmp", src.file_name().unwrap().to_string_lossy()));

    let mut reader = fs::File::open(src)?;
    let mut magic = [0u8; MAGIC.len()];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid file magic"));
    }
    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;
    if version[0] != VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported version"));
    }
    let mut hdr_bytes = [0u8; secretstream::HEADERBYTES];
    reader.read_exact(&mut hdr_bytes)?;
    let header = Header(hdr_bytes);
    let mut pull_stream = Stream::init_pull(&header, key).unwrap();

    {
        let mut out = fs::File::create(&tmp)?;
        let mut buf = vec![0u8; CHUNK_SIZE + secretstream::ABYTES];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 { break; }
            let (plain, tag) = pull_stream.pull(&buf[..n], None).unwrap();
            out.write_all(&plain)?;
            if tag == Tag::Final { break; }
        }
        out.sync_all()?;
    }

    fs::rename(tmp, src)?;
    Ok(())
}

