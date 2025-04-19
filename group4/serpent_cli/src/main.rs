use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread::JoinHandle;

use hmac::{Hmac, Mac};
use rand::RngCore;
use serpent::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit};
use serpent::Serpent;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;
type BResult<T> = Result<T, Box<dyn Error>>;

struct SerpentCli {
    paths: Vec<PathBuf>,
    encrypt: bool,
    serpent_key: Vec<u8>,
    hmac_key: Vec<u8>,
    verbose: bool,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl SerpentCli {
    const BLOCK_SIZE: usize = 16;

    pub fn new(
        paths: Vec<PathBuf>,
        encrypt: bool,
        serpent_key: Vec<u8>,
        hmac_key: Vec<u8>,
        verbose: bool,
    ) -> Self {
        Self { paths, encrypt, serpent_key, hmac_key, verbose, threads: Mutex::new(Vec::new()) }
    }

    pub fn run(&'static self) -> BResult<()> {
        for path in &self.paths {
            let path = path.clone();
            if path.is_dir() {
                if self.verbose { println!("Directory: {:?}", path); }
                let mut threads = self.threads.lock().unwrap();
                threads.push(std::thread::spawn(move || {
                    self.iter_dir(path).unwrap();
                }));
            } else {
                if self.verbose { println!("File: {:?}", path); }
                self.process_file(&path)?;
            }
        }
        loop {
            let mut threads = self.threads.lock().unwrap();
            if threads.is_empty() { break; }
            let t = threads.remove(0);
            drop(threads);
            t.join().unwrap();
        }
        Ok(())
    }

    fn iter_dir(&'static self, dir: PathBuf) -> BResult<()> {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                if self.verbose { println!("Subdir: {:?}", path); }
                let mut threads = self.threads.lock().unwrap();
                threads.push(std::thread::spawn(move || {
                    self.iter_dir(path).unwrap();
                }));
            } else if path.file_name().unwrap() != ".DS_Store" {
                if self.verbose { println!("File: {:?}", path); }
                self.process_file(&path)?;
            }
        }
        Ok(())
    }

    fn process_file(&self, path: &Path) -> BResult<()> {
        let mut data = Vec::new();
        File::open(path)?.read_to_end(&mut data)?;

        let output = if self.encrypt {
            // Encrypt: CBC with PKCS7, then HMAC
            let mut iv = [0u8; Self::BLOCK_SIZE];
            rand::thread_rng().fill_bytes(&mut iv);

            let mut pt = data;
            let pad_len = Self::BLOCK_SIZE - (pt.len() % Self::BLOCK_SIZE);
            pt.extend(std::iter::repeat(pad_len as u8).take(pad_len));

            let serpent = Serpent::new_from_slice(&self.serpent_key)?;
            let mut prev = iv;
            let mut ct = Vec::with_capacity(pt.len());
            for chunk in pt.chunks(Self::BLOCK_SIZE) {
                let mut block_bytes = [0u8; Self::BLOCK_SIZE];
                for i in 0..Self::BLOCK_SIZE { block_bytes[i] = chunk[i] ^ prev[i]; }
                let mut block = Block::<Serpent>::clone_from_slice(&block_bytes);
                serpent.encrypt_block(&mut block);
                let cb = block.to_vec();
                prev.copy_from_slice(&cb);
                ct.extend_from_slice(&cb);
            }

            let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.hmac_key).unwrap();
            mac.update(&iv);
            mac.update(&ct);
            let tag = mac.finalize().into_bytes();

            let mut out = Vec::with_capacity(iv.len() + ct.len() + tag.len());
            out.extend_from_slice(&iv);
            out.extend_from_slice(&ct);
            out.extend_from_slice(&tag);
            out
        } else {
            // Decrypt: verify HMAC then CBC with PKCS7 strip
            if data.len() < Self::BLOCK_SIZE + 32 {
                return Err("file too short".into());
            }
            let iv = &data[..Self::BLOCK_SIZE];
            let tag_in = &data[data.len() - 32..];
            let ct = &data[Self::BLOCK_SIZE..data.len() - 32];

            let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.hmac_key).unwrap();
            mac.update(iv);
            mac.update(ct);
            mac.verify(tag_in.into()).map_err(|_| "HMAC mismatch")?;

            let serpent = Serpent::new_from_slice(&self.serpent_key)?;
            let mut prev = <[u8; Self::BLOCK_SIZE]>::try_from(iv).unwrap();
            let mut pt = Vec::with_capacity(ct.len());
            for chunk in ct.chunks(Self::BLOCK_SIZE) {
                let mut block = Block::<Serpent>::clone_from_slice(chunk);
                serpent.decrypt_block(&mut block);
                let db = block.to_vec();
                let mut pb = [0u8; Self::BLOCK_SIZE];
                for i in 0..Self::BLOCK_SIZE { pb[i] = db[i] ^ prev[i]; }
                prev.copy_from_slice(chunk);
                pt.extend_from_slice(&pb);
            }

            let pad = *pt.last().unwrap() as usize;
            if pad == 0 || pad > Self::BLOCK_SIZE {
                return Err("bad padding".into());
            }
            pt.truncate(pt.len() - pad);
            pt
        };

        let tmp = path.with_extension("tmp");
        let mut f = File::create(&tmp)?;
        f.write_all(&output)?;
        f.sync_all()?;
        fs::remove_file(path)?;
        fs::rename(tmp, path)?;
        Ok(())
    }
}

fn print_usage() {
    eprintln!(
        "Usage: serpent_cli [--encrypt -e | --decrypt -d] -p <paths...>\n\
         (requires 32-byte raw key in key.key)"
    );
}

fn main() -> BResult<()> {
    if !Path::new("key.key").exists() {
        eprintln!("Error: key.key not found");
        std::process::exit(1);
    }
    let key_bytes = fs::read("key.key")?;
    if key_bytes.len() != 32 {
        eprintln!("Error: key.key must be 32 bytes");
        std::process::exit(1);
    }
    let mut hasher = Sha256::new();
    hasher.update(&key_bytes);
    let hmac_key = hasher.finalize().to_vec();

    let args: Vec<String> = std::env::args().collect();
    let encrypt = args.contains(&"--encrypt".into()) || args.contains(&"-e".into());
    let decrypt = args.contains(&"--decrypt".into()) || args.contains(&"-d".into());
    if encrypt == decrypt {
        print_usage();
        return Ok(());
    }
    let paths: Vec<PathBuf> = if let Some(i) = args.iter().position(|x| x == "-p") {
        args[i + 1..].iter().map(PathBuf::from).collect()
    } else {
        print_usage();
        return Ok(());
    };

    let cli: &'static SerpentCli = Box::leak(Box::new(SerpentCli::new(
        paths, encrypt, key_bytes, hmac_key, true,
    )));
    cli.run()?;
    Ok(())
}
