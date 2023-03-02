/*
    DISKHASHER v0.1 - 2022 by Hyohko

    ##################################
    GPLv3 NOTICE AND DISCLAIMER
    ##################################

    This file is part of DISKHASHER.

    DISKHASHER is free software: you can redistribute it
    and/or modify it under the terms of the GNU General
    Public License as published by the Free Software
    Foundation, either version 3 of the License, or (at
    your option) any later version.

    DISKHASHER is distributed in the hope that it will
    be useful, but WITHOUT ANY WARRANTY; without even
    the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General
    Public License along with DISKHASHER. If not, see
    <https://www.gnu.org/licenses/>.
*/

extern crate pretty_env_logger;
#[macro_use]
extern crate log;

use {
    clap::ValueEnum,
    custom_error::custom_error,
    digest::DynDigest,
    hex,
    regex::Regex,
    std::collections::HashMap,
    std::fmt::{self, Display, Formatter},
    std::fs,
    std::fs::File,
    std::io::{BufRead, BufReader, Read},
    std::mem,
    std::path::{Path, PathBuf},
    std::sync::atomic::{AtomicUsize, Ordering},
    std::sync::Mutex,
    std::thread,
    threadpool::ThreadPool,
    walkdir::WalkDir,
};

// TODO - remove public fields
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FileData {
    size: u64,
    path: PathBuf,
    expected_hash: String,
}

impl FileData {
    fn new(size: u64, path: PathBuf) -> Self {
        FileData {
            size,
            path,
            expected_hash: String::new(),
        }
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn path(&self) -> &PathBuf {
        &self.path
    }
    fn path_string(&self) -> String {
        self.path.display().to_string()
    }
    fn hash(&self) -> &String {
        &self.expected_hash
    }
    fn set_hash(&mut self, hash: &mut String) {
        self.expected_hash = mem::take(hash);
    }
}

enum FileType {
    IsDir,
    IsFile,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum HashAlg {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

impl Display for HashAlg {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MD5 => write!(f, "MD5"),
            Self::SHA1 => write!(f, "SHA1"),
            Self::SHA224 => write!(f, "SHA224"),
            Self::SHA256 => write!(f, "SHA256"),
            Self::SHA384 => write!(f, "SHA384"),
            Self::SHA512 => write!(f, "SHA512"),
        }
    }
}

custom_error! {pub HasherError
    RegexError{why: String} = "Regular expression failed => {why}",
    FileError{path: String, why: String} = "File/Directory error => '{path}': {why}",
    HashError{why: String} = "Hash error => {why}",
    ThreadingError{why: String} = "Thread operation failed => {why}",
    ParseError{why: String} = "Parse error => {why}",
    IoError{why: String} = "IO Failure => {why}",
}

impl From<std::io::Error> for HasherError {
    fn from(error: std::io::Error) -> Self {
        HasherError::IoError {
            why: format!("{:?}", error.kind()),
        }
    }
}

use crate::HasherError::*;
#[derive(Debug)]
pub struct Hasher {
    pool: ThreadPool,
    alg: HashAlg,
    root: PathBuf,
    hash_regex: Regex,
    hashfiles: Vec<FileData>,
    checkedfiles: Vec<FileData>,
    hashmap: HashMap<PathBuf, String>,
}

impl Hasher {
    // Public Interface Functions
    pub fn new(
        alg: HashAlg,
        root_dir: String,
        hashfile_pattern: String,
    ) -> Result<Self, HasherError> {
        let hash_regex = match Regex::new(&hashfile_pattern) {
            Ok(v) => v,
            Err(err) => {
                return Err(RegexError {
                    why: format!("'{hashfile_pattern}' returns error {err}"),
                })
            }
        };
        let root = canonicalize_path(&root_dir, FileType::IsDir)?;
        let num_threads = match thread::available_parallelism() {
            Ok(v) => v.get(),
            Err(err) => {
                return Err(ThreadingError {
                    why: format!("{err}: Couldn't get number of available threads"),
                });
            }
        };

        Ok(Hasher {
            pool: ThreadPool::new(num_threads),
            alg,
            root,
            hash_regex,
            hashfiles: vec![],
            checkedfiles: vec![],
            hashmap: [].into(),
        })
    }

    pub fn run(
        &mut self,
        force: bool,
        verbose: bool,
        largest_first: bool,
    ) -> Result<(), HasherError> {
        self.recursive_dir(force, largest_first)?;
        let _e = match self.load_hashes() {
            Ok(v) => v,
            Err(err) => match force {
                true => {
                    warn!("[+] No valid hashfile, but --force flag set");
                }
                false => {
                    return Err(err);
                }
            },
        };
        let num_files = self.checkedfiles.len();
        self.start_hash_threads(force, verbose)?;
        self.join()?;
        self.hashcount_monitor(num_files);
        Ok(())
    }

    //  Private Functions
    fn hashcount_monitor(&self, total_files: usize) {
        increment_hashcount(total_files);
    }

    fn join(&self) -> Result<(), HasherError> {
        self.pool.join();
        Ok(())
    }

    fn load_hashes(&mut self) -> Result<(), HasherError> {
        self.hashmap.reserve(self.checkedfiles.len());

        for f in &self.hashfiles {
            let mut hashpath = f.path().clone();
            hashpath.pop();

            let file = File::open(f.path()).or_else(|err| {
                return Err(FileError {
                    why: format!("{err} : Hashfile cannot be opened"),
                    path: f.path_string(),
                });
            })?;

            let reader = BufReader::new(file);
            let mut num_lines: i32 = 0;
            for line in reader.lines() {
                let newline = line.or_else(|err| {
                    return Err(FileError {
                        why: format!("{err} : Line from file cannot be read"),
                        path: f.path_string(),
                    });
                })?;

                let (hashval, canonical_path) = match split_hashfile_line(&newline, &hashpath) {
                    Ok(v) => v,
                    Err(err) => {
                        error!("[!] {err} : Failed to parse line from hashfile :: '{newline}'");
                        continue;
                    }
                };
                self.hashmap.insert(canonical_path, hashval);
                num_lines += 1;
                if num_lines % 500 == 0 {
                    info!("[*] {num_lines} hashes read from {}", f.path_string());
                }
            }
        }

        if self.hashmap.len() == 0 {
            return Err(HashError {
                why: "No hashes read from hashfiles".to_string(),
            });
        }
        Ok(())
    }

    fn recursive_dir(&mut self, force: bool, largest_first: bool) -> Result<(), HasherError> {
        let mut file_vec = Vec::<FileData>::new();
        let mut files_added: i32 = 0;
        for entry in WalkDir::new(&self.root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path().to_path_buf();
            let size: u64 = match path.metadata() {
                Ok(f) => f.len(),
                Err(err) => {
                    error!("[!] Failed to get metadata for {} : {err}", path.display());
                    continue;
                } // No error for now, keep processing
            };
            file_vec.push(FileData::new(size, path));
            files_added += 1;
            if files_added % 500 == 0 {
                info!("[*] Added {files_added} files to be hashed");
            }
        }

        // Split the file vec into hash files and non-hashfiles
        info!("[+] Identifying hashfiles");
        (self.hashfiles, self.checkedfiles) = file_vec
            .into_iter()
            .partition(|f| path_matches_regex(&self.hash_regex, f.path()));
        if self.hashfiles.len() == 0 {
            let reason = "No hashfiles matched the hashfile pattern".to_string();
            if !force {
                return Err(RegexError { why: reason });
            } else {
                warn!("{reason}");
            }
        }
        info!("[*] {} files in the queue", self.checkedfiles.len());

        if largest_first {
            info!("[*] Sorting files by size, largest first");
            self.checkedfiles
                .sort_unstable_by(|a, b| a.size().cmp(&b.size()));
        } else {
            info!("[*] Sorting files by size, smallest first");
            self.checkedfiles
                .sort_unstable_by(|a, b| b.size().cmp(&a.size()));
        }
        Ok(())
    }

    fn start_hash_threads(&mut self, force: bool, verbose: bool) -> Result<usize, HasherError> {
        const EMPTY_STRING: String = String::new();
        info!(
            "[+] Checking hashes - spinning up {} worker threads",
            self.pool.max_count()
        );

        let num_files = self.checkedfiles.len();
        while let Some(mut ck) = self.checkedfiles.pop() {
            if !&self.hashmap.contains_key(ck.path()) {
                if !force {
                    warn!("[!] {:?} => No hash found", ck.path());
                    self.hashcount_monitor(num_files);
                    continue;
                }
            }
            {
                // Scope
                let mut expected_hash = self
                    .hashmap
                    .get(ck.path())
                    .unwrap_or(&EMPTY_STRING)
                    .to_string();
                ck.set_hash(&mut expected_hash);
            }
            let alg = self.alg;
            self.pool.execute(move || {
                perform_hash(ck, alg, force, verbose, num_files).ok();
            });
        } // end while
        Ok(num_files)
    }
}

// Static Functions
fn canonicalize_path(path: &String, filetype: FileType) -> std::io::Result<PathBuf> {
    let root_path = fs::canonicalize(Path::new(&path))?;
    match filetype {
        FileType::IsDir => {
            if !root_path.is_dir() {
                let emsg = format!(
                    "[-] Path '{}' is not a valid directory",
                    root_path.display()
                );
                return Err(std::io::Error::new(std::io::ErrorKind::Other, emsg));
            }
        }
        FileType::IsFile => {
            if !root_path.is_file() {
                let emsg = format!(
                    "[-] Path '{}' is not a valid directory",
                    root_path.display()
                );
                return Err(std::io::Error::new(std::io::ErrorKind::Other, emsg));
            }
        }
    };
    Ok(root_path)
}

fn canonicalize_split_filepath(
    splitline: &Vec<&str>,
    hashpath: &PathBuf,
) -> Result<PathBuf, HasherError> {
    let file_path = splitline[1..].join(" ");

    let mut file_path_buf = Path::new(&file_path).to_path_buf();
    if file_path_buf.is_absolute() {
        return Ok(file_path_buf);
    }
    if !file_path.starts_with("./") {
        let new_file_path = format!("./{file_path}");
        file_path_buf = Path::new(&new_file_path).to_path_buf();
    }
    file_path_buf = hashpath.join(&file_path_buf);
    let canonical_result =
        canonicalize_path(&file_path_buf.display().to_string(), FileType::IsFile)?;
    Ok(canonical_result)
}

const BUFSIZE: usize = 1024 * 1024 * 2; // 2 MB

#[cfg(target_os = "linux")]
#[repr(C, align(4096))]
struct AlignedHashBuffer([u8; BUFSIZE]);

#[cfg(target_os = "linux")]
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

fn hash_file(path: &PathBuf, alg: HashAlg) -> Result<String, HasherError> {
    let mut hasher = select_hasher(alg);
    #[cfg(target_os = "linux")]
    {
        const O_DIRECT: i32 = 0x4000; // Linux
        let mut buffer: Box<AlignedHashBuffer> = Box::new(AlignedHashBuffer([0u8; BUFSIZE]));
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECT)
            .open(path)?;
        loop {
            let read_count = file.read(&mut buffer.0[..BUFSIZE])?;
            hasher.update(&buffer.0[..read_count]);
            if read_count < BUFSIZE {
                break;
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut buffer: Box<[u8]> = vec![0; BUFSIZE].into_boxed_slice();
        let mut file = File::open(path)?;
        loop {
            let read_count = file.read(&mut buffer[..BUFSIZE])?;
            hasher.update(&buffer[..read_count]);
            if read_count < BUFSIZE {
                break;
            }
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

use lazy_static::lazy_static;
lazy_static! {
    static ref HEXSTRING_PATTERN: Regex = hash_hexpattern();
}

fn hash_hexpattern() -> Regex {
    const STR_REGEX: &str = concat!(
        r"([[:xdigit:]]{32})|", // MD5
        r"([[:xdigit:]]{40})|", // SHA1
        r"([[:xdigit:]]{56})|", // SHA224
        r"([[:xdigit:]]{64})|", // SHA256
        r"([[:xdigit:]]{96})|", // SHA384
        r"([[:xdigit:]]{128})", // SHA512
    );
    // As this regex is initialized at process startup, panic instead
    // of returning an error
    let expr = match Regex::new(&STR_REGEX) {
        Ok(v) => v,
        Err(_e) => panic!("[!] Regular expression engine startup failure"),
    };
    expr
}

fn hexstring_is_valid(hexstring: &str) -> bool {
    match hexstring.len() {
        32 | 40 | 56 | 64 | 96 | 128 => {
            for chr in hexstring.chars() {
                if !chr.is_ascii_hexdigit() {
                    return false;
                }
            }
            return true;
        }
        _ => return false,
    }
}

// Why the separation? We may want to have a per-Hasher object mutex
// and hash count if we spin up multiple. Future-proofing.
fn increment_hashcount(total_files: usize) {
    static S_MONITOR_MUTEX: Mutex<bool> = Mutex::new(false);
    static S_ATOMIC_HASHCOUNT: AtomicUsize = AtomicUsize::new(0);
    increment_hashcount_func(&S_ATOMIC_HASHCOUNT, &S_MONITOR_MUTEX, total_files);
}

fn increment_hashcount_func(
    _atomic_hashcount: &AtomicUsize,
    _monitor_mutex: &Mutex<bool>,
    total_files: usize,
) {
    let _guard = _monitor_mutex
        .lock()
        .expect("If a mutex lock fails, there is a design flaw. Rewrite code.");
    if total_files == 0 {
        warn!("[!] No files to hash");
        return;
    }
    _atomic_hashcount.fetch_add(1, Ordering::SeqCst);
    let curr_hashes: usize = _atomic_hashcount.load(Ordering::SeqCst);
    let pct_complete: f64 = ((curr_hashes) as f64 / (total_files) as f64) * 100.0;
    let approx_five_pct: usize = total_files / 20;
    if curr_hashes % 500 == 0 || curr_hashes % approx_five_pct == 0 {
        info!("[*] ({pct_complete:.2}%) {curr_hashes} hashes complete");
    }
    if curr_hashes == total_files {
        info!(
            "[*] ({pct_complete:.2}%) {curr_hashes} hashes! Processing last file, queue is empty"
        );
    }
}

fn path_matches_regex(hash_regex: &Regex, file_path: &PathBuf) -> bool {
    let str_path = match file_path.file_name() {
        Some(v) => v,
        None => {
            error!("[-] Failed to retrieve file name from path object");
            return false;
        }
    };
    let is_match = hash_regex.is_match(match str_path.to_str() {
        Some(v) => v,
        None => {
            error!("[-] Path string failed to parse");
            return false;
        }
    });
    is_match
}

fn perform_hash(
    fdata: FileData,
    alg: HashAlg,
    force: bool,
    verbose: bool,
    num_files: usize,
) -> Result<(), HasherError> {
    increment_hashcount(num_files);
    let actual_hash = hash_file(fdata.path(), alg)?;
    if force {
        let result = format!(
            "[*] Checksum value :\n\t{:?}\n\tHash         : {:?}",
            fdata.path(),
            actual_hash
        );
        info!("{result}");
    } else {
        // Compare
        let success: bool = fdata.hash() == &actual_hash;
        if success {
            if verbose {
                let result = format!(
                    "[+] Checksum passed:\n\t{:?}\n\tActual hash  : {:?}",
                    fdata.path(),
                    actual_hash
                );
                info!("{result}");
            }
        } else {
            let result = format!(
                "[-] Checksum failed:\n\t{:?}\n\tExpected hash: {:?}\n\tActual hash  : {:?}",
                fdata.path(),
                fdata.hash(),
                actual_hash
            );
            error!("{result}");
        }
    }
    Ok(())
}

fn select_hasher(alg: HashAlg) -> Box<dyn DynDigest> {
    match alg {
        HashAlg::MD5 => Box::new(md5::Md5::default()),
        HashAlg::SHA1 => Box::new(sha1::Sha1::default()),
        HashAlg::SHA224 => Box::new(sha2::Sha224::default()),
        HashAlg::SHA256 => Box::new(sha2::Sha256::default()),
        HashAlg::SHA384 => Box::new(sha2::Sha384::default()),
        HashAlg::SHA512 => Box::new(sha2::Sha512::default()),
    }
}

fn split_hashfile_line(
    newline: &String,
    hashpath: &PathBuf,
) -> Result<(String, PathBuf), HasherError> {
    let splitline: Vec<&str> = newline.split_whitespace().collect();
    if splitline.len() < 2 {
        return Err(ParseError {
            why: format!("Line does not have enough elements: {newline}"),
        });
    }
    let hashval: &str = splitline[0];
    //if !HEXSTRING_PATTERN.is_match(hashval) {
    if !hexstring_is_valid(hashval) {
        return Err(ParseError {
            why: "Line does not start with a valid hex string".to_string(),
        });
    }
    let canonical_path = canonicalize_split_filepath(&splitline, hashpath)?;
    Ok((hashval.to_string(), canonical_path))
}

///////////////////////////////////////////////////////////////////////////////
/// TESTS
///////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod test;
