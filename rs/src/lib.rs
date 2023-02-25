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

use {
    clap::{Parser, ValueEnum},
    custom_error::custom_error,
    digest::DynDigest,
    hex,
    regex::Regex,
    std::collections::HashMap,
    std::fmt::{self, Display, Formatter},
    std::fs,
    std::fs::File,
    std::io::{BufRead, BufReader, Read},
    std::path::{Path, PathBuf},
    std::sync::atomic::{AtomicUsize, Ordering},
    std::sync::Arc,
    std::thread,
    threadpool::ThreadPool,
    walkdir::WalkDir,
};

// TODO - remove public fields
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FileData {
    pub size: u64,
    pub path: PathBuf,
    pub expected_hash: String,
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

#[derive(Parser)]
#[clap(
    author,
    version,
    about = "Hash a directory's files and optionally check against existing hashfile"
)]
pub struct Arguments {
    /// Path to the directory we want to validate
    #[clap(short, long)]
    pub directory: String,
    /// Algorithm to use (SHA1, SHA256)
    #[clap(short, long)]
    #[arg(value_enum)]
    pub algorithm: HashAlg,
    /// Regex pattern used to identify hashfiles
    #[clap(short, long)]
    pub pattern: Option<String>,
    /// Force computation of hashes even if hash pattern fails or is omitted
    #[clap(short, long, action)]
    pub force: bool,
    /// Print all results to stdout
    #[clap(short, long, action)]
    pub verbose: bool,
}

pub enum FileType {
    IsDir,
    IsFile,
}

#[derive(Debug)]
pub struct Hasher {
    hashes_completed: Arc<AtomicUsize>,
    pool: ThreadPool,
    alg: HashAlg,
    root: PathBuf,
    hash_regex: Regex,
    hashfiles: Vec<FileData>,
    checkedfiles: Vec<FileData>,
    hashmap: HashMap<PathBuf, String>,
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
impl Hasher {
    // Public Interface Functions
    pub fn new(
        alg: HashAlg,
        root_dir: String,
        hashfile_pattern: String,
        // Debug level
        // Logfile
    ) -> Result<Self, HasherError> {
        let hash_regex = match Regex::new(&hashfile_pattern) {
            Ok(v) => v,
            Err(e) => {
                return Err(RegexError {
                    why: format!("'{}' returns error {}", hashfile_pattern, e),
                })
            }
        };
        let root = HasherUtil::canonicalize_path(&root_dir, FileType::IsDir)?;
        let num_threads = match thread::available_parallelism() {
            Ok(v) => v.get(),
            Err(_e) => {
                return Err(ThreadingError {
                    why: format!("{}: Couldn't get number of available threads", _e),
                });
            }
        };

        Ok(Hasher {
            hashes_completed: Arc::new(AtomicUsize::new(1)),
            pool: ThreadPool::new(num_threads),
            alg,
            root,
            hash_regex,
            hashfiles: vec![],
            checkedfiles: vec![],
            hashmap: [].into(),
        })
    }

    pub fn run(&mut self, args: &Arguments) -> Result<(), HasherError> {
        self.recursive_dir()?;
        let _e = match self.load_hashes() {
            Ok(v) => v,
            Err(err) => match args.force {
                true => {
                    println!("[+] No valid hashfile, but --force flag set");
                }
                false => {
                    return Err(err);
                }
            },
        };
        let num_files = self.checkedfiles.len();
        self.start_hash_threads(args)?;
        self.join()?;
        self.hashcount_monitor(num_files);
        Ok(())
    }

    //  Private Functions
    fn hashcount_monitor(&self, total_files: usize) {
        HasherUtil::hashcount_monitor_thread(&self.hashes_completed, total_files);
    }

    fn increment_hashcount(&self) {
        HasherUtil::increment_hashcount_thread(&self.hashes_completed);
    }

    fn join(&self) -> Result<(), HasherError> {
        self.pool.join();
        Ok(())
    }

    fn load_hashes(&mut self) -> Result<(), HasherError> {
        self.hashmap.reserve(self.checkedfiles.len());

        for f in &self.hashfiles {
            let mut hashpath = f.path.clone();
            hashpath.pop();

            // Open file
            let file = File::open(&f.path).or_else(|err| {
                return Err(FileError {
                    why: format!("{} : Hashfile cannot be opened, trying any others", err),
                    path: f.path.display().to_string(),
                });
            })?;

            // Read file
            let reader = BufReader::new(file);
            let mut num_lines: i32 = 0;
            for line in reader.lines() {
                let newline = line.or_else(|err| {
                    return Err(FileError {
                        why: format!("{} : Line from file cannot be read", err),
                        path: f.path.display().to_string(),
                    });
                })?;

                let (hashval, canonical_path) =
                    match HasherUtil::split_hashfile_line(&newline, &hashpath) {
                        Ok(v) => v,
                        Err(_e) => {
                            println!(
                                "[!] Failed to parse {}, ignore and continue parsing",
                                newline
                            );
                            continue;
                        }
                    };
                self.hashmap.insert(canonical_path, hashval);
                num_lines += 1;
                if num_lines % 500 == 0 {
                    println!("[*] {} hashes read from {}", num_lines, f.path.display());
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

    fn recursive_dir(&mut self) -> Result<(), HasherError> {
        let mut file_vec = Vec::<FileData>::new();
        let mut files_added: i32 = 0;
        for entry in WalkDir::new(&self.root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let size: u64 = match path.metadata() {
                Ok(f) => f.len(),
                Err(_e) => {
                    println!("[!] Failed to get metadata for {}", path.display());
                    continue;
                } // No error for now, keep processing
            };
            file_vec.push(FileData {
                size,
                path: path.to_path_buf(),
                expected_hash: "".to_string(),
            });
            files_added += 1;
            if files_added % 500 == 0 {
                println!("[*] {} files to be hashed", files_added);
            }
        }

        // Split the file vec into hash files and non-hashfiles
        println!("[+] Identifying hashfiles");
        (self.hashfiles, self.checkedfiles) = file_vec
            .into_iter()
            .partition(|f| HasherUtil::path_matches_regex(&self.hash_regex, &f.path));

        // Sort vector by file size, smallest first
        println!("[*] Sorting files by size");
        self.checkedfiles.sort_by(|a, b| a.size.cmp(&b.size));
        Ok(())
    }

    fn start_hash_threads(&mut self, args: &Arguments) -> Result<usize, HasherError> {
        const EMPTY_STRING: String = String::new();
        println!(
            "[+] Checking hashes - spinning up {} worker threads",
            self.pool.max_count()
        );

        let num_files = self.checkedfiles.len();
        loop {
            let ck = match self.checkedfiles.pop() {
                Some(v) => v,
                None => break, // no more files to check
            };
            if !&self.hashmap.contains_key(&ck.path) {
                if !args.force {
                    println!("[!] {:?} => No hash found", &ck.path);
                    self.increment_hashcount();
                    continue;
                }
            }
            let mut expected_fdata: FileData = ck.clone();
            expected_fdata.expected_hash = self
                .hashmap
                .get(&ck.path)
                .unwrap_or(&EMPTY_STRING)
                .to_string();

            let alg = self.alg;
            let force = args.force;
            let verbose = args.verbose;
            let atomic_clone = self.hashes_completed.clone();
            self.pool.execute(move || {
                HasherUtil::perform_hash(
                    atomic_clone,
                    expected_fdata,
                    alg,
                    force,
                    verbose,
                    num_files,
                )
                .ok();
            });
        } // end loop
        Ok(num_files)
    }
}

struct HasherUtil {}

// Static Functions
impl HasherUtil {
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
            let new_file_path = format!("{}{}", "./", file_path);
            file_path_buf = Path::new(&new_file_path).to_path_buf();
        }
        file_path_buf = hashpath.join(&file_path_buf);
        let canonical_result =
            HasherUtil::canonicalize_path(&file_path_buf.display().to_string(), FileType::IsFile)?;
        Ok(canonical_result)
    }

    fn hash_file(path: &PathBuf, alg: HashAlg) -> Result<String, HasherError> {
        let mut hasher = HasherUtil::select_hasher(alg);

        const BUFSIZE: usize = 1024 * 1024 * 2; // 2 MB
        let mut buffer: Box<[u8]> = vec![0; BUFSIZE].into_boxed_slice();
        let mut file = File::open(path)?;

        loop {
            let read_count = file.read(&mut buffer[..BUFSIZE])?;
            hasher.update(&buffer[..read_count]);
            if read_count < BUFSIZE {
                break;
            }
        }
        Ok(hex::encode(hasher.finalize()))
    }

    fn hashcount_monitor_thread(atomic_hashcount: &Arc<AtomicUsize>, total_files: usize) {
        if total_files == 0 {
            println!("[!] No files to hash");
            return;
        }
        let curr_hashes: usize = atomic_hashcount.load(Ordering::SeqCst);
        let pct_complete: f64 = ((curr_hashes) as f64 / (total_files) as f64) * 100.0;
        if curr_hashes % 500 == 0 {
            println!("[*] ({:.2}%) {} hashes complete", pct_complete, curr_hashes);
        }
        if curr_hashes == total_files {
            println!(
                "[*] ({:.2}%) {} hashes complete\n[+] No more files to hash",
                pct_complete, curr_hashes
            );
        }
    }

    fn hexstring_is_valid(hexstring: &str) -> bool {
        match hexstring.len() {
            32 | 48 | 56 | 64 | 96 | 128 => {
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

    fn increment_hashcount_thread(atomic_size: &Arc<AtomicUsize>) {
        atomic_size.fetch_add(1, Ordering::SeqCst);
    }

    fn path_matches_regex(hash_regex: &Regex, file_path: &PathBuf) -> bool {
        let str_path = match file_path.file_name() {
            Some(v) => v,
            None => {
                println!("[-] Failed to retrieve file name from path object");
                return false;
            }
        };
        let is_match = hash_regex.is_match(match str_path.to_str() {
            Some(v) => v,
            None => {
                println!("[-] Path string failed to parse");
                return false;
            }
        });
        is_match
    }

    fn perform_hash(
        atomic_hashcount: Arc<AtomicUsize>,
        fdata: FileData,
        alg: HashAlg,
        force: bool,
        verbose: bool,
        num_files: usize,
    ) -> Result<(), HasherError> {
        HasherUtil::increment_hashcount_thread(&atomic_hashcount);
        let actual_hash = HasherUtil::hash_file(&fdata.path, alg)?;
        if force {
            println!(
                "[*] Checksum value : {:?}\n\tHash         : {:?}",
                &fdata.path, actual_hash
            );
        } else {
            // Compare
            let success: bool = &fdata.expected_hash == &actual_hash;
            if success {
                if verbose {
                    println!(
                        "[+] Checksum passed: {:?}\n\tActual hash  : {:?}",
                        &fdata.path, actual_hash
                    );
                }
            } else {
                println!(
                    "[-] Checksum failed: {:?}\n\tExpected hash: {:?}\n\tActual hash  : {:?}",
                    &fdata.path, &fdata.expected_hash, actual_hash
                );
            }
        }
        HasherUtil::hashcount_monitor_thread(&atomic_hashcount, num_files);
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
                why: format!("Line does not have enough elements: {}", newline),
            });
        }
        let hashval: &str = splitline[0];
        //if !regex_pattern.is_match(hashval) {
        if !HasherUtil::hexstring_is_valid(hashval) {
            return Err(ParseError {
                why: "Line does not start with a valid hex string".to_string(),
            });
        }
        let canonical_path = HasherUtil::canonicalize_split_filepath(&splitline, hashpath)?;
        Ok((hashval.to_string(), canonical_path))
    }
}

/*fn hash_hexpattern() -> Regex {
    const STR_REGEX: &str = concat!(
        r"([[:xdigit:]]{32})|", // MD5
        r"([[:xdigit:]]{48})|", // SHA1
        r"([[:xdigit:]]{56})|", // SHA224
        r"([[:xdigit:]]{64})|", // SHA256
        r"([[:xdigit:]]{96})|", // SHA384
        r"([[:xdigit:]]{128})", // SHA512
    );
    // error checking omitted b/c we've already validated this
    // regex string as correct
    Regex::new(&STR_REGEX).unwrap()
}*/

///////////////////////////////////////////////////////////////////////////////
/// TESTS
///////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod test;
