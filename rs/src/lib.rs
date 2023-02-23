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
    std::thread,
    threadpool::ThreadPool,
    walkdir::WalkDir,
};

// TODO - remove public fields
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileData {
    pub size: u64,
    pub path: PathBuf,
    pub expected_hash: String,
}

//#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
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

////////////////////////////////////////////////////////////////////////////////////////
/// Create thread pool with one thread per processor
pub fn create_threadpool() -> Result<ThreadPool, String> {
    let num_threads = match thread::available_parallelism() {
        Ok(v) => v.get(),
        Err(_e) => {
            return Err(format!("{}: Couldn't get number of available threads", _e));
        }
    };
    Ok(ThreadPool::new(num_threads))
}

////////////////////////////////////////////////////////////////////////////////////////
/// Recursively enumerates an absolute (canonicalized) path,
/// returns Result<Vec<FileData>, String>, sorted smallest file to largest
pub fn recursive_dir(abs_root_path: &Path) -> Result<Vec<FileData>, String> {
    let mut file_vec = Vec::<FileData>::new();
    let mut files_added: i32 = 0;
    for entry in WalkDir::new(abs_root_path)
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
    // Sort vector by file size, smallest first
    println!("[*] Sorting files by size");
    file_vec.sort_by(|a, b| a.size.cmp(&b.size));
    Ok(file_vec)
}

////////////////////////////////////////////////////////////////////////////////////////
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

////////////////////////////////////////////////////////////////////////////////////////
fn canonicalize_split_filepath(
    splitline: &Vec<&str>,
    hashpath: &PathBuf,
) -> Result<PathBuf, String> {
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
    let canonical_result = fs::canonicalize(&file_path_buf).or_else(|err| {
        return Err(format!(
            "{}: Could not canonicalize the path '{}'",
            err, file_path
        ));
    });
    canonical_result
}

////////////////////////////////////////////////////////////////////////////////////////
/// Checks the hashval to see if it is a valid hex string. Used in the case that
/// we want to slim down the final binary by removing the Regex crate
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

////////////////////////////////////////////////////////////////////////////////////////
/// From the hashfile, BufReader will return one line at a time. Check if line
/// is in the format <HEX STRING> <FILE PATH>. If Ok(), then canonicalize
/// the file path (if the file actually exists) and return the path and hex string
fn split_hashfile_line(
    newline: &String,
    hashpath: &PathBuf,
    // regex_pattern: &Regex,
) -> Result<(String, PathBuf), String> {
    let splitline: Vec<&str> = newline.split_whitespace().collect();
    if splitline.len() < 2 {
        return Err(format!("Line does not have enough elements: {}", newline));
    }
    let hashval: &str = splitline[0];
    //if !regex_pattern.is_match(hashval) {
    if !hexstring_is_valid(hashval) {
        return Err("Line does not start with a valid hex string".to_string());
    }

    let canonical_path = match canonicalize_split_filepath(&splitline, hashpath) {
        Ok(v) => v,
        Err(err) => {
            println!("{}", err);
            return Err(err);
        }
    };

    Ok((hashval.to_string(), canonical_path))
}

////////////////////////////////////////////////////////////////////////////////////////
/// Load hashes from single hash file
/// Takes Regex as argument to avoid repeated computation of it
fn load_hashes_single(
    path: &PathBuf,
    hashmap: &mut HashMap<PathBuf, String>,
    // regex_pattern: &Regex,
) -> Result<(), String> {
    // get the directory name of the hashfile (should already be in canonical form)
    let mut hashpath = path.clone();
    hashpath.pop();

    // Open file
    let file = File::open(path).or_else(|err| {
        return Err(format!(
            "{} : Hashfile '{}' cannot be opened, trying any others",
            path.display(),
            err
        ));
    })?;

    // Read file
    let reader = BufReader::new(file);
    let mut num_lines: i32 = 0;
    for line in reader.lines() {
        let newline = line.or_else(|err| {
            return Err(format!(
                "{} : Line from file '{}' cannot be read",
                path.display(),
                err
            ));
        })?;

        let (hashval, canonical_path) =
            match split_hashfile_line(&newline, &hashpath /*regex_pattern*/) {
                Ok(v) => v,
                Err(_e) => {
                    println!(
                        "[!] Failed to parse {}, ignore and continue parsing",
                        newline
                    );
                    continue;
                } //return Err(_e),
            };
        hashmap.insert(canonical_path, hashval);
        num_lines += 1;
        if num_lines % 500 == 0 {
            println!("[*] {} hashes read from {}", num_lines, path.display());
        }
    }
    Ok(())
}

////////////////////////////////////////////////////////////////////////////////////////
/// Loads the expected hashes for a directory from a hashfile,
/// expects the file format to be "[hex string] [relative file path]"
pub fn load_hashes(
    hashfiles: &Vec<FileData>,
    num_checked_files: usize,
) -> Result<HashMap<PathBuf, String>, String> {
    let mut hash_vec: HashMap<PathBuf, String> = HashMap::new();
    hash_vec.reserve(num_checked_files);
    // let regex_pattern = hash_hexpattern();

    for f in hashfiles {
        // TODO - error handling case. Normally, just continue through all
        // hashfiles
        let _e = load_hashes_single(&f.path, &mut hash_vec /*&regex_pattern*/);
    }

    if hash_vec.len() == 0 {
        return Err("No hashes read from hashfiles".to_string());
    }
    Ok(hash_vec)
}

////////////////////////////////////////////////////////////////////////////////////////
// You can use something like this when parsing user input, CLI arguments, etc.
// DynDigest needs to be boxed here, since function return should be sized.
// TODO - create a version of MD5 that implements the new(), update(), and finalize()
// interfaces
fn select_hasher(alg: HashAlg) -> Box<dyn DynDigest> {
    match alg {
        HashAlg::MD5 => Box::new(md5::Md5::default()),
        HashAlg::SHA1 => Box::new(sha1::Sha1::default()),
        HashAlg::SHA224 => Box::new(sha2::Sha224::default()),
        HashAlg::SHA256 => Box::new(sha2::Sha256::default()),
        HashAlg::SHA384 => Box::new(sha2::Sha384::default()),
        HashAlg::SHA512 => Box::new(sha2::Sha512::default()),
        // _ => unimplemented!("unsupported digest: {}", alg),
    }
}

////////////////////////////////////////////////////////////////////////////////////////
/// Compute the hash of a given file
fn hash_file(path: &PathBuf, alg: HashAlg) -> Result<String, String> {
    // file existence check performed earlier, though we could put one here for completeness
    let mut hasher = select_hasher(alg);

    // open file and read data into heap-based buffer
    const BUFSIZE: usize = 1024 * 1024 * 2; // 2 MB
    let mut buffer: Box<[u8]> = vec![0; BUFSIZE].into_boxed_slice();
    let mut file = File::open(path).or_else(|err| {
        return Err(format!("{}: Unable to open file", err));
    })?;

    loop {
        let read_count = file.read(&mut buffer[..BUFSIZE]).or_else(|err| {
            return Err(format!("{}: Read failure", err));
        })?;
        hasher.update(&buffer[..read_count]);
        if read_count < BUFSIZE {
            break;
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

static mut HASHES_COMPLETE: AtomicUsize = AtomicUsize::new(1);
////////////////////////////////////////////////////////////////////////////////////////
/// Thread safe function called whenever a hash has been computed
pub fn increment_hashcount() {
    unsafe {
        HASHES_COMPLETE.fetch_add(1, Ordering::SeqCst);
    }
}

////////////////////////////////////////////////////////////////////////////////////////
/// Thread safe function that prints out how many files are left to be hashed
pub fn hashcount_monitor(total_files: usize) {
    if total_files == 0 {
        println!("[!] No files to hash");
        return;
    }
    let curr_hashes: usize = unsafe { HASHES_COMPLETE.load(Ordering::SeqCst) };
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

////////////////////////////////////////////////////////////////////////////////////////
/// Thread function that opens file, hashes, and compares with expected hash
pub fn perform_hash(
    fdata: FileData,
    alg: HashAlg,
    force: bool,
    verbose: bool,
    num_files: usize,
) -> Result<bool, String> {
    let success: bool;
    increment_hashcount();
    let actual_hash = hash_file(&fdata.path, alg)?;
    if force {
        println!(
            "[*] Checksum value : {:?}\n\tHash         : {:?}",
            &fdata.path, actual_hash
        );
        success = true;
    } else {
        // Compare
        success = &fdata.expected_hash == &actual_hash;
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
    hashcount_monitor(num_files);
    Ok(success)
}

////////////////////////////////////////////////////////////////////////////////////////
/// Checks to see if a file path matches a regular expression
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

////////////////////////////////////////////////////////////////////////////////////////
/// Given a thread pool, start hashing all files based on hashes in a hash file
pub fn start_hash_threads(
    pool: &mut ThreadPool,
    all_files: Vec<FileData>,
    hash_regex: &Regex,
    args: Arguments,
) -> Result<usize, String> {
    const EMPTY_STRING: String = String::new();
    let num_files: usize;
    let checked_files: Vec<FileData>;
    let expected_hashes: HashMap<PathBuf, String>;
    {
        // Scope so hashfiles drops once it is finished being processed
        println!("[+] Identifying hashfiles");
        let hashfiles: Vec<FileData>;
        (hashfiles, checked_files) = all_files
            .into_iter()
            .partition(|f| path_matches_regex(hash_regex, &f.path));

        println!("[+] Loading expected hashes from {:?}", hashfiles);
        expected_hashes = match load_hashes(&hashfiles, checked_files.len()) {
            Ok(v) => v,
            Err(_e) => {
                if args.force {
                    println!("[!*] No hashes available: {}", _e);
                    println!("[*] --force called, computing hashes anyway");
                    HashMap::<PathBuf, String>::new()
                } else {
                    return Err(format!("[!*] No hashes available: {}", _e));
                }
            }
        };
        // End hashfiles scope
    }

    // load expected hash value into each checked_files entry
    // since checked_files is in file-size order (smallest to largest)
    // this function should process the very smallest files first
    println!(
        "[+] Checking hashes - spinning up {} worker threads",
        pool.max_count()
    );

    num_files = checked_files.len();
    for ck in checked_files {
        if !&expected_hashes.contains_key(&ck.path) {
            if !args.force {
                println!("[!] {:?} => No hash found", &ck.path);
                increment_hashcount();
                continue;
            }
        }
        let mut expected_fdata: FileData = ck.clone();
        expected_fdata.expected_hash = expected_hashes
            .get(&ck.path)
            .unwrap_or(&EMPTY_STRING)
            .to_string();

        pool.execute(move || {
            perform_hash(
                expected_fdata,
                args.algorithm,
                args.force,
                args.verbose,
                num_files,
            )
            .unwrap_or_else(move |_| {
                println!("[!] Failed to start thread for {}", &ck.path.display());
                true
            });
        });
    }
    // end checked_files and expected_hashes scope
    Ok(num_files)
}
///////////////////////////////////////////////////////////////////////////////
/// TESTS
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod test;
