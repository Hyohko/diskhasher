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
    indicatif::style::TemplateError,
    indicatif::{MultiProgress, ProgressBar, ProgressFinish, ProgressStyle},
    regex::Regex,
    std::cmp::Reverse,
    std::collections::HashMap,
    std::fmt::{self, Display, Formatter},
    std::fs,
    std::fs::File,
    std::io::{BufRead, BufReader, Read, Write},
    std::mem,
    std::path::{Path, PathBuf},
    std::sync::{Arc, Mutex},
    std::thread,
    std::time::Duration,
    threadpool::ThreadPool,
    walkdir::WalkDir,
};

#[cfg(target_os = "linux")]
use std::{
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

// TODO - remove public fields
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FileData {
    size: u64,
    path: PathBuf,
    inode: u64,
    expected_hash: String,
}

impl FileData {
    fn new(size: u64, path: PathBuf, inode: u64) -> Self {
        FileData {
            size,
            path,
            inode,
            expected_hash: String::new(),
        }
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn path(&self) -> &PathBuf {
        &self.path
    }
    fn inode(&self) -> u64 {
        self.inode
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
pub enum FileSortLogic {
    LargestFirst,
    SmallestFirst,
    InodeOrder,
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
    StyleError{why: String} = "ProgressBar style error => {why}"
}

impl From<TemplateError> for HasherError {
    fn from(error: TemplateError) -> Self {
        StyleError {
            why: format!("{:?}", error),
        }
    }
}

// todo https://stackoverflow.com/questions/53934888/how-to-include-the-file-path-in-an-io-error-in-rust
impl From<std::io::Error> for HasherError {
    fn from(error: std::io::Error) -> Self {
        HasherError::IoError {
            why: format!("{:?} => {:?}", error.kind(), error),
        }
    }
}

use crate::HasherError::*;
#[derive(Debug, Clone)]
pub struct Hasher {
    pool: ThreadPool,
    alg: HashAlg,
    root: PathBuf,
    hash_regex: Regex,
    hashfiles: Vec<FileData>,
    checkedfiles: Vec<FileData>,
    hashmap: HashMap<PathBuf, String>,
    loghandle: Option<Arc<Mutex<File>>>,
    mp: MultiProgress, // is an Arc type
}

impl Hasher {
    // Public Interface Functions
    pub fn new(
        alg: HashAlg,
        root_dir: String,
        hashfile_pattern: String,
        logfile: Option<String>,
        num_threads: Option<usize>,
    ) -> Result<Self, HasherError> {
        let hash_regex = Regex::new(&hashfile_pattern).map_err(|err| RegexError {
            why: format!("'{hashfile_pattern}' returns error {err}"),
        })?;

        let root = canonicalize_path(&root_dir, FileType::IsDir)?;

        let mut avail_threads = thread::available_parallelism()
            .map_err(|err| ThreadingError {
                why: format!("{err}: Couldn't get number of available threads"),
            })?
            .get();

        if let Some(total_threads) = num_threads {
            if total_threads > avail_threads {
                warn!("[!] Only {avail_threads} threads available");
            } else {
                avail_threads = total_threads
            }
            info!("[+] Allocating {avail_threads} worker threads in the thread pool");
        } else {
            // cap total running threads at the num of cores or 12 threads (which is plenty),
            // whatever is smaller. Much larger than this and it screws
            // up the progress bar rendering, though we still let the user shoot their
            // own feet in the if let above.
            avail_threads = std::cmp::min(avail_threads, 12);
            info!("[+] Defaulting to {avail_threads} worker threads, use '--jobs' arg to change");
        }

        // As much as I hate this construction, there's no more efficient
        // way to make it idiomatic Rust
        let loghandle = match logfile {
            Some(v) => {
                info!("[+] Logging failed hashes to {v}");
                let handle = File::create(&v)?;
                Some(Arc::new(Mutex::new(handle)))
            }
            None => None,
        };

        let mp = MultiProgress::new();

        Ok(Hasher {
            pool: ThreadPool::new(avail_threads),
            alg,
            root,
            hash_regex,
            hashfiles: vec![],
            checkedfiles: vec![],
            hashmap: [].into(),
            loghandle,
            mp,
        })
    }

    pub fn run(
        &mut self,
        force: bool,
        verbose: bool,
        sort_order: FileSortLogic,
    ) -> Result<(), HasherError> {
        self.recursive_dir(force)?;
        if let Err(err) = self.load_hashes() {
            match force {
                true => {
                    warn!("[+] No valid hashfile, but --force flag set");
                }
                false => {
                    return Err(err);
                }
            }
        };
        self.sort_checked_files(sort_order);
        self.start_hash_threads(force, verbose)?;
        self.join()?;
        Ok(())
    }

    fn join(&self) -> Result<(), HasherError> {
        self.pool.join();
        Ok(())
    }

    fn load_hashes(&mut self) -> Result<(), HasherError> {
        self.hashmap.reserve(self.checkedfiles.len());

        let spinner = self.create_spinner(String::from("[+] Parsing hashes from hashfiles"))?;
        let mut total_lines: i32 = 0;
        for f in &self.hashfiles {
            let mut hashpath = f.path().clone();
            hashpath.pop();

            let file = File::open(f.path()).map_err(|err| FileError {
                why: format!("{err} : Hashfile cannot be opened"),
                path: f.path_string(),
            })?;

            let reader = BufReader::new(file);
            for line in reader.lines() {
                let newline = line.map_err(|err| FileError {
                    why: format!("{err} : Line from file cannot be read"),
                    path: f.path_string(),
                })?;

                let (hashval, canonical_path) = match split_hashfile_line(&newline, &hashpath) {
                    Ok(v) => v,
                    Err(err) => {
                        error!("[!] {err} : Failed to parse line from hashfile :: '{newline}'");
                        continue;
                    }
                };
                self.hashmap.insert(canonical_path, hashval);
                total_lines += 1;
                spinner.inc(1);
            }
        }
        self.mp.remove(&spinner);

        if self.hashmap.is_empty() {
            Err(HashError {
                why: String::from("No hashes read from hashfiles"),
            })
        } else {
            info!("[*] {total_lines} hashes read from all hashfiles");
            Ok(())
        }
    }

    fn create_spinner(&self, msg: String) -> Result<ProgressBar, HasherError> {
        let spinner_style =
            ProgressStyle::with_template("[{spinner:.cyan.bold}] (# {pos:.green}) {wide_msg}")?
                .tick_chars("/|\\- ");
        let spinner = self.mp.add(
            ProgressBar::new_spinner()
                .with_style(spinner_style)
                .with_finish(ProgressFinish::AndLeave)
                .with_message(msg),
        );
        spinner.enable_steady_tick(Duration::from_millis(120));
        Ok(spinner)
    }

    fn recursive_dir(&mut self, force: bool) -> Result<(), HasherError> {
        let mut file_vec = Vec::<FileData>::new();

        let spinner = self.create_spinner(format!("[+] Recursing through {:?}", self.root))?;
        for entry in WalkDir::new(&self.root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path().to_path_buf();
            let size = path.metadata()?.len();
            let inode = path.metadata()?.ino();
            file_vec.push(FileData::new(size, path, inode));
            spinner.inc(1);
        }
        self.mp.remove(&spinner);

        // Split the file vec into hash files and non-hashfiles
        info!("[+] Identifying hashfiles");
        (self.hashfiles, self.checkedfiles) = file_vec
            .into_iter()
            .partition(|f| path_matches_regex(&self.hash_regex, f.path()));
        if self.hashfiles.is_empty() {
            let reason = String::from("No hashfiles matched the hashfile pattern");
            if !force {
                return Err(RegexError { why: reason });
            } else {
                warn!("[-] {reason}");
            }
        }
        info!("[*] {} files in the queue", self.checkedfiles.len());
        Ok(())
    }

    fn sort_checked_files(&mut self, sort_order: FileSortLogic) {
        // actual testing indicates that the Reverse sort order puts smallest first, for some reason...
        match sort_order {
            FileSortLogic::InodeOrder => {
                info!("[*] Sorting files by inode");
                self.checkedfiles
                    .sort_unstable_by_key(|a| Reverse(a.inode()));
            }
            FileSortLogic::SmallestFirst => {
                info!("[*] Sorting files by size, smallest first");
                self.checkedfiles
                    .sort_unstable_by_key(|a| Reverse(a.size()));
            }
            FileSortLogic::LargestFirst => {
                info!("[*] Sorting files by size, largest first");
                self.checkedfiles.sort_unstable_by_key(|a| a.size());
            }
        }
    }

    fn start_hash_threads(&mut self, force: bool, verbose: bool) -> Result<usize, HasherError> {
        info!(
            "[+] Checking hashes - spinning up {} worker threads",
            self.pool.max_count()
        );

        let num_files = self.checkedfiles.len();
        let style: ProgressStyle = ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.red/magenta} ({percent:2}%) {pos:>7.green}/{len:7.green} * Total File Progress *",
        )?
        .progress_chars("==>");
        let bar = self
            .mp
            .add(ProgressBar::new(num_files as u64).with_style(style));
        while let Some(mut ck) = self.checkedfiles.pop() {
            match self.hashmap.remove(ck.path()) {
                Some(mut v) => {
                    ck.set_hash(&mut v);
                }
                None => {
                    if !force {
                        warn!("[!] {:?} => No hash found", ck.path());
                        bar.inc(1);
                        continue;
                    }
                }
            };
            let alg = self.alg;
            let loghandle = self.loghandle.clone();
            // after this point, avoid more stdout/stderr prints
            let mp = self.mp.clone();
            let bar = bar.clone();
            self.pool.execute(move || {
                perform_hash_threadfunc(ck, alg, force, verbose, loghandle, mp, bar).ok();
            });
        } // end while
        Ok(num_files)
    }
}

// Static Functions
fn canonicalize_path(path: &String, filetype: FileType) -> Result<PathBuf, HasherError> {
    let root_path = fs::canonicalize(Path::new(&path))?;
    match filetype {
        FileType::IsDir => {
            if !root_path.is_dir() {
                Err(FileError {
                    why: String::from("Path is not a valid directory"),
                    path: root_path.display().to_string(),
                })
            } else {
                Ok(root_path)
            }
        }
        FileType::IsFile => {
            if !root_path.is_file() {
                Err(FileError {
                    why: String::from("Path is not a valid file"),
                    path: root_path.display().to_string(),
                })
            } else {
                Ok(root_path)
            }
        }
    }
}

fn canonicalize_split_filepath(
    splitline: &[&str],
    hashpath: &Path,
) -> Result<PathBuf, HasherError> {
    let file_path = splitline[1..].join(" ");

    let mut file_path_buf: PathBuf = Path::new(&file_path).to_path_buf();
    if file_path_buf.is_absolute() {
        return Ok(file_path_buf);
    }
    if !file_path.starts_with("./") {
        let new_file_path: String = format!("./{file_path}");
        file_path_buf = Path::new(&new_file_path).to_path_buf();
    }
    file_path_buf = hashpath.join(&file_path_buf);
    let canonical_result =
        canonicalize_path(&file_path_buf.display().to_string(), FileType::IsFile)?;
    Ok(canonical_result)
}

#[cfg(target_os = "linux")]
#[repr(C, align(4096))]
struct AlignedHashBuffer([u8; SIZE_2MB]);

const SIZE_2MB: usize = 1024 * 1024 * 2; // 2 MB
const SIZE_128MB: usize = 1024 * 1024 * 128;
const O_DIRECT: i32 = 0x4000; // Linux

fn hash_file(
    path: &PathBuf,
    file_size: u64,
    alg: HashAlg,
    mp: &MultiProgress,
) -> Result<String, HasherError> {
    let mut hasher = select_hasher(alg);

    #[cfg(not(target_os = "linux"))]
    let mut buffer: Box<[u8]> = vec![0; BUFSIZE].into_boxed_slice();

    #[cfg(target_os = "linux")]
    let mut buffer: Box<AlignedHashBuffer> = Box::new(AlignedHashBuffer([0u8; SIZE_2MB]));

    let style: ProgressStyle = ProgressStyle::with_template(
        "[{elapsed_precise}] {bar:40.cyan/blue} ({percent:2}%) {msg}",
    )?
    .progress_chars("##-");
    let bar = mp.add(ProgressBar::new(file_size).with_style(style));

    // This is dumb, but the only way to get a valid, borrowable reference in Rust;
    // we have to add - then remove - the progress bar because we want the bar
    // only to display if files are larger than 128MB
    let display_bar: bool = file_size > SIZE_128MB as u64;
    if display_bar {
        bar.set_message(format!("{:?}", path.file_name().unwrap()));
    } else {
        mp.remove(&bar);
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECT)
        .open(path)?;
    loop {
        let read_count: usize;
        #[cfg(target_os = "linux")]
        {
            read_count = file.read(&mut buffer.0[..SIZE_2MB])?;
            hasher.update(&buffer.0[..read_count]);
        }

        #[cfg(not(target_os = "linux"))]
        {
            read_count = file.read(&mut buffer[..SIZE_2MB])?;
            hasher.update(&buffer[..read_count]);
        }
        if display_bar {
            bar.inc(read_count as u64);
        }
        if read_count < SIZE_2MB {
            break;
        }
    }
    if display_bar {
        bar.finish_and_clear();
        mp.remove(&bar);
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
    Regex::new(STR_REGEX).expect("[!] Regular expression engine startup failure")
}

fn path_matches_regex(hash_regex: &Regex, file_path: &Path) -> bool {
    if let Some(path) = file_path.file_name() {
        if let Some(str_path) = path.to_str() {
            hash_regex.is_match(str_path)
        } else {
            error!("[-] Failed to convert path to string");
            false
        }
    } else {
        error!("[-] Failed to retrieve file name from path object");
        false
    }
}

fn perform_hash_threadfunc(
    fdata: FileData,
    alg: HashAlg,
    force: bool,
    verbose: bool,
    loghandle: Option<Arc<Mutex<File>>>,
    mp: MultiProgress,           // is already an Arc
    total_progress: ProgressBar, // is already an Arc
) -> Result<(), HasherError> {
    total_progress.inc(1);
    let actual_hash = hash_file(fdata.path(), fdata.size(), alg, &mp)?;
    if force {
        let result = format!(
            "[*] Checksum value :\n\t{:?}\n\tHash         : {:?}\n",
            fdata.path(),
            actual_hash
        );
        mp.println(&result).ok();
        write_to_log(&result, &loghandle);
    } else {
        // Compare
        if fdata.hash() == &actual_hash {
            if verbose {
                let result = format!(
                    "[+] Checksum passed:\n\t{:?}\n\tActual hash  : {:?}\n",
                    fdata.path(),
                    actual_hash
                );
                mp.println(&result).ok();
                write_to_log(&result, &loghandle);
            }
        } else {
            let result = format!(
                "[-] Checksum failed:\n\t{:?}\n\tExpected hash: {:?}\n\tActual hash  : {:?}\n",
                fdata.path(),
                fdata.hash(),
                actual_hash
            );
            mp.println(&result).ok();
            write_to_log(&result, &loghandle);
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
    hashpath: &Path,
) -> Result<(String, PathBuf), HasherError> {
    let splitline: Vec<&str> = newline.split_whitespace().collect();
    if splitline.len() < 2 {
        return Err(ParseError {
            why: format!("Line does not have enough elements: {newline}"),
        });
    }
    let hashval: &str = splitline[0];
    //if !HEXSTRING_PATTERN.is_match(hashval) {
    validate_hexstring(hashval)?;
    let canonical_path = canonicalize_split_filepath(&splitline, hashpath)?;
    Ok((String::from(hashval), canonical_path))
}

fn validate_hexstring(hexstring: &str) -> Result<(), HasherError> {
    let hexlen = hexstring.len();
    match hexlen {
        32 | 40 | 56 | 64 | 96 | 128 => {
            for chr in hexstring.chars() {
                if !chr.is_ascii_hexdigit() {
                    return Err(ParseError {
                        why: String::from("Non-hex character found"),
                    });
                }
            }
            Ok(())
        }
        _ => Err(ParseError {
            why: format!("Bad hexstring length: {hexlen}"),
        }),
    }
}

fn write_to_log(msg: &String, loghandle: &Option<Arc<Mutex<File>>>) {
    if let Some(handle) = loghandle {
        let mut guarded_filehandle = handle.lock().expect("Mutex unlock failure - Panic!");
        (*guarded_filehandle).write(msg.as_bytes()).ok();
    }
}
///////////////////////////////////////////////////////////////////////////////
/// TESTS
///////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod test;
