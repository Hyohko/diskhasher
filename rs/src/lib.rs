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
#![warn(
    clippy::all,
    clippy::restriction,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]
// todo!("remove these lints before merge");

extern crate pretty_env_logger;
#[macro_use]
extern crate log;

use {
    aligned_box::AlignedBox,
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
    walkdir::{DirEntry, WalkDir},
};

#[cfg(target_os = "linux")]
use std::{
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

/// Internal structure that tracks files being sent to the
/// hasher thread pool
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FileData {
    size: u64,
    path: PathBuf,
    inode: u64,
    expected_hash: String,
}

impl FileData {
    /// FileData constructor
    fn new(size: u64, path: PathBuf, inode: u64) -> Self {
        Self {
            size,
            path,
            inode,
            expected_hash: String::new(),
        }
    }
    /// Size of referenced file
    fn size(&self) -> u64 {
        self.size
    }
    /// Path to referenced file
    fn path(&self) -> &PathBuf {
        &self.path
    }
    /// [linux] Inode of referenced file
    fn inode(&self) -> u64 {
        self.inode
    }
    /// File path as a string for debug prints
    fn path_string(&self) -> String {
        self.path.display().to_string()
    }
    /// Cryptographic hash as hexstring
    fn hash(&self) -> &String {
        &self.expected_hash
    }
    /// Permits setting of the hash value during computation
    fn set_hash(&mut self, hash: &mut String) {
        self.expected_hash = mem::take(hash);
    }
}

impl TryFrom<DirEntry> for FileData {
    type Error = HasherError;
    fn try_from(entry: DirEntry) -> Result<Self, HasherError> {
        let path = entry.path().to_path_buf();
        let metadata = path.metadata()?;
        Ok(Self::new(metadata.len(), path, metadata.ino()))
    }
}

/// Internal file type for path canonicalization
enum FileType {
    IsDir,
    IsFile,
}

/// Option to command line args - sort files from WalkDir
/// by LargestFirst, SmallestFirst, or in InodeOrder
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum FileSortLogic {
    LargestFirst,
    SmallestFirst,
    InodeOrder,
}

/// Supported hash algorithms
#[non_exhaustive]
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
            why: format!("{error:?}"),
        }
    }
}

// todo https://stackoverflow.com/questions/53934888/how-to-include-the-file-path-in-an-io-error-in-rust
impl From<std::io::Error> for HasherError {
    fn from(error: std::io::Error) -> Self {
        HasherError::IoError {
            why: format!("{:?} => {error:?}", error.kind()),
        }
    }
}

use crate::HasherError::*;

/// This is our primary object, and we can construct one for every
/// root directory we want to inspect.
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
    /// Hasher constructor function - from the arguments, we take the algorithm,
    /// the root directory to compute hashes on, the pattern of (if any) hash files
    /// we need to parse, the (optional) path to our results log file, and the
    /// number of concurrent jobs we will run.
    pub fn new(
        alg: HashAlg,
        root_dir: String,
        hashfile_pattern: String,
        logfile: Option<String>,
        jobs: Option<usize>,
    ) -> Result<Self, HasherError> {
        const STACKSIZE_8MB: usize = 8 * 1024 * 1024;
        let hash_regex = Regex::new(&hashfile_pattern).map_err(|err| RegexError {
            why: format!("'{hashfile_pattern}' returns error {err}"),
        })?;

        let root = canonicalize_path(&root_dir, &FileType::IsDir)?;

        let mut avail_threads = thread::available_parallelism()
            .map_err(|err| ThreadingError {
                why: format!("{err}: Couldn't get number of available threads"),
            })?
            .get();

        if let Some(total_threads) = jobs {
            if total_threads > avail_threads {
                warn!("[!] Only {avail_threads} threads available");
            } else {
                avail_threads = total_threads;
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
        Ok(Self {
            // The debug version is likely allocating the
            // hash buffer on the stack (instead of the Box on the heap)
            // Give each thread a larger stack size
            pool: threadpool::Builder::new()
                .thread_stack_size(STACKSIZE_8MB)
                .num_threads(avail_threads)
                .build(),
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

    /// Once the Hasher object is constructed, we can then begin computation.
    /// The --force option will force hash computation even if no hashfiles
    /// match our pattern, and --verbose will print all results to STDOUT.
    /// We can choose the order in which files will be computed: largest-first,
    /// smallest-first, or in inode order (which may be faster for disk I/O)
    pub fn run(
        &mut self,
        force: bool,
        verbose: bool,
        sort_order: FileSortLogic,
    ) -> Result<(), HasherError> {
        let file_vec = self.recursive_dir()?;
        self.identify_hashfiles(file_vec, force)?;
        if let Err(err) = self.load_hashes() {
            if force {
                warn!("[+] No valid hashfile, but --force flag set");
            } else {
                return Err(err);
            }
        }
        self.sort_checked_files(sort_order);
        self.start_hash_threads(force, verbose)?;
        self.pool.join();
        Ok(())
    }

    fn load_hashes(&mut self) -> Result<(), HasherError> {
        self.hashmap.reserve(self.checkedfiles.len());

        let spinner = self.create_spinner(String::from("[+] Parsing hashes from hashfiles"))?;
        for f in &self.hashfiles {
            let mut hashpath = f.path().clone();
            hashpath.pop();

            let file = File::open(f.path()).map_err(|err| FileError {
                why: format!("{err} : Hashfile cannot be opened"),
                path: f.path_string(),
            })?;

            let reader = BufReader::new(file);
            for line in spinner.wrap_iter(reader.lines()) {
                let newline = line?;
                match split_hashfile_line(&newline, &hashpath) {
                    Ok(v) => self.hashmap.insert(v.0, v.1),
                    Err(err) => {
                        error!("[!] {err} : Failed to parse line from hashfile :: {newline}");
                        continue;
                    }
                };
            }
        }

        self.hashmap.shrink_to_fit();
        if self.hashmap.is_empty() {
            Err(HashError {
                why: String::from("No hashes read from hashfiles"),
            })
        } else {
            info!("[*] {} hashes read from all hashfiles", spinner.position());
            self.mp.remove(&spinner);
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

    fn identify_hashfiles(
        &mut self,
        file_vec: Vec<FileData>,
        force: bool,
    ) -> Result<(), HasherError> {
        // Split the file vec into hash files and non-hashfiles
        info!("[+] Identifying hashfiles");
        (self.hashfiles, self.checkedfiles) = file_vec
            .into_iter()
            .partition(|f| path_matches_regex(&self.hash_regex, f.path()));
        if self.hashfiles.is_empty() {
            let reason = String::from("No hashfiles matched the hashfile pattern");
            if force {
                warn!("[-] {reason}");
            } else {
                return Err(RegexError { why: reason });
            }
        }
        info!("[*] {} files in the queue", self.checkedfiles.len());
        Ok(())
    }

    fn recursive_dir(&mut self) -> Result<Vec<FileData>, HasherError> {
        let mut file_vec = Vec::<FileData>::new();

        let spinner = self.create_spinner(format!("[+] Recursing through {:?}", self.root))?;
        for entry in spinner
            .wrap_iter(WalkDir::new(&self.root).into_iter())
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
        {
            file_vec.push(FileData::try_from(entry)?);
        }
        self.mp.remove(&spinner);
        Ok(file_vec)
    }

    fn sort_checked_files(&mut self, sort_order: FileSortLogic) {
        // since we are popping off the last element of the vec to process it, in the instance
        // of Largest-First hashing, the largest needs to be at the end of the vec, and
        // vice versa for smallest.
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
                self.checkedfiles.sort_unstable_by_key(FileData::size);
            }
        }
    }

    fn spawn_single_job(
        &mut self,
        file_data: &FileData,
        bar: &ProgressBar,
        force: bool,
        verbose: bool,
    ) {
        let mut fd_clone = file_data.clone();
        if let Some(mut v) = self.hashmap.remove(file_data.path()) {
            fd_clone.set_hash(&mut v);
        } else {
            if !force {
                warn!("[!] {:?} => No hash found", file_data.path());
                bar.inc(1);
                return;
            }
        }
        // after this point, avoid more stdout/stderr prints
        let alg = self.alg;
        let mp = self.mp.clone();
        let loghandle = self.loghandle.clone();
        let bar = bar.clone();
        self.pool.execute(move || {
            perform_hash_threadfunc(fd_clone, alg, force, verbose, loghandle, mp, bar).ok();
        });
    }

    fn start_hash_threads(&mut self, force: bool, verbose: bool) -> Result<usize, HasherError> {
        info!(
            "[+] Checking hashes - spinning up {} worker threads",
            self.pool.max_count()
        );

        let num_files = self.checkedfiles.len();
        let style: ProgressStyle = ProgressStyle::with_template(
            "[{elapsed_precise}] ({percent:3}%) {bar:30.red/magenta} {pos:>10.green}/{len:<10.green} * Total File Progress *",
        )?
        .progress_chars("==>");
        let bar = self
            .mp
            .add(ProgressBar::new(num_files as u64).with_style(style));
        while let Some(ck) = self.checkedfiles.pop() {
            self.spawn_single_job(&ck, &bar, force, verbose);
            // every 5000 hashes, shrink the memory space of the hashmap
            if num_files % 5000 == 0 {
                self.hashmap.shrink_to_fit();
                self.checkedfiles.shrink_to_fit();
            }
        }
        Ok(num_files)
    }
}

// Static Functions
fn canonicalize_path(path: &String, filetype: &FileType) -> Result<PathBuf, HasherError> {
    let root_path = fs::canonicalize(Path::new(&path))?;
    match filetype {
        FileType::IsDir => {
            if root_path.is_dir() {
                Ok(root_path)
            } else {
                Err(FileError {
                    why: String::from("Path is not a valid directory"),
                    path: root_path.display().to_string(),
                })
            }
        }
        FileType::IsFile => {
            if root_path.is_file() {
                Ok(root_path)
            } else {
                Err(FileError {
                    why: String::from("Path is not a valid file"),
                    path: root_path.display().to_string(),
                })
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
        Ok(file_path_buf)
    } else {
        if !file_path.starts_with("./") {
            let new_file_path: String = format!("./{file_path}");
            file_path_buf = Path::new(&new_file_path).to_path_buf();
        }
        file_path_buf = hashpath.join(&file_path_buf);
        let canonical_result =
            canonicalize_path(&file_path_buf.display().to_string(), &FileType::IsFile)?;
        Ok(canonical_result)
    }
}

const SIZE_2MB: usize = 1024 * 1024 * 2; // 2 MB
const SIZE_128MB: usize = 1024 * 1024 * 128;
const O_DIRECT: i32 = 0x4000; // Linux
const ALIGNMENT: usize = 0x1000; //4096

fn hash_file(fdata: &FileData, alg: HashAlg, mp: &MultiProgress) -> Result<String, HasherError> {
    let mut hasher: Box<dyn DynDigest> = select_hasher(alg);
    let mut read_count: usize;

    #[cfg(not(target_os = "linux"))]
    let mut buffer: Box<[u8]> = vec![0; BUFSIZE].into_boxed_slice();
    #[cfg(target_os = "linux")]
    let mut buffer = AlignedBox::<[u8]>::slice_from_value(ALIGNMENT, SIZE_2MB, 0_u8).unwrap();
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECT)
        .open(fdata.path())?;

    if fdata.size() > SIZE_128MB as u64 {
        let style: ProgressStyle = ProgressStyle::with_template(
            "[{elapsed_precise}] ({percent:3}%) {bar:30.cyan/blue} {bytes:>10.green}/{total_bytes:<10.green} {msg}",
        )?
        .progress_chars("##-");
        let bar = mp.add(ProgressBar::new(fdata.size()).with_style(style));
        bar.set_message(format!("{:?}", fdata.path().file_name().unwrap()));
        loop {
            {
                read_count = bar.wrap_read(&file).read(&mut buffer[..SIZE_2MB])?;
                hasher.update(&buffer[..read_count]);
            }
            if read_count < SIZE_2MB {
                break;
            }
        }
        bar.finish_and_clear();
        mp.remove(&bar);
        drop(bar);
    } else {
        loop {
            {
                read_count = file.read(&mut buffer[..SIZE_2MB])?;
                hasher.update(&buffer[..read_count]);
            }
            if read_count < SIZE_2MB {
                break;
            }
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

/*use lazy_static::lazy_static;
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
}*/

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
    let actual_hash = hash_file(&fdata, alg, &mp)?;
    total_progress.inc(1);
    let result: String;
    if force {
        result = format!(
            "[*] Checksum value :\n\t{:?}\n\tHash         : {:?}\n",
            fdata.path(),
            actual_hash
        );
        // omitting zero-length hashes from console print in FORCE mode
        if fdata.size() > 0 {
            mp.println(&result).ok();
        }
        write_to_log(&result, &loghandle);
    } else {
        // Compare
        if fdata.hash() == &actual_hash {
            if verbose {
                result = format!(
                    "[+] Checksum passed:\n\t{:?}\n\tActual hash  : {:?}\n",
                    fdata.path(),
                    actual_hash
                );
                mp.println(&result).ok();
                write_to_log(&result, &loghandle);
            }
        } else {
            result = format!(
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

// Clippy would prefer a better default() invocation, but
// that is waaaayyy too verbose. Suppress for this function
#[allow(clippy::box_default)]
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
) -> Result<(PathBuf, String), HasherError> {
    let splitline: Vec<&str> = newline.split_whitespace().collect();
    if splitline.len() < 2 {
        Err(ParseError {
            why: format!("Line does not have enough elements: {newline}"),
        })
    } else {
        let hashval: &str = splitline[0];
        //alternate - !HEXSTRING_PATTERN.is_match(hashval), maybe someday
        validate_hexstring(hashval)?;
        let canonical_path = canonicalize_split_filepath(&splitline, hashpath)?;
        Ok((canonical_path, String::from(hashval)))
    }
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
