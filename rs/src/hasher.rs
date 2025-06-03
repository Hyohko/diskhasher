/*
    DKHASH - 2025 by Hyohko

    ##################################
    GPLv3 NOTICE AND DISCLAIMER
    ##################################

    This file is part of DKHASH.

    DKHASH is free software: you can redistribute it
    and/or modify it under the terms of the GNU General
    Public License as published by the Free Software
    Foundation, either version 3 of the License, or (at
    your option) any later version.

    DKHASH is distributed in the hope that it will
    be useful, but WITHOUT ANY WARRANTY; without even
    the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General
    Public License along with DKHASH. If not, see
    <https://www.gnu.org/licenses/>.
*/

use crate::{
    enums::{FileSortLogic, HashAlg},
    error::HasherError,
    filedata::FileData,
    threadfunc::{ThreadFuncArgs, perform_hash_threadfunc},
    util::{path_matches_regex, split_hashfile_line},
};

use {
    indicatif::{MultiProgress, ProgressBar, ProgressFinish, ProgressStyle},
    regex::Regex,
    std::{
        cmp::Reverse,
        collections::HashMap,
        fs::File,
        fs::canonicalize,
        io::{BufRead, BufReader},
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
        thread::available_parallelism,
        time::Duration,
    },
    threadpool::ThreadPool,
    walkdir::WalkDir,
};

// As much as I hate this construction, there's no more efficient
// way to make it idiomatic Rust b/c we want to propagate
// any errors from File::create
macro_rules! opt_open_file {
    ($logmsg:expr, $opt_filename:expr) => {
        match $opt_filename {
            Some(v_str) => {
                info!("[+] {} -> {}", $logmsg, v_str);
                match File::create(&v_str) {
                    Ok(file) => Some(Arc::new(Mutex::new(file))),
                    Err(e) => {
                        eprintln!("[ERROR] opt_open_file! failed to create file '{}': {}", v_str, e);
                        None
                    }
                }
            }
            None => None,
        }
    };
}

// The filelog macro was defined in macros.rs, but it's actually used by threadfunc.rs
// and its definition needs to be available to threadfunc.rs.
// For now, assuming it's globally available or correctly imported in threadfunc.rs.
// If it were here, the change would be:
// macro_rules! filelog {
//     ($msg:expr, $filehandleopt:expr) => {
//         if let Some(handle) = $filehandleopt {
//             let mut guarded_filehandle = handle.lock().expect("Mutex unlock failure - Panic!");
//             let write_result = (*guarded_filehandle).write_all($msg.as_bytes());
//             if let Err(e) = write_result {
//                 eprintln!("[ERROR] filelog! failed to write to file: {}", e);
//             } else {
//                 if let Err(e) = (*guarded_filehandle).flush() {
//                     eprintln!("[ERROR] filelog! failed to flush file: {}", e);
//                 }
//             }
//         }
//     };
// }


/// This is our primary object, and we can construct one for every
/// root directory we want to inspect.
#[derive(Debug, Clone)]
pub struct DirHasher {
    pool: ThreadPool,
    alg: HashAlg,
    root: PathBuf,
    hash_regex: Regex,
    hashfiles: Vec<FileData>,
    checkedfiles: Vec<FileData>,
    hashmap: HashMap<PathBuf, String>,
    loghandle: Option<Arc<Mutex<File>>>,
    mp: MultiProgress, // is an Arc type
    genhash_handle: Option<Arc<Mutex<File>>>,
    include_regex: Option<Regex>,
    exclude_regex: Option<Regex>,
    hash_hidden: bool, // Default to true if not specified
    gen_hashfile_abs_path: Option<PathBuf>, // Store absolute path to the generated hash file
}

impl DirHasher {
    /// Hasher constructor function - from the arguments, we take the algorithm,
    /// the root directory to compute hashes on, the pattern of (if any) hash files
    /// we need to parse, the (optional) path to our results log file, and the
    /// number of concurrent jobs we will run.
    pub fn new(
        alg: HashAlg,
        root_dir: &str,
        hashfile_pattern: Option<String>,
        logfile: Option<String>,
        jobs: Option<u64>,
        gen_hashfile: Option<String>,
        include_regex_pattern: Option<String>,
        exclude_regex_pattern: Option<String>,
        hash_hidden_opt: Option<bool>,
    ) -> Result<Self, HasherError> {
        let hash_regex = Self::build_hash_regex(&hashfile_pattern, &gen_hashfile)?;

        let include_regex = include_regex_pattern
            .map(|pat| Regex::new(&pat))
            .transpose()
            .map_err(|e| HasherError::Regex { why: format!("Invalid include regex: {e}") })?;

        let exclude_regex = exclude_regex_pattern
            .map(|pat| Regex::new(&pat))
            .transpose()
            .map_err(|e| HasherError::Regex { why: format!("Invalid exclude regex: {e}") })?;

        let hash_hidden = hash_hidden_opt.unwrap_or(true); // Default to true

        let root = canonicalize(Path::new(root_dir))?;
        if !root.is_dir() {
            return Err(HasherError::File {
                why: String::from("Path is not a valid directory"),
                path: root.display().to_string(),
            });
        }

        let avail_threads = Self::determine_thread_count(jobs)?;
        let loghandle = opt_open_file!("Logging hash results", logfile);

        let mut gen_hashfile_abs_path_store: Option<PathBuf> = None;
        let final_genhash_path_opt: Option<String> = gen_hashfile.map(|user_path_str| {
            // Determine if user_path_str is already absolute or relative to root
            let mut path_to_create = PathBuf::from(&user_path_str);
            if !path_to_create.is_absolute() {
                path_to_create = root.join(&path_to_create);
            }
            // Try to canonicalize it early to store its absolute form.
            // This might fail if the path doesn't exist yet, which is fine for creation.
            // We store the intended absolute path for filtering.
            // File::create will handle actual creation.
            match path_to_create.canonicalize() {
                Ok(p) => gen_hashfile_abs_path_store = Some(p),
                Err(_) => { // If it can't be canonicalized (e.g. not existing), store the constructed absolute path
                    gen_hashfile_abs_path_store = Some(path_to_create.clone());
                }
            }
            path_to_create.display().to_string()
        });

        let genhash_handle = opt_open_file!("Generating hashfile", final_genhash_path_opt);

        let mp = MultiProgress::new();
        Ok(Self {
            pool: threadpool::Builder::new()
                .num_threads(avail_threads as usize)
                .build(),
            alg,
            root,
            hash_regex,
            hashfiles: vec![],
            checkedfiles: vec![],
            hashmap: [].into(),
            loghandle,
            mp,
            genhash_handle,
            include_regex,
            exclude_regex,
            hash_hidden,
            gen_hashfile_abs_path: gen_hashfile_abs_path_store,
        })
    }

    /// Build the hash regex, ensuring mutual exclusivity with `gen_hashfile`.
    fn build_hash_regex(
        hashfile_pattern: &Option<String>,
        gen_hashfile: &Option<String>,
    ) -> Result<Regex, HasherError> {
        if let Some(pattern) = hashfile_pattern {
            if gen_hashfile.is_some() {
                return Err(HasherError::Argument {
                    why: String::from(
                        "Args hashfile pattern (-f) and generate hashfile (-g) are mutually exclusive",
                    ),
                });
            }
            Regex::new(pattern).map_err(|err| HasherError::Regex {
                why: format!("'{pattern}' returns error {err}"),
            })
        } else {
            // Match nothing regex
            Ok(Regex::new(".^").expect("This regex ('.^') should never fail unless alloc error occurred"))
        }
    }

    /// Determine the number of threads to use based on available cores and user input.
    fn determine_thread_count(jobs: Option<u64>) -> Result<u64, HasherError> {
        let mut avail_threads: u64 = available_parallelism()
            .map_err(|err| HasherError::Threading {
                why: format!("{err}: Couldn't get number of available threads"),
            })?
            .get()
            .try_into()
            .expect("Failed to cast usize to u64, unrecoverable");

        if let Some(total_threads) = jobs {
            if total_threads > avail_threads {
                warn!("[!] Only {avail_threads} threads available");
                Ok(avail_threads)
            } else {
                info!("[+] Allocating {total_threads} worker threads in the thread pool");
                Ok(total_threads)
            }
        } else {
            avail_threads = std::cmp::min(avail_threads, 12);
            info!("[+] Defaulting to {avail_threads} worker threads, use '--jobs' arg to change");
            Ok(avail_threads)
        }
    }

    /// Once the Hasher object is constructed, we can then begin computation.
    /// The --force option will force hash computation even if no hashfiles
    /// match our pattern, and --verbose will print all results to STDOUT.
    /// We can choose the order in which files will be computed: largest-first,
    /// smallest-first, or in inode order (which may be faster for disk I/O).
    pub fn run(
        &mut self,
        force: bool,
        verbose: bool,
        sort_order: FileSortLogic,
    ) -> Result<(), HasherError> {
        let file_vec = self.recursive_dir()?;
        // eprintln!("[DEBUG] DirHasher::run - بعد recursive_dir, file_vec.len(): {}", file_vec.len());
        self.identify_hashfiles(file_vec, force)?;
        // eprintln!("[DEBUG] DirHasher::run - بعد identify_hashfiles, self.checkedfiles.len(): {}", self.checkedfiles.len());
        self.load_hashes().or_else(|err| {
            if force {
                warn!("[+] No valid hashfile, but --force flag set");
                Ok(())
            } else {
                Err(err)
            }
        })?;

        self.sort_checked_files(sort_order);
        self.start_hash_threads(force, verbose)?;
        self.pool.join();
        Ok(())
    }

    /// Read the list of hashfiles and extract each hash inside them
    fn load_hashes(&mut self) -> Result<(), HasherError> {
        self.hashmap.reserve(self.checkedfiles.len());

        let spinner = self.create_spinner(String::from("[+] Parsing hashes from hashfiles"))?;
        for fd in &self.hashfiles {
            let hashpath = fd.path().parent().ok_or(HasherError::File {
                why: String::from("Hashfile parent directory not found"),
                path: fd.path_string(),
            })?;

            let file = File::open(fd.path()).map_err(|err| HasherError::File {
                why: format!("{err} : Hashfile cannot be opened"),
                path: fd.path_string(),
            })?;

            let reader = BufReader::new(file);
            for line in spinner.wrap_iter(reader.lines()) {
                let newline = line?;
                match split_hashfile_line(&newline, hashpath) {
                    Ok((path, hash)) => self.hashmap.insert(path, hash),
                    Err(err) => {
                        error!("[!] {err} : Failed to parse line from hashfile :: {newline}");
                        continue;
                    }
                };
            }
        }

        self.hashmap.shrink_to_fit();
        if self.hashmap.is_empty() {
            Err(HasherError::Hash {
                why: String::from("No hashes read from hashfiles"),
            })
        } else {
            info!("[*] {} hashes read from all hashfiles", spinner.position());
            self.mp.remove(&spinner);
            Ok(())
        }
    }

    /// Generate a standard spinner for pending jobs with an indeterminate end.
    fn create_spinner(&self, msg: String) -> Result<ProgressBar, HasherError> {
        let spinner_style = ProgressStyle::with_template("[{spinner:.cyan.bold}] (# {pos:.green}) {wide_msg}")?
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

    /// Split the vector of files from `recursive_dir` into hash files and non-hashfiles.
    fn identify_hashfiles(
        &mut self,
        file_vec: Vec<FileData>,
        force: bool,
    ) -> Result<(), HasherError> {
        info!("[+] Identifying hashfiles");
        // eprintln!("[DEBUG] identify_hashfiles - input file_vec.len(): {}", file_vec.len());
        (self.hashfiles, self.checkedfiles) = file_vec
            .into_iter()
            .partition(|f| path_matches_regex(&self.hash_regex, f.path()));
        // eprintln!("[DEBUG] identify_hashfiles - بعد التقسيم, self.checkedfiles.len(): {}", self.checkedfiles.len());
        // eprintln!("[DEBUG] identify_hashfiles - بعد التقسيم, self.hashfiles.len(): {}", self.hashfiles.len());
        if self.hashfiles.is_empty() {
            let reason = String::from("No hashfiles matched the hashfile pattern");
            if force {
                warn!("[-] {reason}");
            } else {
                error!(
                    "[-] '--force' flag not specified, either force computation or check your regex pattern"
                );
                return Err(HasherError::Regex { why: reason });
            }
        }
        info!("[*] {} files in the queue", self.checkedfiles.len());
        Ok(())
    }

    /// Recursively walk the root directory and identify all regular files. Ignore
    /// all files and directories for which we do not have permission to read.
    fn recursive_dir(&mut self) -> Result<Vec<FileData>, HasherError> {
        let spinner = self.create_spinner(format!("[+] Recursing through {:?}", self.root))?;
        let mut file_vec: Vec<FileData> = Vec::new();

        // local_hash_hidden and local_include_regex were duplicated, corrected here.
        // self.hash_hidden and self.include_regex.as_ref() are used directly below,
        // so these specific local assignments for them are not strictly necessary unless for closure captures later.
        let local_exclude_regex = self.exclude_regex.as_ref();

        let walker = WalkDir::new(&self.root).into_iter();

        for entry_result in spinner.wrap_iter(walker) {
            let entry = match entry_result {
                Ok(e) => e,
                Err(e) => {
                    warn!("Error reading directory entry: {}", e);
                    continue;
                }
            };

            let path = entry.path();
            let relative_path = match path.strip_prefix(&self.root) {
                Ok(p) => p,
                Err(_) => path, // Should not happen
            };

            // Skip the root directory itself from being processed as a file/entry here
            if relative_path.as_os_str().is_empty() {
                // eprintln!("[DEBUG] recursive_dir: Skipping root dir entry: {:?}", path);
                continue;
            }

            // Skip if the current entry is the gen_hashfile itself
            if let Some(gen_path_abs) = &self.gen_hashfile_abs_path {
                if path == gen_path_abs {
                    // eprintln!("[DEBUG] recursive_dir: Skipping gen_hashfile itself: {:?}", path);
                    continue;
                }
            }

            // eprintln!("[DEBUG] recursive_dir: Processing entry: path={:?}, relative_path={:?}", path, relative_path);

            // 1. Hidden file/directory filtering
            // This filter applies to both files and directories. If a directory is "hidden",
            // its direct entry is skipped. WalkDir might still yield its children depending on OS and WalkDir version.
            // This logic aims to filter out entries if any component of their relative path is hidden,
            // or if the entry itself is hidden.
            if !self.hash_hidden {
                // An entry is hidden if its own name starts with "." or if any parent
                // directory in the relative_path starts with "."
                let mut is_effectively_hidden = false;
                if entry.file_name().to_string_lossy().starts_with('.') {
                    is_effectively_hidden = true;
                } else {
                    let mut parent = relative_path.parent();
                    while let Some(p) = parent {
                        if p.file_name().map_or(false, |name| name.to_string_lossy().starts_with('.')) {
                            is_effectively_hidden = true;
                            break;
                        }
                        if p.as_os_str().is_empty() { // Reached the top of the relative path
                            break;
                        }
                        parent = p.parent();
                    }
                }

                if is_effectively_hidden {
                    // eprintln!("[DEBUG] recursive_dir: Skipping hidden path (hash_hidden=false): {:?}", relative_path);
                    continue;
                }
            }
            // eprintln!("[DEBUG] recursive_dir: Passed hidden check: {:?}", relative_path);

            // 2. Exclude regex filtering (applies to files and directories)
            if let Some(exclude_r) = local_exclude_regex { // Use the local variable
                if exclude_r.is_match(&relative_path.to_string_lossy()) {
                    // eprintln!("[DEBUG] recursive_dir: Skipping excluded path: {:?} by regex: {:?}", relative_path, exclude_r);
                    continue;
                }
            }
            // // eprintln!("[DEBUG] recursive_dir: Passed exclude check (or no exclude_regex): {:?}", relative_path);

            // We only care about files from this point onwards for adding to `file_vec`
            if !entry.file_type().is_file() {
                // eprintln!("[DEBUG] recursive_dir: Skipping non-file: {:?}", relative_path);
                continue;
            }
            // eprintln!("[DEBUG] recursive_dir: Is file, proceeding: {:?}", relative_path);

            // 3. Include regex filtering (applies to files only)
            if let Some(include_r) = self.include_regex.as_ref() {
                if !include_r.is_match(&relative_path.to_string_lossy()) {
                    // eprintln!("[DEBUG] recursive_dir: Skipping non-included path: {:?} by regex: {:?}", relative_path, include_r);
                    continue;
                }
            }
            // // eprintln!("[DEBUG] recursive_dir: Passed include check (or no include_regex): {:?}", relative_path);

            // If all filters passed and it's a file, try to convert to FileData
            let path_for_warning = path.to_path_buf(); // Clone path for use in warn!
            match FileData::try_from(entry) {
                Ok(fd) => {
                    // eprintln!("[DEBUG] recursive_dir: Successfully added to file_vec: {:?}", fd.path()); // Noisy
                    file_vec.push(fd);
                }
                Err(e) => warn!("Could not process file {:?}: {}", path_for_warning, e),
            }
        }
        self.mp.remove(&spinner);
        Ok(file_vec)
    }

    /// Sort files by size or inode-order (Linux only).
    fn sort_checked_files(&mut self, sort_order: FileSortLogic) {
// since we are popping off the last element of the vec to process it, in the instance
        // of Largest-First hashing, the largest needs to be at the end of the vec, and
        // vice versa for smallest.
        match sort_order {
            #[cfg(target_os = "linux")]
            FileSortLogic::InodeOrder => {
                info!("[*] Sorting files by inode");
                self.checkedfiles.sort_unstable_by_key(|a| Reverse(a.inode()));
            }
            FileSortLogic::SmallestFirst => {
                info!("[*] Sorting files by size, smallest first");
                self.checkedfiles.sort_unstable_by_key(|a| Reverse(a.size()));
            }
            FileSortLogic::LargestFirst => {
                info!("[*] Sorting files by size, largest first");
                self.checkedfiles.sort_unstable_by_key(FileData::size);
            }
        }
    }

    /// Spawn a single hash job for a file.
    fn spawn_single_job(
        &mut self,
        mut file_data: FileData,
        bar: &ProgressBar,
        force: bool,
        verbose: bool,
    ) {
        if let Some(mut v) = self.hashmap.remove(file_data.path()) {
            file_data.set_hash(&mut v);
        } else if !force {
            warn!("[!] {:?} => No hash found", file_data.path());
            bar.inc(1);
            return;
        }
        let gen_hashfile_dir = self
            .genhash_handle
            .as_ref()
            .map(|_| self.root.clone());
        let moved_args = ThreadFuncArgs {
            fdata: file_data,
            alg: self.alg,
            force,
            verbose,
            loghandle: self.loghandle.clone(),
            opt_mp: Some(self.mp.clone()),
            opt_progress: Some(bar.clone()),
            gen_hashfile: self.genhash_handle.clone(),
            gen_hashfile_dir,
        };
        // Restore thread pool execution
        self.pool.execute(move || {
            if let Err(e) = perform_hash_threadfunc(moved_args) {
                eprintln!("[ERROR_IN_THREAD] perform_hash_threadfunc failed: {:?}", e); // Keep this error print
            }
        });
    }

    /// For each file collected, spawn a single hash job.
    fn start_hash_threads(&mut self, force: bool, verbose: bool) -> Result<(), HasherError> {
        // eprintln!("[DEBUG] start_hash_threads - self.checkedfiles.len(): {}", self.checkedfiles.len());
        info!(
            "[+] Checking hashes - spinning up {} worker threads",
            self.pool.max_count()
        );

        let num_files = self.checkedfiles.len();
        if num_files == 0 {
            // eprintln!("[DEBUG] start_hash_threads - No files to hash, skipping progress bar and loop.");
            return Ok(());
        }
        let style: ProgressStyle = ProgressStyle::with_template(
            "[{elapsed_precise}] \
            ({percent:3}%) \
            {bar:30.red/magenta} \
            {pos:>10.green}/{len:<10.green} \
            * Total File Progress *",
        )?
        .progress_chars("==>");
        let bar = self
            .mp
            .add(ProgressBar::new(num_files as u64).with_style(style));
        while let Some(ck) = self.checkedfiles.pop() {
            self.spawn_single_job(ck, &bar, force, verbose);
            // every 4096 hashes (we like our page multiples), shrink the memory space of the hashmap
            if num_files % 4096 == 0 {
                self.hashmap.shrink_to_fit();
                self.checkedfiles.shrink_to_fit();
            }
        }
        Ok(())
    }
}
