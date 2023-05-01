/*
    DISKHASHER v0.3 - 2023 by Hyohko

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

use crate::{
    enums::{FileSortLogic, HashAlg},
    error::HasherError,
    filedata::FileData,
    threadfunc::{perform_hash_threadfunc, ThreadFuncArgs},
    util::{path_matches_regex, split_hashfile_line},
};

use {
    indicatif::{MultiProgress, ProgressBar, ProgressFinish, ProgressStyle},
    regex::Regex,
    std::{
        cmp::Reverse,
        collections::HashMap,
        fs::canonicalize,
        fs::File,
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
            Some(v) => {
                info!("[+] {} -> {v}", $logmsg);
                Some(Arc::new(Mutex::new(File::create(&v)?)))
            }
            None => None,
        }
    };
}

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
    genhash_handle: Option<Arc<Mutex<File>>>,
}

impl Hasher {
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
    ) -> Result<Self, HasherError> {
        let hash_regex: Regex;
        if let Some(pattern) = hashfile_pattern {
            if gen_hashfile.is_some() {
                return Err(HasherError::Argument {
                    why: String::from(
                        "Args hashfile pattern (-f) and generate hashfile (-g) are mutually exclusive",
                    ),
                });
            }
            hash_regex = Regex::new(&pattern).map_err(|err| HasherError::Regex {
                why: format!("'{pattern}' returns error {err}"),
            })?;
        } else {
            // This is the "match nothing" regex
            hash_regex = Regex::new(".^")
                .expect("This regex ('.^') should never fail unless alloc error occurred");
        }

        let root = canonicalize(Path::new(&root_dir))?;
        if !root.is_dir() {
            return Err(HasherError::File {
                why: String::from("Path is not a valid directory"),
                path: root.display().to_string(),
            });
        }

        let mut avail_threads: u64 = available_parallelism()
            .map_err(|err| HasherError::Threading {
                why: format!("{err}: Couldn't get number of available threads"),
            })?
            .get()
            .try_into()
            .expect("Failed to cast usize to u64, unrecoverable");

        avail_threads = if let Some(total_threads) = jobs {
            if total_threads > avail_threads {
                warn!("[!] Only {avail_threads} threads available");
                avail_threads
            } else {
                info!("[+] Allocating {total_threads} worker threads in the thread pool");
                total_threads
            }
        } else {
            // cap total running threads at the num of cores or 12 threads (which is plenty),
            // whatever is smaller. Much larger than this and it screws
            // up the progress bar rendering, though we still let the user shoot their
            // own feet in the if let above.
            avail_threads = std::cmp::min(avail_threads, 12);
            info!("[+] Defaulting to {avail_threads} worker threads, use '--jobs' arg to change");
            avail_threads
        };

        let loghandle = opt_open_file!("Logging hash results", logfile);
        let genhash_path =
            gen_hashfile.map_or_else(|| None, |v| Some(root.join(v).display().to_string()));
        let genhash_handle = opt_open_file!("Generating hashfile", genhash_path);

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
        })
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
        self.identify_hashfiles(file_vec, force)?;
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

    /// Generate a standard spinner for pending jobs with an indeterminate end
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

    /// Split the vector of files from `recursive_dir` into hash files and non-hashfiles.
    fn identify_hashfiles(
        &mut self,
        file_vec: Vec<FileData>,
        force: bool,
    ) -> Result<(), HasherError> {
        info!("[+] Identifying hashfiles");
        (self.hashfiles, self.checkedfiles) = file_vec
            .into_iter()
            .partition(|f| path_matches_regex(&self.hash_regex, f.path()));
        if self.hashfiles.is_empty() {
            let reason = String::from("No hashfiles matched the hashfile pattern");
            if force {
                warn!("[-] {reason}");
            } else {
                error!("[-] '--force' flag not specified, either force computation or check your regex pattern");
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
        let file_vec: Vec<FileData> = spinner
            .wrap_iter(WalkDir::new(&self.root).into_iter())
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .map(FileData::try_from)
            .filter_map(Result::ok)
            .collect();
        self.mp.remove(&spinner);
        Ok(file_vec)
    }

    /// Sort files by size or inode-order (Linux only)
    fn sort_checked_files(&mut self, sort_order: FileSortLogic) {
        // since we are popping off the last element of the vec to process it, in the instance
        // of Largest-First hashing, the largest needs to be at the end of the vec, and
        // vice versa for smallest.
        match sort_order {
            #[cfg(target_os = "linux")]
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

    /// Assign a single hash job to one of the threads in our threadpool
    fn spawn_single_job(
        &mut self,
        mut file_data: FileData,
        bar: &ProgressBar,
        force: bool,
        verbose: bool,
    ) {
        //let mut fd_clone = file_data.clone();
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
            .map_or_else(|| None, |_v| Some(self.root.clone()));
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
        // after this point, avoid more stdout/stderr prints
        self.pool.execute(move || {
            perform_hash_threadfunc(moved_args).ok();
        });
    }

    /// For each file collected, spawn a single hash job.
    fn start_hash_threads(&mut self, force: bool, verbose: bool) -> Result<(), HasherError> {
        info!(
            "[+] Checking hashes - spinning up {} worker threads",
            self.pool.max_count()
        );

        let num_files = self.checkedfiles.len();
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
            // every 5000 hashes, shrink the memory space of the hashmap
            if num_files % 5000 == 0 {
                self.hashmap.shrink_to_fit();
                self.checkedfiles.shrink_to_fit();
            }
        }
        Ok(())
    }
}
