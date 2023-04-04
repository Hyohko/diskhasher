/*
    DISKHASHER v0.2 - 2023 by Hyohko

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
    threadfunc::perform_hash_threadfunc,
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
        hashfile_pattern: Option<String>,
        logfile: Option<String>,
        jobs: Option<usize>,
    ) -> Result<Self, HasherError> {
        let hash_regex: Regex;
        if let Some(pattern) = hashfile_pattern {
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

        let mut avail_threads = available_parallelism()
            .map_err(|err| HasherError::Threading {
                why: format!("{err}: Couldn't get number of available threads"),
            })?
            .get();

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

        // .thread_stack_size(STACKSIZE_8MB) // change stack size only if necessary
        let mp = MultiProgress::new();
        Ok(Self {
            pool: threadpool::Builder::new()
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

            let file = File::open(f.path()).map_err(|err| HasherError::File {
                why: format!("{err} : Hashfile cannot be opened"),
                path: f.path_string(),
            })?;

            let reader = BufReader::new(file);
            for line in spinner.wrap_iter(reader.lines()) {
                let newline = line?;
                match split_hashfile_line(&newline, &hashpath) {
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
                error!("[-] '--force' flag not specified, either force computation or check your regex pattern");
                return Err(HasherError::Regex { why: reason });
            }
        }
        info!("[*] {} files in the queue", self.checkedfiles.len());
        Ok(())
    }

    fn recursive_dir(&mut self) -> Result<Vec<FileData>, HasherError> {
        let spinner = self.create_spinner(format!("[+] Recursing through {:?}", self.root))?;
        let file_vec: Vec<FileData> = spinner
            .wrap_iter(WalkDir::new(&self.root).into_iter())
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .map(|e| FileData::try_from(e))
            .filter_map(Result::ok)
            .collect();
        self.mp.remove(&spinner);
        Ok(file_vec)
    }

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
        } else if !force {
            warn!("[!] {:?} => No hash found", file_data.path());
            bar.inc(1);
            return;
        }

        // after this point, avoid more stdout/stderr prints
        let alg = self.alg;
        let mp = self.mp.clone();
        let loghandle = self.loghandle.clone();
        let bar = bar.clone();
        self.pool.execute(move || {
            perform_hash_threadfunc(
                fd_clone,
                alg,
                force,
                verbose,
                loghandle,
                Some(mp),
                Some(bar),
            )
            .ok();
        });
    }

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
            self.spawn_single_job(&ck, &bar, force, verbose);
            // every 5000 hashes, shrink the memory space of the hashmap
            if num_files % 5000 == 0 {
                self.hashmap.shrink_to_fit();
                self.checkedfiles.shrink_to_fit();
            }
        }
        Ok(())
    }
}
