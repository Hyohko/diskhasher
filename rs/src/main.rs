use {
    clap::Parser, diskhasher::*, regex::Regex, std::collections::HashMap, std::fs::canonicalize,
    std::path::Path, std::path::PathBuf, std::process, std::thread::available_parallelism,
    threadpool::ThreadPool,
};

// CLI stuff

#[derive(Parser)]
#[clap(
    author,
    version,
    about = "Hash a directory's files and optionally check against existing hashfile"
)]
struct Arguments {
    /// Path to the directory we want to validate
    #[clap(short, long)]
    directory: String,
    /// Algorithm to use (SHA1, SHA256)
    #[clap(short, long)]
    #[arg(value_enum)]
    algorithm: HashAlg,
    /// Regex pattern used to identify hashfiles
    #[clap(short, long)]
    pattern: Option<String>,
    //#[clap(short,long)]
    //logfile: Option<String>,
    //#[clap(short,long)]
    //success_log: Option<bool>,
    /// Force computation of hashes even if hash pattern fails or is omitted
    #[clap(short, long, action)]
    force: bool,
    #[clap(short, long, action)]
    verbose: bool,
}

fn main() {
    let args = Arguments::parse();

    // Recursively enumerate directory
    let root_path = canonicalize(Path::new(&args.directory)).unwrap_or_else(|_| {
        println!("[-] Could not canonicalize the path '{}'", args.directory);
        process::exit(1);
    });

    let all_files = recursive_dir(&root_path).unwrap_or_else(|_| {
        println!("[!] Unable to walk directory {}", root_path.display());
        process::exit(1);
    });

    let hashfile_pattern = args.pattern.unwrap_or("NO_VALID_PATTERN".to_string());
    let hash_regex = Regex::new(&hashfile_pattern).unwrap_or_else(|_| {
        println!("[-] Invalid regular expression '{}'", hashfile_pattern);
        process::exit(1);
    });

    let (hashfiles, mut checked_files): (Vec<FileData>, Vec<FileData>) =
        all_files.into_iter().partition(|f| {
            let str_path = f.path.file_name().unwrap_or_else(|| {
                println!("[-] Failed to retrieve file name from path object");
                process::exit(1);
            });
            hash_regex.is_match(str_path.to_str().unwrap())
        });

    // Read hashfile(s)
    let expected_hashes = match load_hashes(&hashfiles, &root_path) {
        Ok(v) => v,
        Err(_e) => {
            if args.force {
                println!("[!*] No hashes available: {}", _e);
                HashMap::<PathBuf, String>::new()
            } else {
                println!("[!*] No hashes available: {}", _e);
                process::exit(1);
            }
        }
    };

    // load expected hash value into each checked_files entry
    for ck in &mut checked_files {
        if !&expected_hashes.contains_key(&ck.path) {
            println!("[!] {:?} => No hash found", &ck.path);
            continue;
        }
        ck.expected_hash = expected_hashes.get(&ck.path).unwrap().to_string();
    }
    let num_threads = match available_parallelism() {
        Ok(v) => v.get(),
        Err(_e) => {
            println!("[-] Couldn't get number of threads '{}'", hashfile_pattern);
            process::exit(1);
        }
    };

    let pool = ThreadPool::new(num_threads);
    for task in checked_files {
        pool.execute(move || {
            perform_hash(task, args.algorithm, args.force, args.verbose).unwrap();
        });
    }

    // Wait for all threads to finish
    pool.join();
}

/*
Stored non-threadpool code
        /*let pending_tasks : Vec<_> = checked_files
        .into_iter()
        .map( |task| thread::spawn(move || {perform_hash(task, args.algorithm)}) )
        .collect();

        for my_task in pending_tasks{
            let _result = my_task.join();
        }*/
*/
