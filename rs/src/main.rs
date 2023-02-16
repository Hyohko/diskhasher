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
    clap::Parser, diskhasher::*, regex::Regex, std::collections::HashMap, std::fs, std::path::Path,
    std::path::PathBuf, std::process,
};

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
    /// Force computation of hashes even if hash pattern fails or is omitted
    #[clap(short, long, action)]
    force: bool,
    /// Print all results to stdout
    #[clap(short, long, action)]
    verbose: bool,
}

/*
//#[clap(short,long)]
//logfile: Option<String>,
//#[clap(short,long)]
//success_log: Option<bool>,
*/

fn main() {
    const EMPTY_STRING: String = String::new();
    let pool = create_threadpool().unwrap_or_else(|err| {
        println!("[-] ThreadPool error: {}", err);
        process::exit(1);
    });

    let args = Arguments::parse();

    println!("[+] Using the {:?} algorithm", args.algorithm);

    // Recursively enumerate directory
    let root_path = fs::canonicalize(Path::new(&args.directory)).unwrap_or_else(|_| {
        println!("[-] Could not canonicalize the path '{}'", args.directory);
        process::exit(1);
    });
    if !root_path.is_dir() {
        println!(
            "[-] Path '{}' is not a valid directory",
            root_path.display()
        );
        process::exit(1);
    }

    let hashfile_pattern = args.pattern.unwrap_or("NO_VALID_PATTERN".to_string());
    println!(
        "[+] Validating hashfile regular expression {:?}",
        hashfile_pattern
    );
    let hash_regex = Regex::new(&hashfile_pattern).unwrap_or_else(|_| {
        println!("[-] Invalid regular expression '{}'", hashfile_pattern);
        process::exit(1);
    });

    println!(
        "[+] Recursively listing all regular files in '{}'",
        root_path.display()
    );
    let all_files = recursive_dir(&root_path).unwrap_or_else(|_| {
        println!("[!] Unable to walk directory {}", root_path.display());
        process::exit(1);
    });

    println!("[+] Identifying hashfiles");
    let (hashfiles, checked_files): (Vec<FileData>, Vec<FileData>) =
        all_files.into_iter().partition(|f| {
            let str_path = f.path.file_name().unwrap_or_else(|| {
                println!("[-] Failed to retrieve file name from path object");
                process::exit(1);
            });
            hash_regex.is_match(str_path.to_str().unwrap())
        });

    println!("[+] Loading expected hashes from {:?}", hashfiles);
    let expected_hashes = match load_hashes(&hashfiles, checked_files.len()) {
        Ok(v) => v,
        Err(_e) => {
            if args.force {
                println!("[!*] No hashes available: {}", _e);
                println!("[*] --force called, computing hashes anyway");
                HashMap::<PathBuf, String>::new()
            } else {
                println!("[!*] No hashes available: {}", _e);
                process::exit(1);
            }
        }
    };

    // load expected hash value into each checked_files entry
    // since checked_files is in file-size order (smallest to largest)
    // this function should process the very smallest files first
    println!(
        "[+] Checking hashes - spinning up {} worker threads",
        pool.max_count()
    );

    let num_files: usize = checked_files.len();
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
            .unwrap();
        });
    }

    // Wait for all threads to finish
    pool.join();
    hashcount_monitor(num_files);
    println!("[+] Done");
}

/*let root_path: PathBuf = match fs::canonicalize(Path::new(&args.directory)) {
    Ok(v) => {
        // fs::canonicalize checks for existence, now we check for directory
        if !v.is_dir() {
            println!("[-] Path '{}' is not a valid directory", v.display());
            process::exit(1);
        } else {
            v
        }
    }
    Err(_e) => {
        println!(
            "[-] ERROR ({:?}) : Could not canonicalize the path '{}'",
            _e, args.directory
        );
        process::exit(1);
    }
};*/

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
