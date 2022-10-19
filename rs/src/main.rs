use regex::Regex;
use std::fs;
use std::path::Path;
use std::thread;
use threadpool::ThreadPool;

use diskhasher::*;

// CLI stuff
use clap::{Parser};
#[derive(Parser)]
#[clap(author, version, about="Hash a directory's files and optionally check against existing hashfile")]
struct Arguments {
    /// Path to the directory we want to validate
    #[clap(short,long)]
    directory: String,
    /// Algorithm to use (SHA1, SHA256)
    #[clap(short,long)]
    #[arg(value_enum)]
    algorithm: HashAlg,
    /// Regex pattern used to identify hashfiles
    #[clap(short,long)]
    pattern: Option<String>,
    //#[clap(short,long)]
    //logfile: Option<String>,
    //#[clap(short,long)]
    //success_log: Option<bool>,
    //#[clap(short,long)]
    //force: Option<bool>,
    //#[clap(short,long)]
    //verbose: Option<bool>
}

fn main()
{
    let args = Arguments::parse();

    // Recursively enumerate directory
    let root_path = match fs::canonicalize(Path::new(&args.directory)) {
        Ok(v) => v,
        Err(_e) => panic!("[-] Could not canonicalize the path '{}'", args.directory)
    };

    let all_files = recursive_dir(&root_path).unwrap();

    let hashfile_pattern = args.pattern.unwrap_or("*".to_string());
    let hash_regex = match Regex::new(&hashfile_pattern) {
        Ok(v) => v,
        Err(_e) => panic!("[-] Invalid regular expression '{}'", hashfile_pattern)
    };

    let (hashfiles, mut checked_files) : (Vec<FileData>, Vec<FileData>) = all_files
        .into_iter()
        .partition( |f| {
            let str_path = match f.path.file_name(){
                Some(v) => v,
                None => panic!("[-] Failed to retrieve file name from path object")
            };
            hash_regex.is_match(str_path.to_str().unwrap())
        });

    // Read hashfile(s)
    let expected_hashes = match load_hashes(&hashfiles, &root_path) {
        Ok(v) => v,
        Err(_e) => panic!("[!] No hashes available: {}", _e)
    };

    // load expected hash value into each checked_files entry
    for ck in &mut checked_files {
        if !&expected_hashes.contains_key(&ck.path){
            println!("[!] {:?} => No hash found", &ck.path);
            continue;
        }
        ck.expected_hash = expected_hashes.get(&ck.path).unwrap().to_string();
    }
    let num_threads = match thread::available_parallelism() {
        Ok(v) => v.get(),
        Err(_e) => panic!("Couldn't get number of threads")
    };

    let pool = ThreadPool::new(num_threads);
    for task in checked_files {
        pool.execute(move || {
            perform_hash(task, args.algorithm).unwrap(); // don't like this
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