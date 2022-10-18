use digest::DynDigest;
use hex;
use regex::Regex;
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufRead, Read};
use std::path::{Path, PathBuf};
use std::thread;
use threadpool::ThreadPool;
use walkdir::WalkDir;

// CLI stuff
use clap::{Parser, ValueEnum};
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

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FileData {
    path: PathBuf,
    file_size: u64,
    expected_hash: String
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum HashAlg {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512
}

impl Display for HashAlg {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MD5 => write!(f, "MD5"),
            Self::SHA1 => write!(f, "SHA1"),
            Self::SHA224 => write!(f, "SHA224"),
            Self::SHA256 => write!(f, "SHA256"),
            Self::SHA384 => write!(f, "SHA384"),
            Self::SHA512 => write!(f, "SHA512")
        }
    }
}

fn main()
{
    let args = Arguments::parse();

    // Recursively enumerate directory
    let root_path = match fs::canonicalize(Path::new(&args.directory)) {
        Ok(v) => v,
        Err(_e) => panic!("Could not canonicalize the path '{}'", args.directory)
    };

    let all_files = recursive_dir(&root_path).unwrap();

    let hashfile_pattern = args.pattern.unwrap_or("*".to_string());
    let hash_regex = match Regex::new(&hashfile_pattern) {
        Ok(v) => v,
        Err(_e) => panic!("Invalid regular expression '{}'", hashfile_pattern)
    };

    let (hashfiles, mut checked_files) : (Vec<FileData>, Vec<FileData>) = all_files
        .into_iter()
        .partition( |f| hash_regex.is_match(f.path.file_name().unwrap().to_str().unwrap()) );
        // this partition sucks.....better way to write it?

    // Read hashfile(s)
    let expected_hashes = match load_hashes(&hashfiles, &root_path) {
        Ok(v) => v,
        Err(_e) => panic!("No hashes available")
    };

    // load expected hash value into each checked_files entry
    for ck in &mut checked_files {
        if !&expected_hashes.contains_key(&ck.path){
            println!("[!] {:?} => No hash found", &ck.path);
            continue;
        }
        ck.expected_hash = expected_hashes.get(&ck.path).unwrap().to_string();
    }

    // TODO - Threadpooling these spawned tasks
    const USE_THREADPOOL: bool = true;

    if USE_THREADPOOL {
        let num_threads = match thread::available_parallelism() {
            Ok(v) => v.get(),
            Err(_e) => panic!("Couldn't get number of threads")
        };
        let pool = ThreadPool::new(num_threads);

        for task in checked_files
        {
            pool.execute(move || {
                perform_hash(task, args.algorithm);
            });
        }

        // Wait for all threads to finish
        pool.join();
    } else {
        let pending_tasks : Vec<_> = checked_files
        .into_iter()
        .map( |task| thread::spawn(move || {perform_hash(task, args.algorithm)}) )
        .collect();

        for my_task in pending_tasks{
            let _result = my_task.join();
        }
    }
        
}

/// Recursively enumerates an absolute (canonicalized) path,
/// returns Option<Vec<FileData>>, sorted smallest file to largest
fn recursive_dir(abs_root_path: &Path) -> Option<Vec<FileData>> {
    let mut file_vec = Vec::<FileData>::new();
    for entry in WalkDir::new(abs_root_path)
        .into_iter()
        .filter_map(|e| e.ok()){
            if entry.file_type().is_file(){
                let file_path = entry.path();
                let size_option = file_path.metadata();
                let size : u64;
                match size_option{
                    Ok(f) => size = f.len(),
                    Err(_e) => continue
                };
                let file_entry = FileData{
                    path : file_path.to_path_buf(),
                    file_size : size,
                    expected_hash : "".to_string()
                }; 
                file_vec.push(file_entry);
            }
        }
    // Sort vector by file size, smallest first
    file_vec.sort_by(|a, b| a.file_size.cmp(&b.file_size));
    Some(file_vec)
}

/// Loads the expected hashes for a directory from a hashfile,
/// expects the file format to be "<hex string> <relative file path>"
fn load_hashes(hashfiles: &Vec<FileData>, abs_root_path: &Path) -> Result<HashMap<PathBuf, String>, String> {
    let mut hash_vec = HashMap::new();
    let hex_pattern = Regex::new(r"([[:xdigit:]]{32})|([[:xdigit:]]{48})|([[:xdigit:]]{64})").unwrap();
    
    for f in hashfiles {
        println!("{:?} : {} bytes", f.path, f.file_size);
        let file = match File::open(&f.path) {
            Ok(v) => v,
            Err(_e) => { println!("ERROR {} : File '{}' cannot be opened", f.path.display(), _e); continue }
        };
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let newline = match line {
                Ok(v) => v,
                Err(_e) => panic!("ERROR {} : Line from file '{}' cannot be read", f.path.display(), _e)
            };
            let mut splitline = newline.split(" ");
            let hashval = splitline.next().unwrap();
            // check first bit for valid hex string
            if !hex_pattern.is_match(hashval) {
                continue;
            }
            // canonicalize path by joining, then check for existence
            splitline.next();
            let file_path = splitline.next().unwrap();
            let canonical_path = match fs::canonicalize(abs_root_path.join(file_path)) {
                Ok(v) => v,
                Err(_e) => panic!("Could not canonicalize the path '{}'", file_path)
            }; 
            if !canonical_path.exists() {
                println!("File '{:?} cannot be found", canonical_path);
                continue;
            }
            hash_vec.insert(canonical_path, hashval.to_string());
        }
    }

    if hash_vec.len() == 0 {
        panic!("No hashes read from hashfiles");
    }
    Ok(hash_vec)
}

// use md5;

// You can use something like this when parsing user input, CLI arguments, etc.
// DynDigest needs to be boxed here, since function return should be sized.
fn select_hasher(alg: HashAlg) -> Box<dyn DynDigest> {
    match alg {
        // HashAlg::SHA1 => Box::new(md5::Md5::default()),
        HashAlg::SHA1 => Box::new(sha1::Sha1::default()),
        HashAlg::SHA224 => Box::new(sha2::Sha224::default()),
        HashAlg::SHA256 => Box::new(sha2::Sha256::default()),
        HashAlg::SHA384 => Box::new(sha2::Sha384::default()),
        HashAlg::SHA512 => Box::new(sha2::Sha512::default()),
        _ => unimplemented!("unsupported digest: {}", alg),
    }
}

/// Thread function that opens file, hashes, and compares with expected hash
fn perform_hash(fdata: FileData, alg: HashAlg) -> bool
{
    // file existence check performed earlier, though we could put one here for completeness
    let mut hasher = select_hasher(alg);

    // open file and read data into heap-based buffer
    const BUFSIZE: usize = 1024 * 1024 * 2; // 2 MB
    let mut buffer: Box<[u8]> = vec![0; BUFSIZE].into_boxed_slice();
    let mut file = match File::open(&fdata.path)
    {
        Ok(v) => v,
        Err(_e) => panic!("Unable to open file - Error {}", _e)
    };

    loop {
        let read_count = match file.read(&mut buffer[..BUFSIZE]) {
            Ok(v) => v,
            Err(_e) => panic!("Read failure: {}", _e)
        };
        hasher.update(&buffer[..read_count]);

        if read_count < BUFSIZE {
            break;
        }
    }
    let actual_hash = hex::encode(hasher.finalize());
    let success: bool = &fdata.expected_hash == &actual_hash;
    if success{
        println!("[+] Checksum passed: {:?}\n\tActual hash  : {:?}",
            &fdata.path, actual_hash);
    } else {
        println!("[-] Checksum failed: {:?}\n\tExpected hash: {:?}\n\tActual hash  : {:?}",
        &fdata.path, &fdata.expected_hash, actual_hash);
    }
    success    
}