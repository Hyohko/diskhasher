use clap::ValueEnum;
use digest::DynDigest;
use hex;
use regex::Regex;
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufRead, Read};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// TODO - remove public fields
#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileData {
    pub size: u64,
    pub path: PathBuf,
    pub expected_hash: String
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum HashAlg {
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

/// Recursively enumerates an absolute (canonicalized) path,
/// returns Option<Vec<FileData>>, sorted smallest file to largest
pub fn recursive_dir(abs_root_path: &Path) -> Result<Vec<FileData>, String> {
    let mut file_vec = Vec::<FileData>::new();
    for entry in WalkDir::new(abs_root_path)
        .into_iter()
        .filter_map(|e| e.ok()){
            if entry.file_type().is_file(){
                let size: u64 = match entry.path().metadata() {
                    Ok(f) => f.len(),
                    Err(_e) => continue
                };
                file_vec.push(FileData{
                    size,
                    path : entry.path().to_path_buf(),
                    expected_hash : "".to_string()
                }); 
            }
        }
    // Sort vector by file size, smallest first
    file_vec.sort_by(|a, b| a.size.cmp(&b.size));
    Ok(file_vec)
}

/*pub fn partition_files(all_files: &Vec<FileData>, hash_regex: Regex) -> (Vec<FileData>, Vec<FileData>) {
    let (hashfiles, checked_files) : (Vec<FileData>, Vec<FileData>) = all_files
        .into_iter()
        .partition( |f| hash_regex.is_match(f.path.file_name().unwrap().to_str().unwrap()) );
    (hashfiles, checked_files)
}*/

/// Loads the expected hashes for a directory from a hashfile,
/// expects the file format to be "<hex string> <relative file path>"
pub fn load_hashes(hashfiles: &Vec<FileData>, abs_root_path: &Path) -> Result<HashMap<PathBuf, String>, String> {
    let mut hash_vec = HashMap::new();
    let hex_pattern = Regex::new(r"([[:xdigit:]]{32})|([[:xdigit:]]{48})|([[:xdigit:]]{64})").unwrap();
    
    for f in hashfiles {
        println!("{:?} : {} bytes", f.path, f.size);
        let file = match File::open(&f.path) {
            Ok(v) => v,
            Err(_e) => { println!("ERROR {} : File '{}' cannot be opened", f.path.display(), _e); continue }
        };
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let newline = match line {
                Ok(v) => v,
                Err(_e) => return Err(format!("ERROR {} : Line from file '{}' cannot be read", f.path.display(), _e))
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
                Err(_e) => return Err(format!("Could not canonicalize the path '{}'", file_path))
            }; 
            if !canonical_path.exists() {
                println!("File '{:?} cannot be found", canonical_path);
                continue;
            }
            hash_vec.insert(canonical_path, hashval.to_string());
        }
    }

    if hash_vec.len() == 0 {
        return Err("No hashes read from hashfiles".to_string());
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
pub fn perform_hash(fdata: FileData, alg: HashAlg) -> Result<bool, String>
{
    // file existence check performed earlier, though we could put one here for completeness
    let mut hasher = select_hasher(alg);

    // open file and read data into heap-based buffer
    const BUFSIZE: usize = 1024 * 1024 * 2; // 2 MB
    let mut buffer: Box<[u8]> = vec![0; BUFSIZE].into_boxed_slice();
    let mut file = match File::open(&fdata.path)
    {
        Ok(v) => v,
        Err(_e) => return Err(format!("Unable to open file - Error {}", _e))
    };

    loop {
        let read_count = match file.read(&mut buffer[..BUFSIZE]) {
            Ok(v) => v,
            Err(_e) => return Err(format!("Read failure: {}", _e))
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
    Ok(success)
}