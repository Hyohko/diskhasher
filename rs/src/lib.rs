use {
    clap::ValueEnum,
    digest::DynDigest,
    hex,
    regex::Regex,
    std::collections::HashMap,
    std::fmt::{self, Display, Formatter},
    std::fs,
    std::fs::File,
    std::io::{BufRead, BufReader, Read},
    std::path::{Path, PathBuf},
    walkdir::WalkDir,
};

// TODO - remove public fields
#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileData {
    pub size: u64,
    pub path: PathBuf,
    pub expected_hash: String,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
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

////////////////////////////////////////////////////////////////////////////////////////
/// Recursively enumerates an absolute (canonicalized) path,
/// returns Option<Vec<FileData>>, sorted smallest file to largest
pub fn recursive_dir(abs_root_path: &Path) -> Result<Vec<FileData>, String> {
    let mut file_vec = Vec::<FileData>::new();
    for entry in WalkDir::new(abs_root_path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            let size: u64 = match entry.path().metadata() {
                Ok(f) => f.len(),
                Err(_e) => continue,
            };
            file_vec.push(FileData {
                size,
                path: entry.path().to_path_buf(),
                expected_hash: "".to_string(),
            });
        }
    }
    // Sort vector by file size, smallest first
    file_vec.sort_by(|a, b| a.size.cmp(&b.size));
    Ok(file_vec)
}

////////////////////////////////////////////////////////////////////////////////////////
fn hash_hexpattern() -> Regex {
    const STR_REGEX: &str = concat!(
        r"([[:xdigit:]]{32})|", // MD5
        r"([[:xdigit:]]{48})|", // SHA1
        r"([[:xdigit:]]{56})|", // SHA224
        r"([[:xdigit:]]{64})|", // SHA256
        r"([[:xdigit:]]{96})|", // SHA384
        r"([[:xdigit:]]{128})", // SHA512
    );
    // error checking omitted b/c we've already validated this
    // regex string as correct
    Regex::new(&STR_REGEX).unwrap()
}

////////////////////////////////////////////////////////////////////////////////////////
fn split_hashfile_line(
    newline: &String,
    hashpath: &PathBuf,
    regex_pattern: &Regex,
) -> Result<(PathBuf, String), String> {
    let mut splitline = newline.split(" ");
    let hashval = splitline.next().unwrap();
    // check first bit for valid hex string
    if !regex_pattern.is_match(hashval) {
        // Not valid hex string, continue
        return Err("[!] Line does not start with a valid hex string".to_string());
    }
    // canonicalize path by joining, then check for existence
    splitline.next();
    let file_path = splitline.next().unwrap();
    let canonical_result = fs::canonicalize(hashpath.join(file_path)).or_else(|err| {
        return Err(format!(
            "[!] ERROR {}: Could not canonicalize the path '{}'",
            err, file_path
        ));
    });
    let canonical_path = canonical_result.unwrap();
    if !canonical_path.exists() {
        return Err(format!("[!] File '{:?} cannot be found", canonical_path));
    }
    Ok((canonical_path, hashval.to_string()))
}

////////////////////////////////////////////////////////////////////////////////////////
/// Load hashes from single hash file
/// Takes Regex as argument to avoid repeated computation of it
fn load_hashes_single(
    path: &PathBuf,
    hashmap: &mut HashMap<PathBuf, String>,
    regex_pattern: &Regex,
) -> Result<(), String> {
    // get the directory name of the hashfile (should already be in canonical form)
    let mut hashpath = path.clone();
    hashpath.pop();

    // Open file
    let file = File::open(path).or_else(|err| {
        return Err(format!(
            "[!] ERROR {} : Hashfile '{}' cannot be opened, trying any others",
            path.display(),
            err
        ));
    });

    // Read file
    let reader = BufReader::new(file.unwrap());
    for line in reader.lines() {
        let newline = line.or_else(|err| {
            return Err(format!(
                "[!] ERROR {} : Line from file '{}' cannot be read",
                path.display(),
                err
            ));
        });

        let (canonical_path, hashval) =
            match split_hashfile_line(&newline.unwrap(), &hashpath, regex_pattern) {
                Ok(v) => v,
                Err(_e) => continue, //return Err(_e),
            };
        hashmap.insert(canonical_path, hashval);
    }
    Ok(())
}

////////////////////////////////////////////////////////////////////////////////////////
/// Loads the expected hashes for a directory from a hashfile,
/// expects the file format to be "[hex string] [relative file path]"
pub fn load_hashes(hashfiles: &Vec<FileData>) -> Result<HashMap<PathBuf, String>, String> {
    let mut hash_vec: HashMap<PathBuf, String> = HashMap::new();
    let regex_pattern = hash_hexpattern();

    for f in hashfiles {
        // TODO - error handling case. Normally, just continue through all
        // hashfiles
        let _e = load_hashes_single(&f.path, &mut hash_vec, &regex_pattern);
    }

    if hash_vec.len() == 0 {
        return Err("No hashes read from hashfiles".to_string());
    }
    Ok(hash_vec)
}

// use md5;

////////////////////////////////////////////////////////////////////////////////////////
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

////////////////////////////////////////////////////////////////////////////////////////
/// Compute the hash of a given file
fn hash_file(path: &PathBuf, alg: HashAlg) -> Result<String, String> {
    // file existence check performed earlier, though we could put one here for completeness
    let mut hasher = select_hasher(alg);

    // open file and read data into heap-based buffer
    const BUFSIZE: usize = 1024 * 1024 * 2; // 2 MB
    let mut buffer: Box<[u8]> = vec![0; BUFSIZE].into_boxed_slice();
    let file_result = File::open(path).or_else(|err| {
        return Err(format!("[-] ERROR {}: Unable to open file", err));
    });

    loop {
        let mut file = file_result.as_ref().unwrap();
        let read_result = file.read(&mut buffer[..BUFSIZE]).or_else(|err| {
            return Err(format!("[-] ERROR {}: Read failure", err));
        });
        let read_count = read_result.unwrap();
        hasher.update(&buffer[..read_count]);
        if read_count < BUFSIZE {
            break;
        }
    }

    Ok(hex::encode(hasher.finalize()))
}

////////////////////////////////////////////////////////////////////////////////////////
/// Thread function that opens file, hashes, and compares with expected hash
pub fn perform_hash(
    fdata: FileData,
    alg: HashAlg,
    force: bool,
    verbose: bool,
) -> Result<bool, String> {
    let actual_hash = hash_file(&fdata.path, alg)?;

    // Compute checksum and don't check expected vs actual
    if force {
        println!(
            "[*] Checksum value : {:?}\n\tHash         : {:?}",
            &fdata.path, actual_hash
        );
        return Ok(true);
    }

    // Compare
    let success: bool = &fdata.expected_hash == &actual_hash;
    if success {
        if verbose {
            println!(
                "[+] Checksum passed: {:?}\n\tActual hash  : {:?}",
                &fdata.path, actual_hash
            );
        }
    } else {
        println!(
            "[-] Checksum failed: {:?}\n\tExpected hash: {:?}\n\tActual hash  : {:?}",
            &fdata.path, &fdata.expected_hash, actual_hash
        );
    }
    Ok(success)
}

/*pub fn partition_files(all_files: &Vec<FileData>, hash_regex: Regex) -> (Vec<FileData>, Vec<FileData>) {
    let (hashfiles, checked_files) : (Vec<FileData>, Vec<FileData>) = all_files
        .into_iter()
        .partition( |f| hash_regex.is_match(f.path.file_name().unwrap().to_str().unwrap()) );
    (hashfiles, checked_files)
}*/
