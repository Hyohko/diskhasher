use {
    crate::error::HasherError,
    minisign::{KeyPair, PublicKey, PublicKeyBox, SecretKeyBox, SignatureBox},
    std::{
        fs::{canonicalize, read_to_string, File},
        io::{stdin, Write},
        path::{Path, PathBuf},
        process,
    },
};

fn prompt_for_new_keypair() {
    println!("Do you want to generate a new keypair? (Y/N)\n> ");
    let mut user_input = String::new();
    let stdin = stdin();
    loop {
        stdin.read_line(&mut user_input).expect("");
        match user_input.trim().chars().nth(0) {
            Some('y') | Some('Y') => return,
            Some('n') | Some('N') | Some('q') | Some('Q') => {
                error!("No keypair generated, exiting");
                process::exit(-1);
            }
            _ => println!("[-] Invalid input, enter 'yes' or 'no'"),
        }
    }
}

fn load_pubkey(pubkey_path: String) -> Result<PublicKeyBox, HasherError> {
    let pubkey = canonicalize(Path::new(&pubkey_path))?;
    if !pubkey.is_file() {
        Err(HasherError::File {
            why: String::from("Public Key Path is not a valid file"),
            path: pubkey.display().to_string(),
        })
    } else {
        let contents = read_to_string(pubkey)?;
        Ok(PublicKeyBox::from_string(&contents)?) // TODO From(PError to HasherError)
    }
}

fn load_privkey(privkey_path: String) -> Result<SecretKeyBox, HasherError> {
    let privkey = canonicalize(Path::new(&privkey_path))?;
    if !privkey.is_file() {
        Err(HasherError::File {
            why: String::from("Private Key Path is not a valid file"),
            path: privkey.display().to_string(),
        })
    } else {
        let contents = read_to_string(privkey)?;
        Ok(SecretKeyBox::from_string(&contents)?)
    }
}

fn get_or_create_keypair(
    public_key: Option<String>,
    private_key: Option<String>,
) -> Result<KeyPair, HasherError> {
    if public_key == None || private_key == None {
        warn!("Public Key or Private Key is missing");
        prompt_for_new_keypair();
        let KeyPair { pk, sk } = KeyPair::generate_encrypted_keypair(None)
            .expect("Key generation is infalliable, but we have an error for some reason");

        // Write keypair to disk
        {
            let pubstr = "./hashsign.pub";
            let privstr = "./hashsign.key";
            info!("Writing keys to disk:\n\tPublic key => {pubstr}\n\tPrivate key => {privstr}");

            let mut pk_file = File::create(pubstr)?;
            let pk_box_str = pk.to_box()?.to_string();
            pk_file.write(pk_box_str.as_bytes()).ok();

            let mut sk_file = File::create(privstr)?;
            let sk_box_str = sk.to_box(None)?.to_string();
            sk_file.write(sk_box_str.as_bytes()).ok();
        }

        return Ok(KeyPair { pk, sk });
    }

    // Unwrap b/c we've already checked for None
    let pk = load_pubkey(public_key.unwrap())?.into_public_key()?;
    let sk = load_privkey(private_key.unwrap())?.into_secret_key(None)?;
    Ok(KeyPair { pk, sk })
}

fn add_extension(path: &mut std::path::PathBuf, extension: impl AsRef<std::path::Path>) {
    match path.extension() {
        Some(ext) => {
            let mut ext = ext.to_os_string();
            ext.push(".");
            ext.push(extension.as_ref());
            path.set_extension(ext)
        }
        None => path.set_extension(extension.as_ref()),
    };
}

fn validate_signature(pk: &PublicKey, hashfile: &PathBuf) -> Result<(), HasherError> {
    let mut sigfile: PathBuf = hashfile.clone();
    add_extension(&mut sigfile, "minisig");

    //let sigstring = read_to_string(sigfile)?;
    let sigbox = SignatureBox::from_file(&sigfile)?;

    let f = File::open(&hashfile)?;
    let verified = minisign::verify(pk, &sigbox, &f, true, false, false);
    match verified {
        Ok(()) => info!("[+] Signature is valid"),
        Err(_) => error!("[!] Signature failed to validate"),
    };
    Ok(())
}

pub fn sign_hash_file(
    hashfile_path: String,
    public_key: Option<String>,
    private_key: Option<String>,
) -> Result<(), HasherError> {
    // Read the hashfile as bytes
    let hashfile = canonicalize(Path::new(&hashfile_path))?;
    if !hashfile.is_file() {
        return Err(HasherError::File {
            why: String::from("Hashfile Path is not a valid file"),
            path: hashfile.display().to_string(),
        });
    }

    let KeyPair { pk, sk } = get_or_create_keypair(public_key, private_key)?;
    let sigbox: SignatureBox;
    {
        let f = File::open(&hashfile)?;
        sigbox = minisign::sign(None, &sk, &f, None, None)?;
    }

    // Write signature to file
    let mut sigfile: PathBuf = hashfile.clone();
    add_extension(&mut sigfile, "minisig");
    info!("Writing signature file\n\t==> {:?}", sigfile);
    {
        let mut g = File::create(sigfile)?;
        g.write(sigbox.into_string().as_bytes())?;
    }
    validate_signature(&pk, &hashfile)
}

pub fn verify_hash_file(hashfile_path: String, public_key: String) -> Result<(), HasherError> {
    let hashfile = canonicalize(Path::new(&hashfile_path))?;
    if !hashfile.is_file() {
        return Err(HasherError::File {
            why: String::from("Hashfile Path is not a valid file"),
            path: hashfile.display().to_string(),
        });
    }

    let pk = load_pubkey(public_key)?.into_public_key()?;
    validate_signature(&pk, &hashfile)
}
