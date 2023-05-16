use {
    crate::error::HasherError,
    minisign::{KeyPair, PublicKey, PublicKeyBox, SecretKeyBox, SignatureBox},
    std::{
        fs::{canonicalize, read_to_string, File},
        io::Write,
        path::{Path, PathBuf},
    },
};

fn load_pubkey(pubkey_path: String) -> Result<PublicKeyBox, HasherError> {
    let pubkey = canonicalize(Path::new(&pubkey_path))?;
    if !pubkey.is_file() {
        Err(HasherError::File {
            why: String::from("Public Key Path is not a valid file"),
            path: pubkey.display().to_string(),
        })
    } else {
        let contents = read_to_string(pubkey)?;
        Ok(PublicKeyBox::from_string(&contents)?)
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

pub fn gen_keypair(prefix: &str) -> Result<KeyPair, HasherError> {
    let KeyPair { pk, sk } = KeyPair::generate_encrypted_keypair(None)
        .expect("Key generation is infalliable, but we have an error for some reason");

    // Write keypair to disk
    {
        let pubstr = format!("./{prefix}.pub");
        let privstr = format!("./{prefix}.key");
        info!("Writing keys to disk:\n\tPublic key => {pubstr}\n\tPrivate key => {privstr}");

        let mut pk_file = File::create(pubstr)?;
        let pk_box_str = pk.to_box()?.to_string();
        pk_file.write(pk_box_str.as_bytes()).ok();

        let mut sk_file = File::create(privstr)?;
        let sk_box_str = sk.to_box(None)?.to_string();
        sk_file.write(sk_box_str.as_bytes()).ok();
    }

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

    let signature_box = SignatureBox::from_file(&sigfile)?;
    let verified = minisign::verify(
        pk,
        &signature_box,
        File::open(hashfile)?,
        true,
        false,
        false,
    );
    match verified {
        Ok(()) => info!("[+] Signature is valid"),
        Err(_) => error!("[!] Signature failed to validate"),
    };
    Ok(())
}

pub fn sign_hash_file(
    hashfile_path: String,
    public_key: String,
    private_key: String,
) -> Result<(), HasherError> {
    // Read the hashfile as bytes
    let hashfile = canonicalize(Path::new(&hashfile_path))?;
    if !hashfile.is_file() {
        return Err(HasherError::File {
            why: String::from("Hashfile Path is not a valid file"),
            path: hashfile.display().to_string(),
        });
    }

    let pk = load_pubkey(public_key)?.into_public_key()?;
    let sk = load_privkey(private_key)?.into_secret_key(None)?;
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
        g.write_all(sigbox.into_string().as_bytes())?;
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
