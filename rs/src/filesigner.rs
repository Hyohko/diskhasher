/*
    DKHASH - 2025 by Hyohko

    ##################################
    GPLv3 NOTICE AND DISCLAIMER
    ##################################

    This file is part of DKHASH.

    DKHASH is free software: you can redistribute it
    and/or modify it under the terms of the GNU General
    Public License as published by the Free Software
    Foundation, either version 3 of the License, or (at
    your option) any later version.

    DKHASH is distributed in the hope that it will
    be useful, but WITHOUT ANY WARRANTY; without even
    the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General
    Public License along with DKHASH. If not, see
    <https://www.gnu.org/licenses/>.
*/
use {
    crate::{
        error::HasherError,
        util::{add_extension, current_timestamp_as_string},
    },
    cpu_endian::{Endian, working},
    minisign::{KeyPair, PublicKey, SecretKey, SignatureBox},
    std::{
        fs::{File, canonicalize},
        io::Write,
        path::{Path, PathBuf},
    },
};

/// Generate a MiniSign Ed22519 Public/Private keypair and save them to disk
/// using the prefix argument to name the files.
pub fn gen_keypair(prefix: &str, password: Option<String>) -> Result<(), HasherError> {
    let paths = [format!("./{prefix}.pub"), format!("./{prefix}.key")];
    for st in paths.iter() {
        if Path::new(&st).exists() {
            return Err(HasherError::File {
                path: st.to_string(),
                why: "Keyfile already exists, delete and run 'genkey' again".to_string(),
            });
        }
    }
    info!(
        "Writing keys to disk:\n\tPublic key => {}\n\tPrivate key => {}",
        paths[0], paths[1]
    );

    let comment = Some(format!(
        "DKHASH Keyfile Created => {}",
        current_timestamp_as_string()
    ));
    KeyPair::generate_and_write_encrypted_keypair(
        File::create(&paths[0])?,
        File::create(&paths[1])?,
        comment.as_deref(),
        password, // if None, no password
    )
    .expect("Key generation is supposed to be infalliable, but we have an error for some reason");
    Ok(())
}

/// Hexencode a public key's keynum, correcting for endianness -
/// output will be in Big Endian
/// todo - validate on BE architecture - the keynum should be the same
pub fn keynum_to_string(pk: &PublicKey) -> String {
    let outstr = match working() {
        Endian::Little => {
            let mut out = pk.keynum().to_vec();
            out.reverse();
            hex::encode(out)
        }
        Endian::Big => hex::encode(pk.keynum()),
        // cpu_endian provides a `Minor` type, so we have to acount for it in the match statement
        Endian::Minor => panic!("Unsupported CPU architecture"),
    };
    outstr.to_uppercase()
}

/// Sign a file using a private key in the MiniSign format.
/// The signature file will be at the same path as the original file
/// but will have the public key's ID number appended as an extension.
pub fn sign_file(
    file_to_sign: &String,
    private_key: &String,
    password: Option<String>,
) -> Result<(), HasherError> {
    info!("[+] Creating digital signature for {file_to_sign}");
    let filepath = canonicalize(Path::new(&file_to_sign))?;
    if !filepath.is_file() {
        return Err(HasherError::File {
            why: String::from("'File to Sign' Path is not a valid file"),
            path: filepath.display().to_string(),
        });
    }

    let pk: PublicKey;
    let sigbox: SignatureBox;
    {
        // scope to drop SecretKey as soon as it is no longer needed
        info!("Loading private key file => {private_key}");
        let sk: SecretKey = SecretKey::from_file(private_key, password)?;
        info!("Deriving public key from private key");
        pk = PublicKey::from_secret_key(&sk)?;

        const VERSION: &str = env!("CARGO_PKG_VERSION");
        const DKHASH: &str = env!("CARGO_PKG_NAME");
        let untrusted_comment = Some(format!("Signed by {DKHASH} {VERSION}").to_string());
        let trusted_comment = Some(format!(
            "Key ID => {} ||| Signature Time/Date (UTC) => {}",
            keynum_to_string(&pk),
            current_timestamp_as_string()
        ));
        sigbox = minisign::sign(
            None,
            &sk,
            File::open(&filepath)?,
            trusted_comment.as_deref(),
            untrusted_comment.as_deref(),
        )?;
    }

    // Write signature to file
    let mut sigfile: PathBuf = filepath.clone();
    add_extension(&mut sigfile, keynum_to_string(&pk));
    info!("Writing signature file\n\t==> {:?}", sigfile);
    File::create(sigfile)?.write_all(sigbox.into_string().as_bytes())?;

    // Check signature to make sure nothing went sideways
    validate_signature(&pk, &filepath)
}

/// Internal function for validating a file's corresponding
/// signature file with a MiniSign public key
fn validate_signature(pk: &PublicKey, file_to_validate: &PathBuf) -> Result<(), HasherError> {
    let mut sigfile: PathBuf = file_to_validate.clone();
    add_extension(&mut sigfile, keynum_to_string(pk));
    info!(
        "Loading signature file\n\t=> {}",
        sigfile.display().to_string()
    );

    // This Ok(...?) construct coerces `PError` to `HasherError` using `From<PError>` trait
    Ok(minisign::verify(
        pk,
        &SignatureBox::from_file(&sigfile)?,
        File::open(file_to_validate)?,
        false,
        false,
        false,
    )?)
}

/// Verify a file's signature using a public key in the MiniSign format.
/// The signature file *must* be at the same path as the original file
/// and must have the public key's ID number appended as an extension.
pub fn verify_file(file_to_sign: &String, public_key: &String) -> Result<(), HasherError> {
    info!("[+] Validating digital signature of {file_to_sign}");
    let filepath = canonicalize(Path::new(file_to_sign))?;
    if !filepath.is_file() {
        return Err(HasherError::File {
            why: String::from("'File to Sign' Path is not a valid file"),
            path: filepath.display().to_string(),
        });
    }

    info!("Loading public key file => {public_key}");
    let pk: PublicKey = PublicKey::from_file(public_key)?;
    validate_signature(&pk, &filepath)
}
