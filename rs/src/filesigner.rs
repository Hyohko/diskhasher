/*
    DISKHASHER - 2023 by Hyohko

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
    crate::{error::HasherError, util::add_extension},
    cpu_endian::{working, Endian},
    minisign::{KeyPair, PublicKey, SecretKey, SignatureBox},
    std::{
        fs::{canonicalize, File},
        io::Write,
        path::{Path, PathBuf},
    },
};

pub fn gen_keypair(prefix: &str, comment: Option<String>) -> Result<(), HasherError> {
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
    KeyPair::generate_and_write_encrypted_keypair(
        File::create(&paths[0])?,
        File::create(&paths[1])?,
        comment.as_deref(),
        None, // always prompt
    )
    .expect("Key generation is supposed to be infalliable, but we have an error for some reason");
    Ok(())
}

/// Hexencode a public key's keynum, correcting for endianness -
/// output will be in Big Endian
fn keynum_to_string(pk: &PublicKey) -> String {
    let outstr = match working() {
        Endian::Little => {
            let mut out = pk.keynum().to_vec();
            out.reverse();
            hex::encode(out)
        }
        Endian::Big => hex::encode(pk.keynum()),
        _ => panic!("If it's not BigEndian or LittleEndian, you're out of luck"),
    };
    outstr.to_uppercase()
}

pub fn sign_file(
    hashfile_path: String,
    private_key: String,
    trusted_comment: Option<String>,
    untrusted_comment: Option<String>,
) -> Result<(), HasherError> {
    info!("[+] Creating digital signature for {hashfile_path}");
    let hashfile = canonicalize(Path::new(&hashfile_path))?;
    if !hashfile.is_file() {
        return Err(HasherError::File {
            why: String::from("Hashfile Path is not a valid file"),
            path: hashfile.display().to_string(),
        });
    }

    let pk: PublicKey;
    let sigbox: SignatureBox;
    {
        // scope to drop SecretKey as soon as it is no longer needed
        info!("Loading private key file => {private_key}");
        let sk: SecretKey = SecretKey::from_file(private_key, None)?;
        info!("Deriving public key from private key");
        pk = PublicKey::from_secret_key(&sk)?;
        sigbox = minisign::sign(
            None,
            &sk,
            File::open(&hashfile)?,
            trusted_comment.as_deref(),
            untrusted_comment.as_deref(),
        )?;
    }

    // Write signature to file
    let mut sigfile: PathBuf = hashfile.clone();
    add_extension(&mut sigfile, keynum_to_string(&pk));
    info!("Writing signature file\n\t==> {:?}", sigfile);
    File::create(sigfile)?.write_all(sigbox.into_string().as_bytes())?;

    // Check signature to make sure nothing went sideways
    validate_signature(&pk, &hashfile)
}

fn validate_signature(pk: &PublicKey, hashfile: &PathBuf) -> Result<(), HasherError> {
    let mut sigfile: PathBuf = hashfile.clone();
    add_extension(&mut sigfile, keynum_to_string(pk));
    info!(
        "Loading signature file\n\t=> {}",
        sigfile.display().to_string()
    );
    let signature_box = SignatureBox::from_file(&sigfile)?;
    Ok(minisign::verify(
        pk,
        &signature_box,
        File::open(hashfile)?,
        true,
        false,
        false,
    )?)
}

pub fn verify_file(hashfile_path: String, public_key: String) -> Result<(), HasherError> {
    info!("[+] Validating digital signature of {hashfile_path}");
    let hashfile = canonicalize(Path::new(&hashfile_path))?;
    if !hashfile.is_file() {
        return Err(HasherError::File {
            why: String::from("Hashfile Path is not a valid file"),
            path: hashfile.display().to_string(),
        });
    }

    info!("Loading public key file => {public_key}");
    let pk: PublicKey = PublicKey::from_file(public_key)?;
    validate_signature(&pk, &hashfile)
}
