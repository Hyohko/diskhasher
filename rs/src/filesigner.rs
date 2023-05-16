/*
    DISKHASHER v0.3 - 2023 by Hyohko

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
    minisign::{KeyPair, PublicKey, SecretKey, SignatureBox},
    std::{
        fs::{canonicalize, File},
        io::Write,
        path::{Path, PathBuf},
    },
};

pub fn gen_keypair(prefix: &str, comment: Option<&str>) -> Result<(), HasherError> {
    let pubstr = format!("./{prefix}.pub");
    let privstr = format!("./{prefix}.key");
    info!("Writing keys to disk:\n\tPublic key => {pubstr}\n\tPrivate key => {privstr}");
    KeyPair::generate_and_write_encrypted_keypair(
        File::create(pubstr)?,
        File::create(privstr)?,
        comment,
        None, // always prompt
    )
    .expect("Key generation is infalliable, but we have an error for some reason");
    Ok(())
}

fn validate_signature(pk: &PublicKey, hashfile: &PathBuf) -> Result<(), HasherError> {
    let mut sigfile: PathBuf = hashfile.clone();
    add_extension(&mut sigfile, "minisig");
    info!(
        "Loading signature file\n\t=> {}",
        sigfile.display().to_string()
    );
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
    let hashfile = canonicalize(Path::new(&hashfile_path))?;
    if !hashfile.is_file() {
        return Err(HasherError::File {
            why: String::from("Hashfile Path is not a valid file"),
            path: hashfile.display().to_string(),
        });
    }

    info!("Loading public key file => {public_key}");
    let pk: PublicKey = PublicKey::from_file(public_key)?;
    info!("Loading private key file => {private_key}");
    let sigbox: SignatureBox;
    {
        // scope to drop SecretKey as soon as it is no longer needed
        let sk: SecretKey = SecretKey::from_file(private_key, None)?;
        sigbox = minisign::sign(None, &sk, File::open(&hashfile)?, None, None)?;
    }

    // Write signature to file
    let mut sigfile: PathBuf = hashfile.clone();
    add_extension(&mut sigfile, "minisig");
    info!("Writing signature file\n\t==> {:?}", sigfile);
    File::create(sigfile)?.write_all(sigbox.into_string().as_bytes())?;

    // Check signature to make sure nothing went sideways
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

    info!("Loading public key file => {public_key}");
    let pk: PublicKey = PublicKey::from_file(public_key)?;
    validate_signature(&pk, &hashfile)
}
