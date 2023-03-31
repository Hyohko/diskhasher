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
    crate::HasherError,
    std::fs,
    std::path::{Path, PathBuf},
};

fn canonicalize_filepath(file_path: &str, hashpath: &Path) -> Result<PathBuf, HasherError> {
    let mut file_path_buf: PathBuf = Path::new(&file_path).to_path_buf();
    if file_path_buf.is_absolute() {
        Ok(file_path_buf)
    } else {
        if !file_path.starts_with("./") {
            let new_file_path: String = format!("./{file_path}");
            file_path_buf = Path::new(&new_file_path).to_path_buf();
        }
        file_path_buf = hashpath.join(&file_path_buf);
        file_path_buf = fs::canonicalize(file_path_buf)?;
        if file_path_buf.is_file() {
            Ok(file_path_buf)
        } else {
            Err(HasherError::File {
                why: String::from("Path is not a valid regular file"),
                path: file_path_buf.display().to_string(),
            })
        }
    }
}

/*use lazy_static::lazy_static;
lazy_static! {
    static ref HEXSTRING_PATTERN: Regex = hash_hexpattern();
}

fn hash_hexpattern() -> Regex {
    const STR_REGEX: &str = concat!(
        r"([[:xdigit:]]{32})|", // MD5
        r"([[:xdigit:]]{40})|", // SHA1
        r"([[:xdigit:]]{56})|", // SHA224
        r"([[:xdigit:]]{64})|", // SHA256
        r"([[:xdigit:]]{96})|", // SHA384
        r"([[:xdigit:]]{128})", // SHA512
    );
    // As this regex is initialized at process startup, panic instead
    // of returning an error
    Regex::new(STR_REGEX).expect("[!] Regular expression engine startup failure")
}*/

pub fn split_hashfile_line(
    newline: &String,
    hashpath: &Path,
) -> Result<(PathBuf, String), HasherError> {
    let (hashval, file_path) = newline.split_once(' ').ok_or(HasherError::Parse {
        why: format!("Line does not have enough elements: {newline}"),
    })?;
    //alternate - !HEXSTRING_PATTERN.is_match(hashval), maybe someday
    validate_hexstring(hashval)?;
    let canonical_path = canonicalize_filepath(&file_path.trim(), hashpath)?;
    Ok((canonical_path, String::from(hashval)))
}

pub fn validate_hexstring(hexstring: &str) -> Result<(), HasherError> {
    match hexstring.len() {
        32 | 40 | 56 | 64 | 96 | 128 => {
            for chr in hexstring.chars() {
                if !chr.is_ascii_hexdigit() {
                    return Err(HasherError::Parse {
                        why: String::from("Non-hex character found"),
                    });
                }
            }
            Ok(())
        }
        _ => Err(HasherError::Parse {
            why: format!("Bad hexstring length: {}", hexstring.len()),
        }),
    }
}
