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
    crate::error::HasherError,
    regex::Regex,
    std::{
        fs::canonicalize,
        path::{Path, PathBuf},
    },
};

/// Stitch an extra extension onto the end of a path.
/// Adds a leading dot before the new extension.
/// E.g., add_extension("myfile.txt", "new") -> "myfile.txt.new"
pub(crate) fn add_extension(path: &mut PathBuf, extension: &str) {
    let new_ext = match path.extension() {
        Some(ext) => format!("{}.{}", ext.to_string_lossy(), extension),
        None => extension.to_string(),
    };
    path.set_extension(new_ext);
}

/// Canonicalizes a file path, checking to see that the file exists and returns
/// an absolute path to that file.
/// TODO: Once `PathBuf::absolute()` is part of Rust Stable, replace this function
pub(crate) fn canonicalize_filepath(
    file_path: &str,
    containing_dir: &Path,
) -> Result<PathBuf, HasherError> {
    let mut file_path_buf: PathBuf = Path::new(&file_path).to_path_buf();
    if file_path_buf.is_relative() {
        file_path_buf = containing_dir.join(&file_path_buf);
        file_path_buf = canonicalize(file_path_buf)?;
    }
    if file_path_buf.is_file() {
        Ok(file_path_buf)
    } else {
        Err(HasherError::File {
            why: String::from("Path is not a valid regular file"),
            path: file_path_buf.display().to_string(),
        })
    }
}

/// Validates that at least the file name portion of a file path matches
/// the given regular expression.
pub(crate) fn path_matches_regex(hash_regex: &Regex, file_path: &Path) -> bool {
    file_path
        .file_name()
        .and_then(|name| name.to_str())
        .map_or(false, |str_path| hash_regex.is_match(str_path))
}

/// Takes a line from a hashfile in the format "<hash hexstring> <path to file>",
/// validates that the hash is the correct length/format, and checks for the existence
/// of the file on disk at the given path, returning the path and the hash if both check out
pub(crate) fn split_hashfile_line(
    newline: &String,
    hashpath: &Path,
) -> Result<(PathBuf, String), HasherError> {
    let (hashval, file_path) = newline.split_once(' ').ok_or(HasherError::Parse {
        why: format!("Line does not have enough elements: {newline}"),
    })?;
    //alternate - !HEXSTRING_PATTERN.is_match(hashval), maybe someday
    validate_hexstring(hashval)?;
    let canonical_path = canonicalize_filepath(file_path.trim(), hashpath)?;
    Ok((canonical_path, String::from(hashval)))
}

/// Returns Ok(()) if hexstring is a supported length - i.e. matches
/// the output of one of the algorithms we support.
pub(crate) fn validate_hexstring(hexstring: &str) -> Result<(), HasherError> {
    const VALID_LENGTHS: [usize; 6] = [32, 40, 56, 64, 96, 128];

    if !VALID_LENGTHS.contains(&hexstring.len()) {
        return Err(HasherError::Parse {
            why: format!("Bad hexstring length: {}", hexstring.len()),
        });
    }

    if !hexstring.chars().all(|chr| chr.is_ascii_hexdigit()) {
        return Err(HasherError::Parse {
            why: String::from("Non-hex character found"),
        });
    }

    Ok(())
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
