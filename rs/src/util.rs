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
    crate::error::HasherError,
    chrono::{DateTime, Utc},
    regex::Regex,
    std::{
        fs::canonicalize,
        path::{Path, PathBuf},
        time::SystemTime,
    },
};

/// Stitch an extra extension on to the end of a path - add a leading dot before
/// the new extension. E.g. add_extension("myfile.txt", "new") -> "myfile.txt.new"
pub(crate) fn add_extension(path: &mut std::path::PathBuf, extension: impl AsRef<std::path::Path>) {
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

/// Retrieves the current system time and outputs it in RFC 3339 format,
/// always as a UTC (+00:00 or Zulu) timestamp, to the nanosecond where possible
/// e.g. %YYYY-%MM-%DDThh:mm:ss.sssssssss+00:00
pub(crate) fn current_timestamp_as_string() -> String {
    let now = SystemTime::now();
    let now: DateTime<Utc> = now.into();
    now.to_rfc3339()
}

/// Validates that at least the file name portion of a file path matches
/// the given regular expression.
pub(crate) fn path_matches_regex(hash_regex: &Regex, file_path: &Path) -> bool {
    file_path.file_name().map_or_else(
        || {
            error!("[-] Failed to retrieve file name from path object");
            false
        },
        |path| {
            path.to_str().map_or_else(
                || {
                    error!("[-] Failed to convert path to string");
                    false
                },
                |str_path| hash_regex.is_match(str_path),
            )
        },
    )
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
/// the output of one of the algorithms we support
pub(crate) fn validate_hexstring(hexstring: &str) -> Result<(), HasherError> {
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
