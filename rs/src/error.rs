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
use {custom_error::custom_error, indicatif::style::TemplateError};

custom_error! {pub HasherError
    RegexError{why: String} = "Regular expression failed => {why}",
    FileError{path: String, why: String} = "File/Directory error => '{path}': {why}",
    HashError{why: String} = "Hash error => {why}",
    ThreadingError{why: String} = "Thread operation failed => {why}",
    ParseError{why: String} = "Parse error => {why}",
    IoError{why: String} = "IO Failure => {why}",
    StyleError{why: String} = "ProgressBar style error => {why}",
    IntegerError{why: String} = "Integer conversion error => {why}",
    AllocationError{why: String} = "Allocation failure => {why}"
}

impl From<TemplateError> for HasherError {
    fn from(error: TemplateError) -> Self {
        HasherError::StyleError {
            why: format!("{error:?}"),
        }
    }
}

// todo https://stackoverflow.com/questions/53934888/how-to-include-the-file-path-in-an-io-error-in-rust
impl From<std::io::Error> for HasherError {
    fn from(error: std::io::Error) -> Self {
        HasherError::IoError {
            why: format!("{:?} => {error:?}", error.kind()),
        }
    }
}
