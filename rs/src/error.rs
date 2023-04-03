/*
    DISKHASHER v0.2 - 2023 by Hyohko

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
    Regex{why: String} = "Regular expression failed => {why}",
    File{path: String, why: String} = "File/Directory error => '{path}': {why}",
    Hash{why: String} = "Hash error => {why}",
    Threading{why: String} = "Thread operation failed => {why}",
    Parse{why: String} = "Parse error => {why}",
    Io{why: String} = "IO Failure => {why}",
    Style{why: String} = "ProgressBar style error => {why}",
}

impl From<TemplateError> for HasherError {
    fn from(error: TemplateError) -> Self {
        HasherError::Style {
            why: format!("{error:?}"),
        }
    }
}

// todo https://stackoverflow.com/questions/53934888/how-to-include-the-file-path-in-an-io-error-in-rust
impl From<std::io::Error> for HasherError {
    fn from(error: std::io::Error) -> Self {
        HasherError::Io {
            why: format!("{:?} => {error:?}", error.kind()),
        }
    }
}
