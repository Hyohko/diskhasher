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
    custom_error::custom_error, indicatif::style::TemplateError, minisign::PError,
    std::path::StripPrefixError,
};
// use std::fmt; // No longer needed as Display is auto-generated

custom_error! {pub HasherError
    Argument{why: String} = "CLI argument error\n\t=> {why}",
    Regex{why: String} = "Regular expression failed\n\t=> {why}",
    File{path: String, source: std::io::Error} = "File/Directory error (see source)", // Provide a basic format string
    Hash{why: String} = "Hash error\n\t=> {why}",
    Threading{why: String} = "Thread operation failed\n\t=> {why}",
    Parse{why: String} = "Parse error\n\t=> {why}",
    Io{source: std::io::Error} = "IO Failure (see source)", // Provide a basic format string
    Style{why: String} = "ProgressBar style error\n\t=> {why}",
    Signature{why: String} = "Digital signature error\n\t=> {why}"
}

// Removed manual fmt::Display for HasherError.
// custom_error! will generate Display. For variants with `source`,
// it will append the source error's display to the provided format string.

impl From<TemplateError> for HasherError {
    fn from(error: TemplateError) -> Self {
        Self::Style {
            why: format!("{error:?}"),
        }
    }
}

// todo https://stackoverflow.com/questions/53934888/how-to-include-the-file-path-in-an-io-error-in-rust
// The custom_error! macro will automatically generate From<std::io::Error> for HasherError::Io
// because the 'Io' variant has a field 'source: std::io::Error'.
// So, the manual implementation below is removed.
// impl From<std::io::Error> for HasherError {
//     fn from(error: std::io::Error) -> Self {
//         Self::Io { source: error }
//     }
// }

impl From<StripPrefixError> for HasherError {
    fn from(error: StripPrefixError) -> Self {
        Self::Parse {
            why: format!("{error:?}"),
        }
    }
}

impl From<PError> for HasherError {
    fn from(error: PError) -> Self {
        Self::Signature {
            why: format!("{error:?}"),
        }
    }
}
