/*
    DKHASH - 2023 by Hyohko

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

custom_error! {pub HasherError
    Argument{why: String} = "CLI argument error\n\t=> {why}",
    Regex{why: String} = "Regular expression failed\n\t=> {why}",
    File{path: String, why: String} = "File/Directory error\n\t=> '{path}': {why}",
    Hash{why: String} = "Hash error\n\t=> {why}",
    Threading{why: String} = "Thread operation failed\n\t=> {why}",
    Parse{why: String} = "Parse error\n\t=> {why}",
    Io{why: String} = "IO Failure\n\t=> {why}",
    Style{why: String} = "ProgressBar style error\n\t=> {why}",
    Signature{why: String} = "Digital signature error\n\t=> {why}"
}

impl From<TemplateError> for HasherError {
    fn from(error: TemplateError) -> Self {
        Self::Style {
            why: format!("{error:?}"),
        }
    }
}

// todo https://stackoverflow.com/questions/53934888/how-to-include-the-file-path-in-an-io-error-in-rust
impl From<std::io::Error> for HasherError {
    fn from(error: std::io::Error) -> Self {
        Self::Io {
            why: format!("{:?} => {error:?}", error.kind()),
        }
    }
}

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
