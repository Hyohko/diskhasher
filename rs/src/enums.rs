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

use clap::{builder::PossibleValue, ValueEnum};

/// Supported hash algorithms
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum HashAlg {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

impl ValueEnum for HashAlg {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::MD5,
            Self::SHA1,
            Self::SHA224,
            Self::SHA256,
            Self::SHA384,
            Self::SHA512,
            Self::SHA3_224,
            Self::SHA3_256,
            Self::SHA3_384,
            Self::SHA3_512,
        ]
    }

    fn to_possible_value<'a>(&self) -> Option<PossibleValue> {
        Some(match self {
            Self::MD5 => PossibleValue::new("md5").help("MD5 (insecure)"),
            Self::SHA1 => PossibleValue::new("sha1").help("SHA1 (insecure)"),
            Self::SHA224 => PossibleValue::new("sha224").help("SHA224"),
            Self::SHA256 => PossibleValue::new("sha256").help("SHA256"),
            Self::SHA384 => PossibleValue::new("sha384").help("SHA384"),
            Self::SHA512 => PossibleValue::new("sha512").help("SHA512"),
            Self::SHA3_224 => PossibleValue::new("sha3-224").help("SHA3-224"),
            Self::SHA3_256 => PossibleValue::new("sha3-256").help("SHA3-256"),
            Self::SHA3_384 => PossibleValue::new("sha3-384").help("SHA3-384"),
            Self::SHA3_512 => PossibleValue::new("sha3-512").help("SHA3-512"),
        })
    }
}

impl std::fmt::Display for HashAlg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value()
            .expect("no values are skipped")
            .get_name()
            .fmt(f)
    }
}

impl std::str::FromStr for HashAlg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for variant in Self::value_variants() {
            if variant.to_possible_value().unwrap().matches(s, false) {
                return Ok(*variant);
            }
        }
        Err(format!("invalid hash algorithm: {s}"))
    }
}

/// Option to command line args - sort files from `WalkDir`
/// by `LargestFirst`, `SmallestFirst`, or in `InodeOrder`
#[derive(Clone, Copy, Debug)]
pub enum FileSortLogic {
    LargestFirst,
    SmallestFirst,
    #[cfg(target_os = "linux")]
    InodeOrder,
}

impl ValueEnum for FileSortLogic {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            #[cfg(target_os = "linux")]
            Self::InodeOrder,
            Self::LargestFirst,
            Self::SmallestFirst,
        ]
    }

    fn to_possible_value<'a>(&self) -> Option<PossibleValue> {
        Some(match self {
            #[cfg(target_os = "linux")]
            Self::InodeOrder => PossibleValue::new("inode-order").help("Sort by inode order"),
            Self::LargestFirst => PossibleValue::new("largest-first").help("Sort by largest first"),
            Self::SmallestFirst => {
                PossibleValue::new("smallest-first").help("Sort by smallest first")
            }
        })
    }
}

impl std::fmt::Display for FileSortLogic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value()
            .expect("no values are skipped")
            .get_name()
            .fmt(f)
    }
}

impl std::str::FromStr for FileSortLogic {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for variant in Self::value_variants() {
            if variant.to_possible_value().unwrap().matches(s, false) {
                return Ok(*variant);
            }
        }
        Err(format!("invalid sorting option: {s}"))
    }
}
