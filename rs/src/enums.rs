
use clap::ValueEnum;
use std::fmt::{self, Display, Formatter};
/// Supported hash algorithms
#[non_exhaustive]
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum HashAlg {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

impl Display for HashAlg {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MD5 => write!(f, "MD5"),
            Self::SHA1 => write!(f, "SHA1"),
            Self::SHA224 => write!(f, "SHA224"),
            Self::SHA256 => write!(f, "SHA256"),
            Self::SHA384 => write!(f, "SHA384"),
            Self::SHA512 => write!(f, "SHA512"),
        }
    }
}

/// Option to command line args - sort files from WalkDir
/// by LargestFirst, SmallestFirst, or in InodeOrder
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum FileSortLogic {
    LargestFirst,
    SmallestFirst,
    #[cfg(target_os = "linux")]
    InodeOrder,
}
