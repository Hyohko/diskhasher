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
use {crate::HasherError, std::mem, std::path::PathBuf, walkdir::DirEntry};

#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

/// Internal structure that tracks files being sent to the
/// hasher thread pool
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileData {
    size: u64,
    path: PathBuf,
    #[cfg(target_os = "linux")]
    inode: u64,
    expected_hash: String,
}

impl FileData {
    /// FileData constructor
    #[cfg(not(target_os = "linux"))]
    pub fn new(size: u64, path: PathBuf) -> Self {
        Self {
            size,
            path,
            expected_hash: String::new(),
        }
    }
    #[cfg(target_os = "linux")]
    pub fn new(size: u64, path: PathBuf, inode: u64) -> Self {
        Self {
            size,
            path,
            inode,
            expected_hash: String::new(),
        }
    }
    /// Size of referenced file
    pub fn size(&self) -> u64 {
        self.size
    }
    /// Path to referenced file
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
    /// [linux] Inode of referenced file
    #[cfg(target_os = "linux")]
    pub fn inode(&self) -> u64 {
        self.inode
    }
    /// File path as a string for debug prints
    pub fn path_string(&self) -> String {
        self.path.display().to_string()
    }
    /// Cryptographic hash as hexstring
    pub fn hash(&self) -> &String {
        &self.expected_hash
    }
    /// Permits setting of the hash value during computation
    pub fn set_hash(&mut self, hash: &mut String) {
        self.expected_hash = mem::take(hash);
    }
}

impl TryFrom<DirEntry> for FileData {
    type Error = HasherError;
    fn try_from(entry: DirEntry) -> Result<Self, HasherError> {
        let path = entry.path().to_path_buf();
        let metadata = path.metadata()?;

        #[cfg(not(target_os = "linux"))]
        return Ok(Self::new(metadata.len(), path));

        #[cfg(target_os = "linux")]
        return Ok(Self::new(metadata.len(), path, metadata.ino()));
    }
}
