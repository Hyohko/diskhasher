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
#[cfg(target_os = "linux")]
use crate::constants::ALIGNMENT;

use crate::{
    constants::{O_FLAGS, SIZE_2MB, SIZE_128MB},
    enums::HashAlg,
    error::HasherError,
    filedata::FileData,
    util::canonicalize_filepath,
};
// Macros at crate top-level
use crate::{filelog, hashobj, known_zero_hash};

use {
    digest::DynDigest,
    indicatif::{MultiProgress, ProgressBar, ProgressStyle},
    std::{
        fs::{File, OpenOptions},
        io::{Read, Write},
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    },
};

#[cfg(target_os = "linux")]
use {aligned_box::AlignedBox, std::os::unix::fs::OpenOptionsExt};

#[cfg(target_os = "windows")]
use std::os::windows::fs::OpenOptionsExt;

// For the ease of refactoring the threadfunc
pub(crate) struct ThreadFuncArgs {
    pub(crate) fdata: FileData,
    pub(crate) alg: HashAlg,
    pub(crate) force: bool,
    pub(crate) verbose: bool,
    pub(crate) loghandle: Option<Arc<Mutex<File>>>,
    pub(crate) opt_mp: Option<MultiProgress>, // is already an Arc
    pub(crate) opt_progress: Option<ProgressBar>, // is already an Arc
    pub(crate) gen_hashfile: Option<Arc<Mutex<File>>>,
    pub(crate) gen_hashfile_dir: Option<PathBuf>,
}

macro_rules! read_all_into_hasher {
    ($fd:expr, $hash:expr) => {
        #[cfg(target_os = "windows")]
        let mut buf = vec![0_u8; SIZE_2MB].into_boxed_slice();
        #[cfg(target_os = "linux")]
        let mut buf = AlignedBox::<[u8]>::slice_from_value(ALIGNMENT, SIZE_2MB, 0_u8)
            .expect("Heap read buffer allocation failed, panic");

        loop {
            let read_count = $fd.read(&mut buf[..SIZE_2MB])?;
            if read_count == 0 {
                break;
            }
            $hash.update(&buf[..read_count]);
        }
    };
}

/// Compute the hash of a single file, given the following conditions:
/// 1. If the file length is zero, return immediately as zero-length hashes are already known.
/// 2. If the file size equals or exceeds 128 MB, show a progress bar.
/// 3. In all cases, read the file in 2MB chunks and compute the hash as given by `alg`.
pub(crate) fn hash_file(
    fdata: &FileData,
    alg: HashAlg,
    opt_mp: &Option<MultiProgress>,
) -> Result<String, HasherError> {
    if fdata.size() == 0 {
        return Ok(known_zero_hash!(alg));
    }

    let mut hasher: Box<dyn DynDigest> = hashobj!(alg);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_FLAGS.try_into().expect("Invalid O_FLAGS configuration"))
        .open(fdata.path())?;

    if opt_mp.is_some() && fdata.size() >= SIZE_128MB as u64 {
        let mp = opt_mp.as_ref().unwrap();
        let bar = create_progress_bar(mp, fdata)?;
        read_all_into_hasher!(bar.wrap_read(&file), hasher);
        bar.finish_and_clear();
        mp.remove(&bar);
    } else {
        read_all_into_hasher!(file, hasher);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Create a progress bar for large files.
fn create_progress_bar(mp: &MultiProgress, fdata: &FileData) -> Result<ProgressBar, HasherError> {
    let style = ProgressStyle::with_template(
        "[{elapsed_precise}] \
        ({percent:3}%) \
        {bar:30.cyan/blue} \
        {bytes:>10.green}/{total_bytes:<10.green} \
        {msg}",
    )?
    .progress_chars("##-");
    let bar = mp.add(ProgressBar::new(fdata.size()).with_style(style));
    bar.set_message(format!("{:?}", fdata.path().file_name().unwrap()));
    Ok(bar)
}

/// Compute hash of a single file and print the result.
pub fn hash_single_file(filename: &str, alg: HashAlg) -> Result<(), HasherError> {
    let abspath = canonicalize_filepath(filename, &std::env::current_dir()?)?;
    let fdata = FileData::try_from(abspath)?;
    let mp = MultiProgress::new();
    let actual_hash = hash_file(&fdata, alg, &Some(mp))?;
    println!(
        "[*] Checksum value :\n\
        \t{:?}\n\
        \tHash         : {:?}\n",
        fdata.path(),
        actual_hash
    );
    Ok(())
}

/// Calls `hash_file` and reports the success or failure (if `--force` is false),
/// logging results to file if a valid file handle is passed in.
pub(crate) fn perform_hash_threadfunc(args: ThreadFuncArgs) -> Result<(), HasherError> {
    let actual_hash = hash_file(&args.fdata, args.alg, &args.opt_mp)?;
    if let Some(tp) = args.opt_progress {
        tp.inc(1);
    }

    if let Some(root_dir) = &args.gen_hashfile_dir {
        let stripped_path = args.fdata.path().strip_prefix(root_dir)?;
        let joined_path = Path::new("./").join(stripped_path).display().to_string();
        let gen_hash_line = format!("{actual_hash} {joined_path}\n");
        // eprintln!("[DEBUG] perform_hash_threadfunc: Attempting to write to gen_hashfile: {}", gen_hash_line.trim()); // Removed
        filelog!(gen_hash_line, args.gen_hashfile);
    }

    let result = if args.force {
        format!(
            "[*] Checksum value :\n\
            \t{:?}\n\
            \tHash         : {:?}\n",
            args.fdata.path(),
            actual_hash
        )
    } else if args.fdata.hash() == &actual_hash {
        format!(
            "[+] Checksum passed:\n\
            \t{:?}\n\
            \tActual hash  : {:?}\n",
            args.fdata.path(),
            actual_hash
        )
    } else {
        format!(
            "[-] Checksum failed:\n\
            \t{:?}\n\
            \tExpected hash: {:?}\n\
            \tActual hash  : {:?}\n",
            args.fdata.path(),
            args.fdata.hash(),
            actual_hash
        )
    };

    if args.verbose || (!args.force && args.fdata.hash() != &actual_hash) {
        if let Some(mp) = args.opt_mp {
            mp.println(&result).ok();
        }
    }

    filelog!(result, args.loghandle);
    Ok(())
}
