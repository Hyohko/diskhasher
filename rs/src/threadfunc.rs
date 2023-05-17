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
#[cfg(target_os = "linux")]
use crate::constants::ALIGNMENT;

use crate::{
    constants::{O_FLAGS, SIZE_128MB, SIZE_2MB},
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
        let mut read_count: usize;
        loop {
            {
                read_count = $fd.read(&mut buf[..SIZE_2MB])?;
                $hash.update(&buf[..read_count]);
            }
            if read_count < SIZE_2MB {
                break;
            }
        }
    };
}

/// Compute the hash of a single file, given the following conditions:
/// 1. If the file length is zero, return immediately as zero-length hashes are already known
/// 2. If the `indicatif::MultiProgress` option is set
///  * If the file size equals or exceeds 128 MB, show a progress bar
/// 3. In all cases, read the file in 2MB chunks and compute the hash as given by alg
pub(crate) fn hash_file(
    fdata: &FileData,
    alg: HashAlg,
    opt_mp: &Option<MultiProgress>,
) -> Result<String, HasherError> {
    if fdata.size() == 0 {
        return Ok(known_zero_hash!(alg));
    }

    let mut hasher: Box<dyn DynDigest> = hashobj!(alg);
    // the try_into will not fail if you don't monkey with the constants that make up O_FLAGS
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(
            O_FLAGS
                .try_into()
                .expect("O_FLAGS integer conversion failed b/c the programmer messed with it"),
        )
        .open(fdata.path())?;

    if let Some(mp) = opt_mp {
        if fdata.size() >= SIZE_128MB as u64 {
            let style: ProgressStyle = ProgressStyle::with_template(
                "[{elapsed_precise}] \
                ({percent:3}%) \
                {bar:30.cyan/blue} \
                {bytes:>10.green}/{total_bytes:<10.green} \
                {msg}",
            )?
            .progress_chars("##-");
            let bar = mp.add(ProgressBar::new(fdata.size()).with_style(style));
            bar.set_message(format!("{:?}", fdata.path().file_name().unwrap()));
            read_all_into_hasher!(bar.wrap_read(&file), hasher);
            bar.finish_and_clear();
            mp.remove(&bar);
            drop(bar);
        } else {
            // smaller than 128 MB
            read_all_into_hasher!(file, hasher);
        }
    } else {
        // No progress bars
        read_all_into_hasher!(file, hasher);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Compute hash of a single file
pub fn hash_single_file(filename: &str, alg: HashAlg) -> Result<(), HasherError> {
    // canonicalize file path and check for existence
    let abspath = canonicalize_filepath(filename, &std::env::current_dir()?)?;
    let fdata = FileData::try_from(abspath)?;
    // Create a multiprogress in case this is a large file. Whether or not
    // it is displayed is determined by the hash_file() logic
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

/// Calls `hash_file` and reports the success or failure (if --force is false),
/// logging results to file if a valid file handle is passed in.
pub(crate) fn perform_hash_threadfunc(args: ThreadFuncArgs) -> Result<(), HasherError> {
    let actual_hash = hash_file(&args.fdata, args.alg, &args.opt_mp)?;
    if let Some(tp) = args.opt_progress {
        tp.inc(1);
    }
    if let Some(root_dir) = &args.gen_hashfile_dir {
        let stripped_path = args.fdata.path().strip_prefix(root_dir)?;
        let joined_path = Path::new("./").join(stripped_path).display().to_string();
        filelog!(format!("{actual_hash} {joined_path}\n"), args.gen_hashfile);
    }
    let result: String;
    // If we are saving the hashes off in a hashfile of our own, don't print anything
    if args.force {
        result = format!(
            "[*] Checksum value :\n\
            \t{:?}\n\
            \tHash         : {:?}\n",
            args.fdata.path(),
            actual_hash
        );
        // omitting zero-length hashes from console print in FORCE mode unless verbose - if
        // and only if we are not generating a new hashfile (cuz that's unnecessary)
        if (args.fdata.size() > 0 || args.verbose) && args.gen_hashfile_dir.is_none() {
            if let Some(mp) = args.opt_mp {
                mp.println(&result).ok();
            }
        }
        filelog!(result, args.loghandle);
    } else {
        // Compare
        if args.fdata.hash() == &actual_hash {
            // Success case - hash matches
            if args.verbose {
                result = format!(
                    "[+] Checksum passed:\n\
                    \t{:?}\n\
                    \tActual hash  : {:?}\n",
                    args.fdata.path(),
                    actual_hash
                );
                if let Some(mp) = args.opt_mp {
                    mp.println(&result).ok();
                }
                filelog!(result, args.loghandle);
            }
        } else {
            // Failure case - hash does not match
            result = format!(
                "[-] Checksum failed:\n\
                \t{:?}\n\
                \tExpected hash: {:?}\n\
                \tActual hash  : {:?}\n",
                args.fdata.path(),
                args.fdata.hash(),
                actual_hash
            );
            if let Some(mp) = args.opt_mp {
                mp.println(&result).ok();
            }
            filelog!(result, args.loghandle);
        }
    }
    Ok(())
}
